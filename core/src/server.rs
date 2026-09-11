use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::framing::{new_stream, recv_frame, recv_message, send_data, send_message, Frame, MessageStream};
use crate::protocol::{FileEntry, HelloResponse, Message, PROTOCOL_VERSION};
use crate::{discovery, fs_util, tls};

type ServerStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
type Stream = MessageStream<ServerStream>;

const CHUNK_SIZE: usize = 64 * 1024;

// -------- run, stops when shutdown_rx fires --------
pub async fn run(
    bind: &str,
    root: PathBuf,
    name: Option<String>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let tls_config = tls::build_server_config()?;
    let acceptor = TlsAcceptor::from(tls_config);
    let root = Arc::new(root);

    let port = listener.local_addr()?.port();
    let device_name = name.unwrap_or_else(hostname_or_default);
    // dropped (and therefore unregistered) automatically when this function returns
    let _mdns_daemon = discovery::advertise(port, &device_name)?;

    info!("subspace_conduit server listening on {bind}, serving {}", root.display());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, peer_addr) = accept_result?;
                let acceptor = acceptor.clone();
                let root = root.clone();
                info!("connection from {peer_addr}");
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, acceptor, root).await {
                        warn!("connection from {peer_addr} ended with error: {e}");
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!("shutdown requested, stopping server");
                break;
            }
        }
    }

    Ok(())
}

// -------- connection handling --------
async fn handle_connection(
    socket: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    root: Arc<PathBuf>,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(socket).await?;
    let mut stream = new_stream(tls_stream);

    let msg = recv_message(&mut stream).await?;
    match msg {
        Message::Hello(hello) if hello.version == PROTOCOL_VERSION => {
            let response = Message::HelloResponse(HelloResponse::Accepted {
                server_name: "subspace_conduit".to_string(),
            });
            send_message(&mut stream, &response).await?;
        }
        Message::Hello(hello) => {
            let response = Message::HelloResponse(HelloResponse::Rejected {
                reason: format!("unsupported protocol version {}", hello.version),
            });
            send_message(&mut stream, &response).await?;
            return Ok(());
        }
        other => {
            warn!("expected Hello as first message, got {other:?}");
            return Ok(());
        }
    }

    loop {
        let msg = match recv_message(&mut stream).await {
            Ok(msg) => msg,
            Err(_) => break,
        };

        match msg {
            Message::ListDir { path } => handle_list_dir(&mut stream, &root, &path).await?,
            Message::Download { path, offset } => handle_download(&mut stream, &root, &path, offset).await?,
            Message::Upload { path, size, resume } => handle_upload(&mut stream, &root, &path, size, resume).await?,
            other => warn!("unexpected message in command loop: {other:?}"),
        }
    }

    Ok(())
}

// -------- list --------
async fn handle_list_dir(stream: &mut Stream, root: &Path, path: &str) -> anyhow::Result<()> {
    let target = match fs_util::resolve_safe(root, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(stream, &Message::ListError { reason: e.to_string() }).await?;
            return Ok(());
        }
    };

    let mut read_dir = match tokio::fs::read_dir(&target).await {
        Ok(rd) => rd,
        Err(e) => {
            send_message(stream, &Message::ListError { reason: e.to_string() }).await?;
            return Ok(());
        }
    };

    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        let metadata = entry.metadata().await?;
        entries.push(FileEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            size: metadata.len(),
            is_dir: metadata.is_dir(),
        });
    }

    send_message(stream, &Message::DirListing { entries }).await?;
    Ok(())
}

// -------- download --------
async fn handle_download(stream: &mut Stream, root: &Path, path: &str, offset: u64) -> anyhow::Result<()> {
    let target = match fs_util::resolve_safe(root, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(stream, &Message::DownloadError { reason: e.to_string() }).await?;
            return Ok(());
        }
    };

    let mut file = match tokio::fs::File::open(&target).await {
        Ok(f) => f,
        Err(e) => {
            send_message(stream, &Message::DownloadError { reason: e.to_string() }).await?;
            return Ok(());
        }
    };

    let size = file.metadata().await?.len();
    if offset > size {
        let reason = format!("resume offset {offset} is past end of file (size {size})");
        send_message(stream, &Message::DownloadError { reason }).await?;
        return Ok(());
    }

    send_message(stream, &Message::DownloadStart { size }).await?;

    let mut hasher = Sha256::new();
    let mut position: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);

        let chunk_start = position;
        let chunk_end = position + n as u64;
        if chunk_end > offset {
            let send_from = if chunk_start < offset { (offset - chunk_start) as usize } else { 0 };
            send_data(stream, &buf[send_from..n]).await?;
        }
        position = chunk_end;
    }

    let checksum = hex::encode(hasher.finalize());
    send_message(stream, &Message::DownloadEnd { checksum }).await?;
    Ok(())
}

// -------- upload --------
async fn handle_upload(stream: &mut Stream, root: &Path, path: &str, _size: u64, resume: bool) -> anyhow::Result<()> {
    let target = match fs_util::resolve_safe(root, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(stream, &Message::UploadError { reason: e.to_string() }).await?;
            return Ok(());
        }
    };

    let existing_size = if resume {
        tokio::fs::metadata(&target).await.map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    send_message(stream, &Message::UploadReady { offset: existing_size }).await?;

    let mut hasher = Sha256::new();
    if existing_size > 0 {
        let mut existing = tokio::fs::File::open(&target).await?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = existing.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }

    let mut open_options = tokio::fs::OpenOptions::new();
    open_options.write(true).create(true);
    if existing_size > 0 { open_options.append(true); } else { open_options.truncate(true); }
    let mut file = open_options.open(&target).await?;

    loop {
        match recv_frame(stream).await? {
            Frame::Data(data) => {
                hasher.update(&data);
                file.write_all(&data).await?;
            }
            Frame::Control(Message::UploadEnd { checksum }) => {
                let computed = hex::encode(hasher.finalize());
                if computed == checksum {
                    send_message(stream, &Message::UploadAck).await?;
                } else {
                    let reason = format!("checksum mismatch: client sent {checksum}, server computed {computed}");
                    send_message(stream, &Message::UploadError { reason }).await?;
                }
                break;
            }
            Frame::Control(other) => {
                warn!("unexpected message during upload: {other:?}");
                break;
            }
        }
    }

    Ok(())
}

// -------- helpers --------
fn hostname_or_default() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "subspace-conduit-server".to_string())
}
