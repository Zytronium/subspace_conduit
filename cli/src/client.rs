use std::sync::Arc;

use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tracing::info;

use subspace_conduit_core::framing::{new_stream, recv_frame, recv_message, send_data, send_message, Frame};
use subspace_conduit_core::protocol::{Hello, HelloResponse, Message, PROTOCOL_VERSION};
use subspace_conduit_core::trust::KnownHostsStore;

use crate::tofu;
use crate::Action;

type ClientStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
type Stream = subspace_conduit_core::framing::MessageStream<ClientStream>;

const CHUNK_SIZE: usize = 64 * 1024;

pub async fn run(addr: &str, action: Action) -> anyhow::Result<()> {
    let socket = tokio::net::TcpStream::connect(addr).await?;

    let store = Arc::new(KnownHostsStore::load()?);
    let tls_config = tofu::build_client_config(store);
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from("subspace-conduit.local")?.to_owned();
    let tls_stream = connector.connect(server_name, socket).await?;

    let mut stream = new_stream(tls_stream);
    info!("connected to {addr}");

    let hello = Message::Hello(Hello {
        version: PROTOCOL_VERSION,
        device_name: hostname_or_default(),
    });
    send_message(&mut stream, &hello).await?;

    match recv_message(&mut stream).await? {
        Message::HelloResponse(HelloResponse::Accepted { server_name }) => {
            info!("handshake accepted by {server_name}");
        }
        Message::HelloResponse(HelloResponse::Rejected { reason }) => {
            anyhow::bail!("handshake rejected: {reason}");
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    match action {
        Action::List { path } => do_list(&mut stream, &path).await,
        Action::Download { remote, local, resume } => do_download(&mut stream, &remote, &local, resume).await,
        Action::Upload { local, remote, resume } => do_upload(&mut stream, &local, &remote, resume).await,
    }
}

// -------- list --------
async fn do_list(stream: &mut Stream, path: &str) -> anyhow::Result<()> {
    send_message(stream, &Message::ListDir { path: path.to_string() }).await?;
    match recv_message(stream).await? {
        Message::DirListing { entries } => {
            for entry in entries {
                let kind = if entry.is_dir { "DIR " } else { "FILE" };
                println!("{kind}  {:>10}  {}", entry.size, entry.name);
            }
        }
        Message::ListError { reason } => anyhow::bail!("list failed: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

// -------- download --------
async fn do_download(stream: &mut Stream, remote: &str, local: &str, resume: bool) -> anyhow::Result<()> {
    let local_path = std::path::Path::new(local);
    let offset = if resume && local_path.exists() {
        tokio::fs::metadata(local_path).await?.len()
    } else {
        0
    };

    send_message(stream, &Message::Download { path: remote.to_string(), offset }).await?;

    let size = match recv_message(stream).await? {
        Message::DownloadStart { size } => size,
        Message::DownloadError { reason } => anyhow::bail!("download failed: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    let mut hasher = Sha256::new();
    if offset > 0 {
        let mut existing = tokio::fs::File::open(local_path).await?;
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
    if offset > 0 { open_options.append(true); } else { open_options.truncate(true); }
    let mut file = open_options.open(local_path).await?;

    let mut received: u64 = offset;
    loop {
        match recv_frame(stream).await? {
            Frame::Data(data) => {
                received += data.len() as u64;
                hasher.update(&data);
                file.write_all(&data).await?;
            }
            Frame::Control(Message::DownloadEnd { checksum }) => {
                let computed = hex::encode(hasher.finalize());
                if computed != checksum {
                    anyhow::bail!(
                        "checksum mismatch after download: server sent {checksum}, \
                         computed {computed}. The local file '{local}' may be corrupted."
                    );
                }
                break;
            }
            Frame::Control(other) => anyhow::bail!("unexpected message mid-download: {other:?}"),
        }
    }

    info!("downloaded {received} of {size} bytes to {local} (resumed from {offset}), checksum verified");
    Ok(())
}

// -------- upload --------
async fn do_upload(stream: &mut Stream, local: &str, remote: &str, resume: bool) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::open(local).await?;
    let size = file.metadata().await?.len();

    send_message(stream, &Message::Upload { path: remote.to_string(), size, resume }).await?;

    let offset = match recv_message(stream).await? {
        Message::UploadReady { offset } => offset,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    if offset > size {
        anyhow::bail!("remote file is larger ({offset} bytes) than local file ({size} bytes), cannot resume");
    }

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
    send_message(stream, &Message::UploadEnd { checksum }).await?;

    match recv_message(stream).await? {
        Message::UploadAck => info!("upload of {local} complete (resumed from {offset}), checksum verified"),
        Message::UploadError { reason } => anyhow::bail!("upload failed: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

// -------- helpers --------
fn hostname_or_default() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-device".to_string())
}
