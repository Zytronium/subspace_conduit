use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::framing::{new_stream, recv_frame, recv_message, send_data, send_message, Frame, MessageStream};
use crate::protocol::{FileEntry, Hello, HelloResponse, Message, PROTOCOL_VERSION};
use crate::trust::KnownHostsStore;

const CHUNK_SIZE: usize = 64 * 1024;
const SERVER_NAME: &str = "subspace-conduit.local";

pub type ClientStream = MessageStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

// -------- trust status --------
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TrustStatus {
    Unknown,
    Trusted,
    Mismatch { expected: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub host_key: String,
    pub fingerprint: String,
    pub status: TrustStatus,
}

// -------- probe: capture a server's cert fingerprint without trusting it --------
pub async fn probe_fingerprint(addr: &str, store: &KnownHostsStore) -> anyhow::Result<ProbeResult> {
    let socket = tokio::net::TcpStream::connect(addr).await?;
    let config = crate::tls::build_peek_client_config();
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(SERVER_NAME)?.to_owned();

    let tls_stream = connector.connect(server_name, socket).await?;
    let certs = tls_stream.get_ref().1.peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("server presented no certificate"))?;
    let leaf = certs.first().ok_or_else(|| anyhow::anyhow!("empty certificate chain"))?;
    let fingerprint = hex::encode(Sha256::digest(leaf.as_ref()));

    let host_key = format!("{SERVER_NAME}");
    let status = match store.known_fingerprint(&host_key) {
        Some(known) if known == fingerprint => TrustStatus::Trusted,
        Some(known) => TrustStatus::Mismatch { expected: known },
        None => TrustStatus::Unknown,
    };

    Ok(ProbeResult { host_key, fingerprint, status })
}

// -------- explicitly trust a fingerprint after user confirmation --------
pub fn trust_server(store: &KnownHostsStore, host_key: &str, fingerprint: &str) -> anyhow::Result<()> {
    store.trust(host_key, fingerprint)
}

// -------- connect for real, using a verifier that requires an already-known match --------
pub async fn connect(addr: &str, store: Arc<KnownHostsStore>) -> anyhow::Result<ClientStream> {
    let socket = tokio::net::TcpStream::connect(addr).await?;
    let config = crate::tls::build_strict_client_config(store);
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(SERVER_NAME)?.to_owned();
    let tls_stream = connector.connect(server_name, socket).await?;
    let mut stream = new_stream(tls_stream);

    let hello = Message::Hello(Hello {
        version: PROTOCOL_VERSION,
        device_name: hostname_or_default(),
    });
    send_message(&mut stream, &hello).await?;

    match recv_message(&mut stream).await? {
        Message::HelloResponse(HelloResponse::Accepted { .. }) => Ok(stream),
        Message::HelloResponse(HelloResponse::Rejected { reason }) => anyhow::bail!("handshake rejected: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

// -------- list --------
pub async fn list_dir(stream: &mut ClientStream, path: &str) -> anyhow::Result<Vec<FileEntry>> {
    send_message(stream, &Message::ListDir { path: path.to_string() }).await?;
    match recv_message(stream).await? {
        Message::DirListing { entries } => Ok(entries),
        Message::ListError { reason } => anyhow::bail!("list failed: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

// -------- download --------
// progress is called with (bytes_received, total_size) after each chunk.
pub async fn download_file(
    stream: &mut ClientStream,
    remote: &str,
    local: &Path,
    resume: bool,
    mut progress: impl FnMut(u64, u64),
) -> anyhow::Result<()> {
    let offset = if resume && local.exists() {
        tokio::fs::metadata(local).await?.len()
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
        let mut existing = tokio::fs::File::open(local).await?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = existing.read(&mut buf).await?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
    }

    let mut open_options = tokio::fs::OpenOptions::new();
    open_options.write(true).create(true);
    if offset > 0 { open_options.append(true); } else { open_options.truncate(true); }
    let mut file = open_options.open(local).await?;

    let mut received = offset;
    loop {
        match recv_frame(stream).await? {
            Frame::Data(data) => {
                received += data.len() as u64;
                hasher.update(&data);
                file.write_all(&data).await?;
                progress(received, size);
            }
            Frame::Control(Message::DownloadEnd { checksum }) => {
                let computed = hex::encode(hasher.finalize());
                if computed != checksum {
                    anyhow::bail!("checksum mismatch after download, file may be corrupted");
                }
                break;
            }
            Frame::Control(other) => anyhow::bail!("unexpected message mid-download: {other:?}"),
        }
    }
    Ok(())
}

// -------- upload --------
pub async fn upload_file(
    stream: &mut ClientStream,
    local: &Path,
    remote: &str,
    resume: bool,
    mut progress: impl FnMut(u64, u64),
) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::open(local).await?;
    let size = file.metadata().await?.len();

    send_message(stream, &Message::Upload { path: remote.to_string(), size, resume }).await?;

    let offset = match recv_message(stream).await? {
        Message::UploadReady { offset } => offset,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    if offset > size {
        anyhow::bail!("remote file is larger than local file, cannot resume");
    }

    let mut hasher = Sha256::new();
    let mut position: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);

        let chunk_start = position;
        let chunk_end = position + n as u64;
        if chunk_end > offset {
            let send_from = if chunk_start < offset { (offset - chunk_start) as usize } else { 0 };
            send_data(stream, &buf[send_from..n]).await?;
        }
        position = chunk_end;
        progress(position, size);
    }

    let checksum = hex::encode(hasher.finalize());
    send_message(stream, &Message::UploadEnd { checksum }).await?;

    match recv_message(stream).await? {
        Message::UploadAck => Ok(()),
        Message::UploadError { reason } => anyhow::bail!("upload failed: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn hostname_or_default() -> String {
    hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "unknown-device".to_string())
}
