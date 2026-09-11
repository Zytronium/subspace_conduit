use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

// -------- handshake --------
#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HelloResponse {
    Accepted { server_name: String },
    Rejected { reason: String },
}

// -------- file listing --------
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

// -------- messages --------
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Hello(Hello),
    HelloResponse(HelloResponse),
    Ping,
    Pong,

    // -------- directory listing --------
    ListDir { path: String },
    DirListing { entries: Vec<FileEntry> },
    ListError { reason: String },

    // -------- download (server to client) --------
    Download { path: String, offset: u64 },
    DownloadStart { size: u64 },
    DownloadEnd { checksum: String },
    DownloadError { reason: String },

    // -------- upload (client to server) --------
    Upload { path: String, size: u64, resume: bool },
    UploadReady { offset: u64 },
    UploadEnd { checksum: String },
    UploadAck,
    UploadError { reason: String },
}
