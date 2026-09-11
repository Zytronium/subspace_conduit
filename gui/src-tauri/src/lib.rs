use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, State};
use tokio::sync::Mutex;
use uuid::Uuid;

use subspace_conduit_core::api::{self, ClientStream, ProbeResult};
use subspace_conduit_core::discovery::{self, DiscoveredServer};
use subspace_conduit_core::protocol::FileEntry;
use subspace_conduit_core::trust::KnownHostsStore;

// -------- shared state --------
struct AppState {
    store: Arc<KnownHostsStore>,
    sessions: Mutex<HashMap<String, ClientStream>>,
    server_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[derive(Clone, Serialize)]
struct TransferProgress {
    session_id: String,
    transferred: u64,
    total: u64,
}

// -------- discover --------
#[tauri::command]
async fn discover_servers(timeout_secs: u64) -> Result<Vec<DiscoveredServer>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        discovery::discover(std::time::Duration::from_secs(timeout_secs))
    })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

// -------- probe a server's cert fingerprint before trusting it --------
#[tauri::command]
async fn probe_server(addr: String, state: State<'_, AppState>) -> Result<ProbeResult, String> {
    api::probe_fingerprint(&addr, &state.store)
        .await
        .map_err(|e| e.to_string())
}

// -------- host a server from within the app --------
#[tauri::command]
async fn start_server(
    bind: String,
    root: String,
    name: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut shutdown_guard = state.server_shutdown.lock().await;
    if shutdown_guard.is_some() {
        return Err("server is already running".to_string());
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    let root_path = PathBuf::from(root);

    tauri::async_runtime::spawn(async move {
        if let Err(e) = subspace_conduit_core::server::run(&bind, root_path, name, rx).await {
            eprintln!("server task ended with error: {e}");
        }
    });

    *shutdown_guard = Some(tx);
    Ok(())
}

#[tauri::command]
async fn stop_server(state: State<'_, AppState>) -> Result<(), String> {
    let mut shutdown_guard = state.server_shutdown.lock().await;
    match shutdown_guard.take() {
        Some(tx) => {
            let _ = tx.send(());
            Ok(())
        }
        None => Err("server is not running".to_string()),
    }
}

#[tauri::command]
async fn server_status(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.server_shutdown.lock().await.is_some())
}

// -------- explicitly trust a fingerprint after user confirmation --------
#[tauri::command]
fn trust_server(host_key: String, fingerprint: String, state: State<'_, AppState>) -> Result<(), String> {
    api::trust_server(&state.store, &host_key, &fingerprint).map_err(|e| e.to_string())
}

// -------- connect, returns a session id for subsequent calls --------
#[tauri::command]
async fn connect_session(addr: String, state: State<'_, AppState>) -> Result<String, String> {
    let stream = api::connect(&addr, state.store.clone())
        .await
        .map_err(|e| e.to_string())?;
    let session_id = Uuid::new_v4().to_string();
    state.sessions.lock().await.insert(session_id.clone(), stream);
    Ok(session_id)
}

#[tauri::command]
async fn disconnect_session(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.sessions.lock().await.remove(&session_id);
    Ok(())
}

// -------- list --------
#[tauri::command]
async fn list_dir(session_id: String, path: String, state: State<'_, AppState>) -> Result<Vec<FileEntry>, String> {
    let mut sessions = state.sessions.lock().await;
    let stream = sessions.get_mut(&session_id).ok_or("no such session")?;
    api::list_dir(stream, &path).await.map_err(|e| e.to_string())
}

// -------- download, emits "transfer-progress" events as it goes --------
#[tauri::command]
async fn download_file(
    app: tauri::AppHandle,
    session_id: String,
    remote: String,
    local: String,
    resume: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut sessions = state.sessions.lock().await;
    let stream = sessions.get_mut(&session_id).ok_or("no such session")?;
    let local_path = PathBuf::from(local);
    let sid = session_id.clone();

    api::download_file(stream, &remote, &local_path, resume, move |transferred, total| {
        let _ = app.emit(
            "transfer-progress",
            TransferProgress { session_id: sid.clone(), transferred, total },
        );
    })
        .await
        .map_err(|e| e.to_string())
}

// -------- upload, emits "transfer-progress" events as it goes --------
#[tauri::command]
async fn upload_file(
    app: tauri::AppHandle,
    session_id: String,
    local: String,
    remote: String,
    resume: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut sessions = state.sessions.lock().await;
    let stream = sessions.get_mut(&session_id).ok_or("no such session")?;
    let local_path = PathBuf::from(local);
    let sid = session_id.clone();

    api::upload_file(stream, &local_path, &remote, resume, move |transferred, total| {
        let _ = app.emit(
            "transfer-progress",
            TransferProgress { session_id: sid.clone(), transferred, total },
        );
    })
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let store = Arc::new(KnownHostsStore::load().expect("failed to load known hosts store"));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            store,
            sessions: Mutex::new(HashMap::new()),
            server_shutdown: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            discover_servers,
            probe_server,
            trust_server,
            connect_session,
            disconnect_session,
            list_dir,
            download_file,
            upload_file,
            start_server,
            stop_server,
            server_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
