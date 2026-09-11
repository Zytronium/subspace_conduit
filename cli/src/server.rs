use std::path::PathBuf;

pub async fn run(bind: &str, root: PathBuf, name: Option<String>) -> anyhow::Result<()> {
    let (_tx, rx) = tokio::sync::oneshot::channel();
    subspace_conduit_core::server::run(bind, root, name, rx).await
}
