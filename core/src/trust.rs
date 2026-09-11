use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

// -------- known hosts store --------
#[derive(Debug)]
pub struct KnownHostsStore {
    path: PathBuf,
    entries: Mutex<HashMap<String, String>>,
}

impl KnownHostsStore {
    pub fn load() -> anyhow::Result<Self> {
        let path = known_hosts_path()?;
        let entries = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            HashMap::new()
        };
        Ok(Self { path, entries: Mutex::new(entries) })
    }

    fn save(&self) -> anyhow::Result<()> {
        let entries = self.entries.lock().unwrap();
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(&*entries)?;
        fs::write(&self.path, raw)?;
        Ok(())
    }

    pub fn known_fingerprint(&self, host_key: &str) -> Option<String> {
        self.entries.lock().unwrap().get(host_key).cloned()
    }

    pub fn trust(&self, host_key: &str, fingerprint: &str) -> anyhow::Result<()> {
        self.entries.lock().unwrap().insert(host_key.to_string(), fingerprint.to_string());
        self.save()
    }
}

fn known_hosts_path() -> anyhow::Result<PathBuf> {
    let mut dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
    dir.push("subspace_conduit");
    dir.push("known_hosts.json");
    Ok(dir)
}
