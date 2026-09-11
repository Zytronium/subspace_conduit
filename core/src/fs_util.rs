use std::path::{Component, Path, PathBuf};

// -------- safe path resolution --------
// Resolves a client-supplied relative path against the server root, and
// guarantees the result stays inside the root. Any ".." component is
// rejected outright, and requesting "." (or an empty path) returns the
// root itself.
pub fn resolve_safe(root: &Path, requested: &str) -> anyhow::Result<PathBuf> {
    let canonical_root = root.canonicalize()?;
    let trimmed = requested.trim_start_matches('/');
    let requested_path = Path::new(trimmed);

    for component in requested_path.components() {
        if matches!(component, Component::ParentDir) {
            anyhow::bail!("path escapes server root: {requested}");
        }
    }

    if trimmed.is_empty() || requested_path == Path::new(".") {
        return Ok(canonical_root);
    }

    let candidate = canonical_root.join(requested_path);

    let parent = candidate.parent().unwrap_or(&canonical_root);
    if !parent.exists() {
        anyhow::bail!("parent directory does not exist: {}", parent.display());
    }
    let canonical_parent = parent.canonicalize()?;

    if !canonical_parent.starts_with(&canonical_root) {
        anyhow::bail!("path escapes server root: {requested}");
    }

    let resolved = match candidate.file_name() {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent,
    };

    Ok(resolved)
}
