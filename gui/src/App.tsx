import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type DiscoveredServer = { name: string; addr: string; port: number };
type TrustStatus = "Unknown" | "Trusted" | { Mismatch: { expected: string } };
type ProbeResult = { host_key: string; fingerprint: string; status: TrustStatus };
type FileEntry = { name: string; size: number; is_dir: boolean };
type TransferProgress = { session_id: string; transferred: number; total: number };

type LogEntry = { id: number; time: string; text: string; level: "info" | "success" | "error" };

function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB"];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i++;
    }
    return `${value.toFixed(1)} ${units[i]}`;
}

function joinRemotePath(parent: string, child: string): string {
    if (parent === "." || parent === "") return child;
    return `${parent.replace(/\/$/, "")}/${child}`;
}

function FileIcon({ isFolder }: { isFolder: boolean }) {
    return isFolder ? (
        <svg className="entry-icon folder-icon" viewBox="0 0 48 48" aria-hidden="true">
            <path d="M5 12.5A3.5 3.5 0 0 1 8.5 9H19l4 5h16.5a3.5 3.5 0 0 1 3.5 3.5v18A3.5 3.5 0 0 1 39.5 39h-31A3.5 3.5 0 0 1 5 35.5v-23Z" />
            <path className="icon-detail" d="M5 18h38" />
        </svg>
    ) : (
        <svg className="entry-icon file-icon" viewBox="0 0 48 48" aria-hidden="true">
            <path d="M12 5h17l10 10v28H12z" />
            <path className="icon-detail" d="M29 5v11h10M18 27h14M18 34h10" />
        </svg>
    );
}

function App() {
    // -------- discovery / connection state --------
    const [servers, setServers] = useState<DiscoveredServer[]>([]);
    const [discovering, setDiscovering] = useState(false);
    const [selectedAddr, setSelectedAddr] = useState<string | null>(null);
    const [probe, setProbe] = useState<ProbeResult | null>(null);
    const [sessionId, setSessionId] = useState<string | null>(null);
    const [connectedTo, setConnectedTo] = useState<string | null>(null);

    // -------- file browser state --------
    const [entries, setEntries] = useState<FileEntry[]>([]);
    const [currentPath, setCurrentPath] = useState(".");
    const [activeTab, setActiveTab] = useState<"browse" | "activity">("browse");

    // -------- hosting state --------
    const [bindAddr, setBindAddr] = useState("0.0.0.0:7878");
    const [serverRoot, setServerRoot] = useState("");
    const [serverName, setServerName] = useState("");
    const [serverRunning, setServerRunning] = useState(false);

    // -------- transfers --------
    const [transfers, setTransfers] = useState<Record<string, TransferProgress & { label: string }>>({});

    // -------- activity log --------
    const [log, setLog] = useState<LogEntry[]>([]);
    const logCounter = useRef(0);

    function pushLog(text: string, level: LogEntry["level"] = "info") {
        logCounter.current += 1;
        const time = new Date().toLocaleTimeString();
        setLog((prev) => [...prev.slice(-49), { id: logCounter.current, time, text, level }]);
    }

    useEffect(() => {
        const unlisten = listen<TransferProgress>("transfer-progress", (event) => {
            setTransfers((prev) => ({
                ...prev,
                [event.payload.session_id]: {
                    ...event.payload,
                    label: prev[event.payload.session_id]?.label ?? "transfer",
                },
            }));
        });
        return () => {
            unlisten.then((f) => f());
        };
    }, []);

    // -------- discovery --------
    async function handleDiscover() {
        setDiscovering(true);
        pushLog("Searching the local network...");
        try {
            const found = await invoke<DiscoveredServer[]>("discover_servers", { timeoutSecs: 3 });
            setServers(found);
            pushLog(`Found ${found.length} device${found.length === 1 ? "" : "s"}`, "success");
        } catch (e) {
            pushLog(`Discovery failed: ${e}`, "error");
        } finally {
            setDiscovering(false);
        }
    }

    // -------- probe + trust --------
    async function handleSelectDevice(addr: string) {
        setSelectedAddr(addr);
        setProbe(null);
        pushLog(`Reading certificate from ${addr}...`);
        try {
            const result = await invoke<ProbeResult>("probe_server", { addr });
            setProbe(result);
        } catch (e) {
            pushLog(`Could not reach ${addr}: ${e}`, "error");
        }
    }

    async function handleTrustAndConnect() {
        if (!probe || !selectedAddr) return;
        try {
            if (probe.status === "Unknown") {
                await invoke("trust_server", { hostKey: probe.host_key, fingerprint: probe.fingerprint });
                pushLog("Fingerprint trusted");
            }
            const id = await invoke<string>("connect_session", { addr: selectedAddr });
            setSessionId(id);
            setConnectedTo(selectedAddr);
            setProbe(null);
            pushLog(`Connected to ${selectedAddr}`, "success");
            await refreshListing(id, ".");
        } catch (e) {
            pushLog(`Connection failed: ${e}`, "error");
        }
    }

    async function handleDisconnect() {
        if (!sessionId) return;
        await invoke("disconnect_session", { sessionId });
        pushLog(`Disconnected from ${connectedTo}`);
        setSessionId(null);
        setConnectedTo(null);
        setEntries([]);
    }

    // -------- file browser --------
    async function refreshListing(id: string, path: string) {
        try {
            const result = await invoke<FileEntry[]>("list_dir", { sessionId: id, path });
            setEntries(result);
            setCurrentPath(path);
        } catch (e) {
            pushLog(`Could not list ${path}: ${e}`, "error");
        }
    }

    async function handleDownload(remote: string) {
        if (!sessionId) return;
        const destination = await save({ defaultPath: remote });
        if (!destination) return;
        pushLog(`Downloading ${remote}...`);
        try {
            await invoke("download_file", { sessionId, remote, local: destination, resume: false });
            pushLog(`Downloaded ${remote}`, "success");
        } catch (e) {
            pushLog(`Download of ${remote} failed: ${e}`, "error");
        }
    }

    function handleOpenFolder(name: string) {
        if (!sessionId) return;
        void refreshListing(sessionId, joinRemotePath(currentPath, name));
    }

    function handleGoUp() {
        if (!sessionId || currentPath === ".") return;
        const parts = currentPath.split("/").filter(Boolean);
        parts.pop();
        void refreshListing(sessionId, parts.length ? parts.join("/") : ".");
    }

    function handleBreadcrumb(path: string) {
        if (!sessionId || path === currentPath) return;
        void refreshListing(sessionId, path);
    }

    async function handleUpload() {
        if (!sessionId) return;
        const selected = await open({ multiple: false });
        if (!selected || Array.isArray(selected)) return;
        const fileName = selected.split(/[\\/]/).pop() ?? "uploaded_file";
        const remoteName = joinRemotePath(currentPath, fileName);
        pushLog(`Uploading ${remoteName}...`);
        try {
            await invoke("upload_file", { sessionId, local: selected, remote: remoteName, resume: false });
            pushLog(`Uploaded ${remoteName}`, "success");
            await refreshListing(sessionId, currentPath);
        } catch (e) {
            pushLog(`Upload failed: ${e}`, "error");
        }
    }

    // -------- hosting --------
    async function handleChooseRoot() {
        const selected = await open({ directory: true, multiple: false });
        if (typeof selected === "string") setServerRoot(selected);
    }

    async function handleStartServer() {
        if (!serverRoot) {
            pushLog("Choose a folder to share before starting the server", "error");
            return;
        }
        try {
            await invoke("start_server", { bind: bindAddr, root: serverRoot, name: serverName || null });
            setServerRunning(true);
            pushLog(`Hosting ${serverRoot} on ${bindAddr}`, "success");
        } catch (e) {
            pushLog(`Could not start server: ${e}`, "error");
        }
    }

    async function handleStopServer() {
        await invoke("stop_server");
        setServerRunning(false);
        pushLog("Server stopped");
    }

    const activeTransfers = Object.entries(transfers).filter(([, t]) => t.transferred < t.total);

    return (
        <div className="shell">
            <aside className="sidebar">
                <div className="brand">
                    <span className="brand-mark">Subspace Conduit</span>
                    <span className="brand-sub">Device-to-device file transfer</span>
                </div>

                <div className="sidebar-section">
                    <span className="sidebar-heading">Network</span>
                    <button className="btn btn-block" onClick={handleDiscover} disabled={discovering}>
                        {discovering ? "Searching..." : "Find devices"}
                    </button>
                    <div className="device-list">
                        {servers.length === 0 && !discovering && (
                            <div className="empty-hint">No devices found yet.</div>
                        )}
                        {servers.map((s) => (
                            <div
                                key={`${s.addr}:${s.port}`}
                                className={`device-row ${selectedAddr === `${s.addr}:${s.port}` ? "selected" : ""}`}
                                onClick={() => handleSelectDevice(`${s.addr}:${s.port}`)}
                                tabIndex={0}
                            >
                                <span className="device-name">{s.name.split(".")[0]}</span>
                                <span className="device-addr">{s.addr}:{s.port}</span>
                            </div>
                        ))}
                    </div>
                    {connectedTo && (
                        <>
                            <div className="status-line">
                                <span className="status-dot live" />
                                Connected to {connectedTo}
                            </div>
                            <button className="btn btn-block btn-danger" onClick={handleDisconnect}>
                                Disconnect
                            </button>
                        </>
                    )}
                </div>

                <div className="sidebar-section">
                    <span className="sidebar-heading">Host</span>
                    <div className="field">
                        <label>Folder to share</label>
                        <div className="path-picker">
                            <input value={serverRoot} readOnly placeholder="Choose a folder" />
                            <button className="btn" onClick={handleChooseRoot}>Browse</button>
                        </div>
                    </div>
                    <div className="field">
                        <label>Device name</label>
                        <input
                            value={serverName}
                            onChange={(e) => setServerName(e.target.value)}
                            placeholder="optional"
                        />
                    </div>
                    <div className="field">
                        <label>Bind address</label>
                        <input value={bindAddr} onChange={(e) => setBindAddr(e.target.value)} />
                    </div>
                    {serverRunning ? (
                        <>
                            <div className="status-line">
                                <span className="status-dot live" />
                                Hosting on {bindAddr}
                            </div>
                            <button className="btn btn-block btn-danger" onClick={handleStopServer}>
                                Stop hosting
                            </button>
                        </>
                    ) : (
                        <button className="btn btn-block btn-primary" onClick={handleStartServer}>
                            Start hosting
                        </button>
                    )}
                </div>
            </aside>

            <main className="main">
                <div className="topbar">
                    <div className="tabs">
                        <button
                            className={`tab ${activeTab === "browse" ? "active" : ""}`}
                            onClick={() => setActiveTab("browse")}
                        >
                            Browse
                        </button>
                        <button
                            className={`tab ${activeTab === "activity" ? "active" : ""}`}
                            onClick={() => setActiveTab("activity")}
                        >
                            Activity
                        </button>
                    </div>
                </div>

                <div className="content">
                    {activeTab === "browse" && (
                        <>
                            {probe && (
                                <div className="trust-card">
                                    <div className="trust-status">
                    <span
                        className={`status-dot ${
                            probe.status === "Trusted"
                                ? "live"
                                : probe.status === "Unknown"
                                    ? "warning"
                                    : "danger"
                        }`}
                    />
                                        {probe.status === "Trusted" && "Already trusted"}
                                        {probe.status === "Unknown" && "New device, review before trusting"}
                                        {typeof probe.status === "object" && "Fingerprint does not match, do not trust"}
                                    </div>
                                    <div className="trust-fingerprint">{probe.fingerprint}</div>
                                    <button className="btn btn-primary" onClick={handleTrustAndConnect}>
                                        {probe.status === "Trusted" ? "Connect" : "Trust and connect"}
                                    </button>
                                </div>
                            )}

                            {!probe && sessionId && (
                                <>
                                    <div className="browser-toolbar">
                                        <div className="breadcrumbs" aria-label="Current folder">
                                            <button className="breadcrumb" onClick={() => handleBreadcrumb(".")}>Home</button>
                                            {currentPath !== "." && currentPath.split("/").filter(Boolean).map((part, index, parts) => {
                                                const path = parts.slice(0, index + 1).join("/");
                                                return (
                                                    <span className="breadcrumb-segment" key={path}>
                                                        <span className="breadcrumb-separator">/</span>
                                                        <button className="breadcrumb" onClick={() => handleBreadcrumb(path)}>{part}</button>
                                                    </span>
                                                );
                                            })}
                                        </div>
                                        <div className="browser-actions">
                                            <button className="btn" onClick={handleGoUp} disabled={currentPath === "."}>
                                                <span aria-hidden="true">↑</span> Up
                                            </button>
                                            <button className="btn" onClick={() => refreshListing(sessionId, currentPath)}>
                                                Refresh
                                            </button>
                                            <button className="btn btn-primary" onClick={handleUpload}>
                                                Upload a file
                                            </button>
                                        </div>
                                    </div>
                                    <div className="file-grid">
                                        {[...entries].sort((a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name)).map((e) => {
                                            const remotePath = joinRemotePath(currentPath, e.name);
                                            return (
                                                <article className={`file-card ${e.is_dir ? "folder-card" : ""}`} key={e.name}>
                                                    <button
                                                        className="entry-open"
                                                        onClick={() => e.is_dir && handleOpenFolder(e.name)}
                                                        disabled={!e.is_dir}
                                                        aria-label={e.is_dir ? `Open ${e.name}` : e.name}
                                                    >
                                                        <FileIcon isFolder={e.is_dir} />
                                                        <span className="entry-name" title={e.name}>{e.name}</span>
                                                        <span className="entry-meta">{e.is_dir ? "Folder" : formatBytes(e.size)}</span>
                                                    </button>
                                                    {!e.is_dir && (
                                                        <button className="entry-download" onClick={() => handleDownload(remotePath)}>
                                                            Download
                                                        </button>
                                                    )}
                                                </article>
                                            );
                                        })}
                                    </div>
                                    {entries.length === 0 && <div className="empty-state">This folder is empty.</div>}
                                </>
                            )}

                            {!probe && !sessionId && (
                                <div className="empty-state">
                                    Find a device on the left, then connect to browse its shared files.
                                </div>
                            )}

                            {activeTransfers.length > 0 && (
                                <div className="transfer-list">
                                    {activeTransfers.map(([id, t]) => (
                                        <div className="transfer-row" key={id}>
                                            <div className="transfer-meta">
                                                <span>{formatBytes(t.transferred)} / {formatBytes(t.total)}</span>
                                                <span>{Math.round((t.transferred / t.total) * 100)}%</span>
                                            </div>
                                            <div className="progress-track">
                                                <div
                                                    className="progress-fill"
                                                    style={{ width: `${(t.transferred / t.total) * 100}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}

                    {activeTab === "activity" && (
                        <div className="log-panel">
                            {log.length === 0 && <div className="empty-state">Nothing has happened yet.</div>}
                            {log.map((entry) => (
                                <div className={`log-entry ${entry.level}`} key={entry.id}>
                                    <span className="log-time">{entry.time}</span>
                                    <span>{entry.text}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}

export default App;
