use clap::{Parser, Subcommand};

mod server;
mod client;
mod tofu;

#[derive(Parser)]
#[command(name = "subspace_conduit")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, default_value = "0.0.0.0:7878")]
        bind: String,
        #[arg(short, long, default_value = ".")]
        root: String,
        #[arg(short, long)]
        name: Option<String>,
    },
    Connect {
        #[arg(short, long)]
        addr: Option<String>,
        #[arg(short, long)]
        name: Option<String>,
        #[command(subcommand)]
        action: Action,
    },
    Discover {
        #[arg(short, long, default_value = "3")]
        timeout: u64,
    },
}

#[derive(Subcommand, Clone)]
pub enum Action {
    List {
        #[arg(default_value = ".")]
        path: String,
    },
    Download {
        remote: String,
        local: String,
        #[arg(short, long)]
        resume: bool,
    },
    Upload {
        local: String,
        remote: String,
        #[arg(short, long)]
        resume: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { bind, root, name } => server::run(&bind, root.into(), name).await,
        Commands::Connect { addr, name, action } => {
            let resolved_addr = resolve_target(addr, name)?;
            client::run(&resolved_addr, action).await
        }
        Commands::Discover { timeout } => {
            let servers = subspace_conduit_core::discovery::discover(std::time::Duration::from_secs(timeout))?;
            if servers.is_empty() {
                println!("No subspace_conduit servers found.");
            } else {
                for s in servers {
                    println!("{}  {}:{}", s.name, s.addr, s.port);
                }
            }
            Ok(())
        }
    }
}

// -------- resolve --addr or --name into a connectable address --------
fn resolve_target(addr: Option<String>, name: Option<String>) -> anyhow::Result<String> {
    match (addr, name) {
        (Some(addr), None) => Ok(addr),
        (None, Some(name)) => {
            let timeout = std::time::Duration::from_secs(3);
            match subspace_conduit_core::discovery::resolve_by_name(&name, timeout)? {
                Some(server) => Ok(format!("{}:{}", server.addr, server.port)),
                None => anyhow::bail!("no server named '{name}' found on the local network"),
            }
        }
        (Some(_), Some(_)) => anyhow::bail!("pass either --addr or --name, not both"),
        (None, None) => anyhow::bail!("pass either --addr or --name"),
    }
}
