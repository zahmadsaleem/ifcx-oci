use anyhow::{ensure, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ifcx_oci::{
    client::{Client, Reference},
    registry::{self, Registry},
    release,
};
use std::{
    fs,
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "IFClite model artifacts, scoped OCI clients and a local registry in one binary"
)]
struct Cli {
    #[arg(long, global = true, default_value = "build/client-auth.json")]
    auth_file: PathBuf,
    /// Allow HTTP only for loopback registries.
    #[arg(long, global = true)]
    plain_http: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve a persistent, authenticated single-instance OCI registry.
    Serve {
        #[arg(long, default_value = "build/registry")]
        data: PathBuf,
        #[arg(long, default_value = "127.0.0.1:5000")]
        listen: SocketAddr,
        /// External HTTPS origin (or loopback HTTP); required for non-loopback binding.
        #[arg(long)]
        public_url: Option<String>,
        /// Public OAuth client ID to register for browser login.
        #[arg(long, requires = "oauth_redirect_uris")]
        oauth_client_id: Option<String>,
        /// Exact callback URL for the registered client; repeat per origin.
        #[arg(long = "oauth-redirect-uri", requires = "oauth_client_id")]
        oauth_redirect_uris: Vec<String>,
    },
    /// Manage local registry users and exact repository/action grants.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Obtain a scoped JWT through the OCI Bearer/token endpoint flow.
    Login {
        registry: String,
        #[arg(long)]
        username: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Convert one IFC STEP model into typed Parquet tables and GLB geometry.
    Convert {
        source: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "model")]
        model_id: String,
        #[arg(long)]
        include_source: bool,
    },
    Verify {
        directory: PathBuf,
    },
    Push {
        directory: PathBuf,
        destination: String,
    },
    Pull {
        source: String,
        #[arg(long)]
        output: PathBuf,
        /// ifcx-oci convenience: select an exact layer path; repeat for several.
        #[arg(long = "layer", value_name = "PATH")]
        layers: Vec<String>,
    },
    /// Retrieve individual OCI blobs.
    Blob {
        #[command(subcommand)]
        command: BlobCommand,
    },
    /// Inspect OCI manifests without downloading payloads.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Browse accessible repositories and their tags.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Resolve an artifact tag or reference to its verified manifest digest.
    Resolve {
        source: String,
        /// Print REGISTRY/REPOSITORY@DIGEST instead of the digest alone.
        #[arg(short = 'l', long)]
        full_reference: bool,
    },
    Copy {
        source: String,
        destination: String,
    },
    /// Generate a real IFC, convert it and demonstrate two scoped registries.
    Demo {
        #[arg(long, default_value = "build/showcase")]
        output: PathBuf,
        #[arg(long)]
        oras: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BlobCommand {
    /// Fetch a blob by REGISTRY/REPOSITORY@sha256:DIGEST and verify its bytes.
    Fetch {
        source: String,
        /// New output file, or - for raw bytes on stdout.
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ManifestCommand {
    /// Fetch the original manifest JSON by tag or digest.
    Fetch {
        source: String,
        /// New output file, or - for stdout (the default).
        #[arg(short, long, default_value = "-")]
        output: PathBuf,
        /// Prettify manifest JSON printed to stdout.
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Subcommand)]
enum RepoCommand {
    /// List accessible repositories; local login needs --scope registry:catalog:read.
    Ls {
        registry: String,
        /// Start after this repository name.
        #[arg(long)]
        last: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: ListFormat,
    },
    /// List named releases in REGISTRY/REPOSITORY.
    Tags {
        repository: String,
        /// Start after this tag name.
        #[arg(long)]
        last: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: ListFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ListFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum UserCommand {
    Add {
        #[arg(long)]
        data: PathBuf,
        username: String,
        #[arg(long = "grant")]
        grants: Vec<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    Grant {
        #[arg(long)]
        data: PathBuf,
        username: String,
        grant: String,
    },
}

fn password(stdin: bool) -> Result<String> {
    if stdin {
        let mut value = String::new();
        io::stdin().read_to_string(&mut value)?;
        Ok(value.trim_end_matches(['\r', '\n']).into())
    } else {
        Ok(rpassword::prompt_password("Password: ")?)
    }
}
fn print(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn check_output(output: &Path) -> Result<()> {
    ensure!(
        output.as_os_str() == "-" || !output.exists(),
        "Output must not already exist"
    );
    Ok(())
}

fn write_output(output: &Path, bytes: &[u8]) -> Result<()> {
    if output.as_os_str() == "-" {
        io::stdout().lock().write_all(bytes)?;
    } else {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(output).map_err(|e| e.error)?;
    }
    Ok(())
}

fn print_list(entries: &[String]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    for entry in entries {
        writeln!(stdout, "{entry}")?;
    }
    Ok(())
}

fn shutdown_signal() -> Result<impl std::future::Future<Output = ()> + Send> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("Shutting down; draining active requests");
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            data,
            listen,
            public_url,
            oauth_client_id,
            oauth_redirect_uris,
        } => {
            let registry = Registry::open(data)?;
            if let Some(public_url) = public_url {
                registry.set_public_url(&public_url)?;
            }
            if let Some(client_id) = oauth_client_id {
                registry.oauth.configure(&client_id, &oauth_redirect_uris)?;
            }
            let listener = registry::bind(listen).await?;
            eprintln!(
                "OCI registry listening on http://{} (JWT authentication required)",
                listener.local_addr()?
            );
            registry::serve_with_shutdown(listener, registry, shutdown_signal()?).await?;
        }
        Command::User { command } => match command {
            UserCommand::Add {
                data,
                username,
                grants,
                password_stdin,
            } => {
                Registry::open(data)?.auth.add_user(
                    &username,
                    &password(password_stdin)?,
                    &grants,
                )?;
                print(&serde_json::json!({"user":username,"grants":grants}))?;
            }
            UserCommand::Grant {
                data,
                username,
                grant,
            } => {
                Registry::open(data)?.auth.grant(&username, &grant)?;
                print(&serde_json::json!({"user":username,"grant":grant}))?;
            }
        },
        Command::Login {
            registry,
            username,
            scopes,
            password_stdin,
        } => {
            let mut client = Client::new(cli.auth_file, cli.plain_http)?;
            print(
                &client
                    .login(&registry, &username, &password(password_stdin)?, &scopes)
                    .await?,
            )?;
        }
        Command::Convert {
            source,
            output,
            model_id,
            include_source,
        } => print(&release::convert(
            &source,
            &output,
            &model_id,
            include_source,
        )?)?,
        Command::Verify { directory } => print(&release::verify(&directory)?)?,
        Command::Push {
            directory,
            destination,
        } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            print(&serde_json::json!({"digest":client.push(&directory,&destination).await?}))?;
        }
        Command::Pull {
            source,
            output,
            layers,
        } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            if layers.is_empty() {
                let (digest, report) = client.pull(&source, &output).await?;
                print(&serde_json::json!({"digest":digest,"verification":report}))?;
            } else {
                let (digest, layers) = client.pull_layers(&source, &output, &layers).await?;
                print(&serde_json::json!({"digest":digest,"layers":layers}))?;
            }
        }
        Command::Blob {
            command: BlobCommand::Fetch { source, output },
        } => {
            check_output(&output)?;
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            let bytes = client.fetch_blob(&source).await?;
            write_output(&output, &bytes)?;
            if output.as_os_str() != "-" {
                print(&serde_json::json!({
                    "digest": release::digest(&bytes), "size": bytes.len(), "output": output
                }))?;
            }
        }
        Command::Manifest {
            command:
                ManifestCommand::Fetch {
                    source,
                    output,
                    pretty,
                },
        } => {
            check_output(&output)?;
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            let reference = Reference::parse(&source, cli.plain_http)?;
            let (raw, _) = client.manifest(&reference).await?;
            if pretty && output.as_os_str() == "-" {
                print(&serde_json::from_slice::<serde_json::Value>(&raw)?)?;
            } else {
                write_output(&output, &raw)?;
            }
        }
        Command::Repo { command } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            match command {
                RepoCommand::Ls {
                    registry,
                    last,
                    format,
                } => {
                    let entries = client.repositories(&registry, last.as_deref()).await?;
                    match format {
                        ListFormat::Text => print_list(&entries)?,
                        ListFormat::Json => print(&serde_json::json!({"repositories":entries}))?,
                    }
                }
                RepoCommand::Tags {
                    repository,
                    last,
                    format,
                } => {
                    let entries = client.tags(&repository, last.as_deref()).await?;
                    match format {
                        ListFormat::Text => print_list(&entries)?,
                        ListFormat::Json => {
                            let reference =
                                Reference::parse(&format!("{repository}:latest"), cli.plain_http)?;
                            print(
                                &serde_json::json!({"name":reference.repository,"tags":entries}),
                            )?;
                        }
                    }
                }
            }
        }
        Command::Resolve {
            source,
            full_reference,
        } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            let digest = client.resolve(&source).await?;
            if full_reference {
                let reference = Reference::parse(&source, cli.plain_http)?;
                println!("{}/{}@{digest}", reference.registry, reference.repository);
            } else {
                println!("{digest}");
            }
        }
        Command::Copy {
            source,
            destination,
        } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            print(&serde_json::json!({"digest":client.copy(&source,&destination).await?}))?;
        }
        Command::Demo { output, oras } => {
            print(&ifcx_oci::demo::run(&output, oras.as_deref()).await?)?
        }
    }
    Ok(())
}
