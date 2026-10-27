use anyhow::Result;
use clap::{Parser, Subcommand};
use ifcx_oci::{
    client::Client,
    registry::{self, Registry},
    release,
};
use std::{
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
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
    /// Serve a persistent, authenticated loopback OCI registry.
    Serve {
        #[arg(long, default_value = "build/registry")]
        data: PathBuf,
        #[arg(long, default_value = "127.0.0.1:5000")]
        listen: SocketAddr,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { data, listen } => {
            let registry = Registry::open(data)?;
            let listener = registry::bind(listen).await?;
            eprintln!(
                "Local OCI registry: http://{} (JWT authentication required)",
                listener.local_addr()?
            );
            tokio::select! {result=registry::serve(listener,registry)=>result?,result=tokio::signal::ctrl_c()=>result?,};
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
        Command::Pull { source, output } => {
            let client = Client::new(cli.auth_file, cli.plain_http)?;
            let (digest, report) = client.pull(&source, &output).await?;
            print(&serde_json::json!({"digest":digest,"verification":report}))?;
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
