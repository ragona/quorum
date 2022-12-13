#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::redundant_pub_crate)]

use std::io;
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::str;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use rand::rngs::OsRng;

use quorum::{decrypt, encrypt, generate};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate key shares to be distributed among share-holders
    Generate(Generate),

    /// Encrypt using key shares
    Encrypt(Encrypt),

    /// Decrypt using key shares
    Decrypt(Decrypt),
}

#[derive(Args)]
/// Generate a new set of quorum keys
struct Generate {
    /// Number of shares required to reconstruct the secret
    #[arg(short, long, default_value_t = 3)]
    threshold: u8,

    /// Number of shares that will be generated
    #[arg(short, long, default_value_t = 5)]
    shares: u8,

    /// Path to write private share keys
    out: Option<PathBuf>,
}

#[derive(Args)]
/// Encrypt using key shares
struct Encrypt {
    /// Path to write ciphertext
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Path to read ciphertext file
    #[arg(short = 'i', long = "in")]
    file_in: Option<PathBuf>,

    /// Path to quorum public key
    pub_key: PathBuf,
}

#[derive(Args)]
/// Decrypt using key shares
struct Decrypt {
    /// Number of shares required to reconstruct the secret
    #[arg(short, long, default_value_t = 3)]
    threshold: u8,

    /// Path to write plaintext
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Path to read ciphertext file
    #[arg(short = 'i', long = "in")]
    file_in: Option<PathBuf>,

    /// Paths to share key files
    shares: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut rng = OsRng;
    match cli.command {
        Commands::Generate(Generate {
            threshold,
            shares,
            out,
        }) => {
            let threshold = NonZeroU8::new(threshold)
                .ok_or_else(|| anyhow::anyhow!("threshold must be greater than zero"))?;
            let shares = NonZeroU8::new(shares)
                .ok_or_else(|| anyhow::anyhow!("shares must be greater than zero"))?;
            let pems = generate(threshold, shares, &mut rng)?;
            if let Some(dir) = out {
                pems.write_to_directory(dir)?;
            } else {
                let mut stdout = io::stdout().lock();
                pems.write(&mut stdout)?;
            }
            Ok(())
        }
        Commands::Encrypt(Encrypt {
            file_in,
            out,
            pub_key,
        }) => {
            encrypt(file_in.as_deref(), out.as_deref(), pub_key)?;
            Ok(())
        }
        Commands::Decrypt(Decrypt {
            file_in,
            out,
            shares,
            threshold,
        }) => {
            let threshold = NonZeroU8::new(threshold)
                .ok_or_else(|| anyhow::anyhow!("threshold must be greater than zero"))?;
            decrypt(file_in.as_deref(), out.as_deref(), &shares, threshold)?;
            Ok(())
        }
    }
}
