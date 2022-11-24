#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
#![allow(clippy::similar_names)]

mod encrypt;
mod quorum;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::str;

use encrypt::{decrypt, encrypt};
use quorum::{generate, recover_secret};

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
    out: String,
}

#[derive(Args)]
/// Encrypt using key shares
struct Encrypt {
    /// Number of shares required to reconstruct the secret
    #[arg(short, long, default_value_t = 3)]
    threshold: u8,

    /// Path to write ciphertext
    #[arg(short, long)]
    out: Option<String>,

    /// Paths to share key files
    shares: Vec<String>,
}

#[derive(Args)]
/// Decrypt using key shares
struct Decrypt {
    /// Number of shares required to reconstruct the secret
    #[arg(short, long, default_value_t = 3)]
    threshold: u8,

    /// Path to write plaintext
    #[arg(short, long)]
    out: Option<String>,

    /// Path to read ciphertext file
    #[arg(short = 'i', long = "in")]
    file_in: Option<String>,

    /// Paths to share key files
    shares: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => generate(&args),
        Commands::Encrypt(args) => encrypt(&args),
        Commands::Decrypt(args) => decrypt(&args),
    }
}
