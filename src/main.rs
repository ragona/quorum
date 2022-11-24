#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
#![allow(clippy::similar_names)]

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use pem::{encode, parse, Pem};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{self, SecureRandom as _};
use sharks::{Share, Sharks};
use std::fs::File;
use std::io::BufRead;
use std::io::Read;
use std::{fs, io, str};

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

fn generate(args: &Generate) -> Result<()> {
    let sharks = Sharks(args.threshold);
    let rng = rand::SystemRandom::new();
    let mut secret = [0; 32];

    if let Err(err) = rng.fill(&mut secret) {
        bail!("Failed to generate secret: {}", err);
    }

    let shares: Vec<Vec<u8>> = sharks
        .dealer(&secret)
        .take(args.shares as usize)
        .map(|s| Vec::from(&s))
        .collect();

    for (i, share) in shares.iter().enumerate() {
        let pem = Pem {
            tag: String::from("QUORUM SHARE"),
            contents: share.clone(),
        };

        fs::write(format!("{}/share_{}.priv", args.out, i), encode(&pem))?;
    }

    Ok(())
}

fn encrypt(args: &Encrypt) -> Result<()> {
    let mut buf = vec![];
    let secret = recover_secret(args.shares.clone(), args.threshold)?;

    io::stdin().lock().read_until(0x0, &mut buf)?;

    encrypt_buffer(&secret, &mut buf)?;

    let pem = Pem {
        tag: String::from("QUORUM CIPHERTEXT"),
        contents: buf,
    };

    if let Some(path) = &args.out {
        fs::write(path, encode(&pem))?;
    } else {
        println!("{}", encode(&pem));
    }

    Ok(())
}

fn decrypt(args: &Decrypt) -> Result<()> {
    let secret = recover_secret(args.shares.clone(), args.threshold)?;
    let mut buf = vec![];

    if let Some(path) = &args.file_in {
        File::open(path)?.read_to_end(&mut buf)?;
    } else {
        io::stdin().lock().read_until(0x0, &mut buf)?;
    }

    let mut pem = match parse(&buf) {
        Ok(p) => p,
        Err(e) => {
            bail!("Failed to parse PEM: {}", e);
        }
    };

    decrypt_buffer(&secret, &mut pem.contents)?;

    if let Some(path) = &args.out {
        fs::write(path, pem.contents)?;
    } else {
        print!("{}", str::from_utf8(&pem.contents)?);
    }

    Ok(())
}

fn recover_secret(share_paths: Vec<String>, threshold: u8) -> Result<[u8; 32]> {
    let mut shares: Vec<Share> = vec![];
    let sharks = Sharks(threshold);

    for path in share_paths {
        let file = fs::read(path)?;
        let pem = parse(file)?;
        let share = match Share::try_from(pem.contents.as_slice()) {
            Ok(s) => s,
            Err(e) => {
                bail!(
                    "Failed to convert provided PEM-encoded share to Share: {}",
                    e
                );
            }
        };

        shares.push(share);
    }

    let secret: [u8; 32] = match sharks.recover(&shares) {
        Ok(v) => match v.try_into() {
            Ok(s) => s,
            Err(_) => {
                bail!("Failed to convert secret into 32-byte array");
            }
        },
        Err(e) => {
            bail!("Failed to recover secret: {}", e);
        }
    };

    Ok(secret)
}

fn encrypt_buffer(secret: &[u8; 32], buf: &mut Vec<u8>) -> Result<()> {
    let aad = vec![];
    let mut nonce_bytes = [0u8; 12];
    let rng = rand::SystemRandom::new();
    let key = match UnboundKey::new(&CHACHA20_POLY1305, secret) {
        Ok(k) => LessSafeKey::new(k),
        Err(e) => {
            bail!("Failed to create key: {}", e)
        }
    };

    if let Err(e) = rng.fill(&mut nonce_bytes) {
        bail!("Failed to generate nonce: {}", e)
    }

    if let Err(e) = key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        buf,
    ) {
        bail!("Failed to decrypt ciphertext: {}", e);
    }

    buf.append(&mut nonce_bytes.to_vec());

    Ok(())
}

fn decrypt_buffer(secret: &[u8; 32], buf: &mut Vec<u8>) -> Result<()> {
    let aad = vec![];
    let mut nonce_bytes = [0u8; 12];
    let key = match UnboundKey::new(&CHACHA20_POLY1305, secret) {
        Ok(k) => LessSafeKey::new(k),
        Err(e) => {
            bail!("Failed to create key: {}", e)
        }
    };

    nonce_bytes.copy_from_slice(&buf[buf.len() - CHACHA20_POLY1305.nonce_len()..]);
    buf.truncate(buf.len() - CHACHA20_POLY1305.nonce_len());

    if let Err(e) = key.open_in_place(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        buf,
    ) {
        bail!("Failed to decrypt ciphertext: {}", e);
    }

    buf.truncate(buf.len() - CHACHA20_POLY1305.tag_len());

    Ok(())
}