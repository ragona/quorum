use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use pem::{encode, parse, Pem};
use ring::aead::*;
use ring::rand::{self, SecureRandom as _};
use sharks::{Share, Sharks};
use std::io::BufRead;
use std::{fs, io};

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
    #[arg(short, long)]
    out: Option<String>,
}

#[derive(Args)]
/// Encrypt using key shares
struct Encrypt {
    /// Number of shares required to reconstruct the secret
    #[arg(short, long, default_value_t = 3)]
    threshold: u8,

    /// Paths to share key files
    #[arg(short, long, value_delimiter = ' ')]
    shares: Vec<String>,

    /// Path to write ciphertext
    #[arg(short, long)]
    out: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => generate(&args),
        Commands::Encrypt(args) => encrypt(&args),
    }
}

fn generate(args: &Generate) -> Result<()> {
    let sharks = Sharks(args.threshold);
    let rng = rand::SystemRandom::new();
    let mut secret = vec![0; 32];

    rng.fill(&mut secret).unwrap();

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

        if let Some(out) = &args.out {
            fs::write(format!("{}/share_{}.priv", out, i), encode(&pem))?;
        } else {
            println!("{}", encode(&pem));
        }
    }

    Ok(())
}

fn encrypt(args: &Encrypt) -> Result<()> {
    let mut shares: Vec<Share> = vec![];
    let sharks = Sharks(args.threshold);

    for path in &args.shares {
        let file = fs::read(path)?;
        let pem = parse(file)?;
        let share =
            Share::try_from(pem.contents.as_slice()).expect("Failed to convert PEM to Share");

        shares.push(share);
    }

    let secret = sharks.recover(&shares).unwrap();

    let mut buf = vec![];
    io::stdin().lock().read_until(0x0, &mut buf)?;

    encrypt_with_secret(&secret, &mut buf)?;

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

fn encrypt_with_secret(secret: &Vec<u8>, buf: &mut Vec<u8>) -> Result<()> {
    let aad = vec![];
    let key = UnboundKey::new(&CHACHA20_POLY1305, &secret).unwrap();
    let key = LessSafeKey::new(key); //We always use a random Nonce

    let rng = rand::SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.seal_in_place_append_tag(nonce, Aad::from(aad), buf)
        .unwrap();

    Ok(())
}
