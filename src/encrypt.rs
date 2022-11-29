use anyhow::{Context, Result};

use ecies::decrypt as ec_decrypt;
use ecies::encrypt as ec_encrypt;
use pem::{encode, Pem};
use std::fs::File;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::{fs, io};

use crate::{recover_secret, Decrypt, Encrypt};

pub fn encrypt(args: &Encrypt) -> Result<()> {
    let mut plaintext = vec![];
    let pem_file = fs::read(&args.pub_key).context("Failed to load pubkey")?;
    let pk_pem = pem::parse(pem_file).context("Failed to parse pubkey PEM format")?;

    if let Some(path) = &args.file_in {
        File::open(path)
            .with_context(|| format!("Failed to open plaintext: {}", path))?
            .read_to_end(&mut plaintext)
            .with_context(|| format!("Failed to load plaintext: {}", path))?;
    } else {
        io::stdin()
            .lock()
            .read_to_end(&mut plaintext)
            .context("Failed to read from stdin")?;
    }

    let ciphertext =
        ec_encrypt(&pk_pem.contents, &plaintext).context("Failed to encrypt ciphertext")?;

    let pem = Pem {
        tag: String::from("QUORUM CIPHERTEXT"),
        contents: ciphertext,
    };

    if let Some(path) = &args.out {
        fs::write(path, encode(&pem))
            .with_context(|| format!("Failed to write ciphertext to: {}", path))?;
    } else {
        print!("{}", encode(&pem));
    }

    Ok(())
}

pub fn decrypt(args: &Decrypt) -> Result<()> {
    let mut ciphertext = vec![];
    let secret =
        recover_secret(&args.shares, args.threshold).context("Failed to recover secret")?;

    if let Some(path) = &args.file_in {
        File::open(path)?.read_to_end(&mut ciphertext)?;
    } else {
        io::stdin().lock().read_until(0x0, &mut ciphertext)?;
    }

    let pem = pem::parse(&ciphertext).context("Failed to parse ciphertext PEM")?;
    let plaintext = ec_decrypt(&secret, &pem.contents).context("Failed to decrypt message")?;

    if let Some(path) = &args.out {
        fs::write(path, &plaintext)
            .with_context(|| format!("Failed to write plaintext to {}", path))?;
    } else {
        io::stdout()
            .lock()
            .write_all(&plaintext)
            .context("Failed to write plaintext to stdout")?;
    }

    Ok(())
}
