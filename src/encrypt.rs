use anyhow::{bail, Result};
use pem::{encode, parse, Pem};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{self, SecureRandom as _};
use std::fs::File;
use std::io::BufRead;
use std::io::Read;
use std::{fs, io, str};

use crate::{recover_secret, Decrypt, Encrypt};

pub(crate) fn encrypt(args: &Encrypt) -> Result<()> {
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

pub(crate) fn decrypt(args: &Decrypt) -> Result<()> {
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
