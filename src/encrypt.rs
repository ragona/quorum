use anyhow::{anyhow, Result};

use ecies::decrypt as ec_decrypt;
use ecies::encrypt as ec_encrypt;
use pem::{encode, Pem};
use std::fs::File;
use std::io::BufRead;
use std::io::Read;
use std::{fs, io, str};

use crate::{recover_secret, Decrypt, Encrypt};

pub fn encrypt(args: &Encrypt) -> Result<()> {
    let mut plaintext = vec![];
    let pk_pem = fs::read(&args.pub_key)?;
    let pk_pem = pem::parse(pk_pem)?;

    if let Some(path) = &args.file_in {
        File::open(path)?.read_to_end(&mut plaintext)?;
    } else {
        io::stdin().lock().read_until(0x0, &mut plaintext)?;
    }

    let ciphertext = ec_encrypt(&pk_pem.contents, &plaintext).unwrap();

    let pem = Pem {
        tag: String::from("QUORUM CIPHERTEXT"),
        contents: ciphertext,
    };

    if let Some(path) = &args.out {
        fs::write(path, encode(&pem))?;
    } else {
        print!("{}", encode(&pem));
    }

    Ok(())
}

pub fn decrypt(args: &Decrypt) -> Result<()> {
    let secret = recover_secret(args.shares.clone(), args.threshold)?;
    let mut ciphertext = vec![];

    if let Some(path) = &args.file_in {
        File::open(path)?.read_to_end(&mut ciphertext)?;
    } else {
        io::stdin().lock().read_until(0x0, &mut ciphertext)?;
    }

    let pem = pem::parse(&ciphertext).map_err(|e| anyhow!("Failed to parse PEM: {:?}", e))?;
    let plaintext = ec_decrypt(&secret, &pem.contents)?;

    if let Some(path) = &args.out {
        fs::write(path, &plaintext)?;
    } else {
        print!("{}", str::from_utf8(&plaintext)?);
    }

    Ok(())
}
