use std::fs;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::num::NonZeroU8;
use std::path::Path;

use anyhow::{Context, Result};
use pem::Pem;
use zeroize::{Zeroize, Zeroizing};

use crate::generate::recover_secret_from_paths;
use crate::utils;

pub fn encrypt<P>(inpath: Option<&Path>, outpath: Option<&Path>, pk: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let mut plaintext = Zeroizing::new(vec![]);
    let pem_file = fs::read(pk).context("Failed to load pubkey")?;
    let pk_pem = pem::parse(pem_file).context("Failed to parse pubkey PEM format")?;

    if let Some(path) = inpath {
        File::open(path)
            .with_context(|| format!("Failed to open plaintext: {}", path.display()))?
            .read_to_end(&mut plaintext)
            .with_context(|| format!("Failed to load plaintext: {}", path.display()))?;
    } else {
        io::stdin()
            .lock()
            .read_to_end(&mut plaintext)
            .context("Failed to read from stdin")?;
    }

    let ciphertext =
        ecies::encrypt(&pk_pem.contents, &plaintext).context("Failed to encrypt ciphertext")?;

    let mut pem = Pem {
        tag: String::from("QUORUM CIPHERTEXT"),
        contents: ciphertext,
    };

    let encoded_pem = Zeroizing::new(pem::encode_config(&pem, utils::ENCODE_CONFIG));

    pem.tag.zeroize();
    pem.contents.zeroize();

    if let Some(path) = outpath {
        fs::write(path, encoded_pem)
            .with_context(|| format!("Failed to write ciphertext to: {}", path.display()))?;
    } else {
        print!("{}", encoded_pem.as_str());
    }

    Ok(())
}

pub fn decrypt<P>(
    inpath: Option<&Path>,
    outpath: Option<&Path>,
    share_paths: &[P],
    threshold: NonZeroU8,
) -> Result<()>
where
    P: AsRef<Path>,
{
    let mut ciphertext = Zeroizing::new(vec![]);
    let secret =
        recover_secret_from_paths(share_paths, threshold).context("Failed to recover secret")?;

    if let Some(path) = inpath {
        File::open(path)?.read_to_end(&mut ciphertext)?;
    } else {
        io::stdin().lock().read_until(0x0, &mut ciphertext)?;
    }

    let mut pem = pem::parse(&ciphertext).context("Failed to parse ciphertext PEM")?;
    let plaintext = Zeroizing::new(
        ecies::decrypt(secret.as_ref(), &pem.contents).context("Failed to decrypt message")?,
    );

    pem.tag.zeroize();
    pem.contents.zeroize();

    if let Some(path) = outpath {
        fs::write(path, &plaintext)
            .with_context(|| format!("Failed to write plaintext to {}", path.display()))?;
    } else {
        io::stdout()
            .lock()
            .write_all(&plaintext)
            .context("Failed to write plaintext to stdout")?;
    }

    Ok(())
}
