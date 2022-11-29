use crate::Generate;
use anyhow::{anyhow, bail, Context, Result};
use ecies::utils::generate_keypair;
use pem::{encode, parse, Pem};
use rand::rngs::OsRng;
use rand::RngCore;
use sharks::{Share, Sharks};
use std::{fs, path::Path};

const QUORUM_ID_SIZE: usize = 32;

pub fn generate(args: &Generate) -> Result<()> {
    if args.shares == 0 {
        bail!("Must generate at least one share");
    }

    if args.threshold > args.shares {
        bail!("Number of shares must be greater than or equal to threshold");
    }

    let sharks = Sharks(args.threshold);
    let mut quorum_id = vec![0u8; QUORUM_ID_SIZE];

    OsRng.fill_bytes(&mut quorum_id);
    let (sk, pk) = generate_keypair();

    let shares: Vec<Vec<u8>> = sharks
        .dealer(&sk.serialize())
        .take(args.shares as usize)
        .map(|s| Vec::from(&s))
        .collect();

    for (i, share) in shares.iter().enumerate() {
        let mut share_with_id = share.clone();
        share_with_id.append(&mut quorum_id.clone());

        let sk_pem = Pem {
            tag: String::from("QUORUM SHARE"),
            contents: share_with_id,
        };

        let encoded_pem = encode(&sk_pem);

        if let Some(path) = &args.out {
            let share_name = format!("quorum_share_{}.priv", i);
            fs::write(Path::new(&path).join(&share_name), encoded_pem).with_context(|| {
                format!("Failed to write share file {} to {}", &share_name, path)
            })?;
        } else {
            print!("{}", encoded_pem);
        }
    }

    let pk_pem = Pem {
        tag: String::from("QUORUM PUBKEY"),
        contents: Vec::from(pk.serialize()),
    };

    let encoded_pem = encode(&pk_pem);

    if let Some(path) = &args.out {
        fs::write(Path::new(&path).join("quorum.pub"), encoded_pem)
            .with_context(|| format!("Failed to write public key to {}", path))?;
    } else {
        print!("{}", encoded_pem);
    }

    Ok(())
}

pub fn recover_secret(share_paths: &Vec<String>, threshold: u8) -> Result<[u8; 32]> {
    if share_paths.is_empty() {
        bail!("You must provide at least one share");
    }

    if share_paths.len() < threshold as usize {
        bail!("Not enough private shares provided for threshold");
    }

    if share_paths.len() > 255 {
        bail!("Too many shares provided; max of 255");
    }

    let mut shares = Vec::with_capacity(share_paths.len());
    let sharks = Sharks(threshold);

    // Extract the quorum ID from the first provided share.
    // All shares must have this same ID to prevent accidentally
    // combining shares that do not match.
    let mut quorum_id = [0u8; QUORUM_ID_SIZE];
    let first_path = share_paths.first().unwrap(); // safe, empty check above

    let file = fs::read(first_path)
        .with_context(|| format!("Failed to read share from: {}", first_path))?;

    let pem =
        parse(file).with_context(|| format!("Failed to parse PEM file from: {}", first_path))?;

    quorum_id.copy_from_slice(&pem.contents[pem.contents.len() - QUORUM_ID_SIZE..]);

    for path in share_paths {
        let file =
            fs::read(&path).with_context(|| format!("Failed to read share from: {}", &path))?;

        let mut pem =
            parse(file).with_context(|| format!("Failed to parse PEM share from: {}", &path))?;

        let mut share_quorum_id = [0u8; QUORUM_ID_SIZE];
        share_quorum_id.copy_from_slice(&pem.contents[pem.contents.len() - QUORUM_ID_SIZE..]);

        if share_quorum_id != quorum_id {
            bail!("Failed to recover secret: Shares are from different groups");
        }

        pem.contents.truncate(pem.contents.len() - QUORUM_ID_SIZE);

        let share = Share::try_from(pem.contents.as_slice())
            .map_err(|e| anyhow!("Failed to convert PEM to Share: {}", e))?;

        shares.push(share);
    }

    let secret: [u8; 32] = sharks
        .recover(&shares)
        .map_err(|e| anyhow!("Failed to recover secret: {:?}", e))?
        .try_into()
        .map_err(|e| anyhow!("Failed to convert secret into 32-byte array: {:?}", e))?;

    Ok(secret)
}
