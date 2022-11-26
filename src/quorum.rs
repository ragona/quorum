use crate::Generate;
use anyhow::{bail, Result};
use ecies::utils::generate_keypair;
use pem::{encode, parse, Pem};
use rand::rngs::OsRng;
use rand::RngCore;
use sharks::{Share, Sharks};
use std::{fs, path::Path};

const QUORUM_ID_SIZE: usize = 32;

pub(crate) fn generate(args: &Generate) -> Result<()> {
    let sharks = Sharks(args.threshold);
    let mut quorum_id = vec![0u8; QUORUM_ID_SIZE];

    OsRng.fill_bytes(&mut quorum_id);
    let (sk, pk) = generate_keypair();

    let shares: Vec<Vec<u8>> = sharks
        .dealer(&sk.serialize())
        .take(args.shares as usize)
        .map(|s| Vec::from(&s))
        .collect();

    let out_path = Path::new(&args.out);

    for (i, share) in shares.iter().enumerate() {
        let mut share_with_id = share.clone();
        share_with_id.append(&mut quorum_id.clone());

        let sk_pem = Pem {
            tag: String::from("QUORUM SHARE"),
            contents: share_with_id,
        };

        fs::write(
            out_path.join(format!("quorum_share_{}.priv", i)),
            encode(&sk_pem),
        )?;
    }

    let pk_pem = Pem {
        tag: String::from("QUORUM PUBKEY"),
        contents: Vec::from(pk.serialize()),
    };

    fs::write(out_path.join("quorum.pub"), encode(&pk_pem))?;

    Ok(())
}

pub(crate) fn recover_secret(share_paths: Vec<String>, threshold: u8) -> Result<[u8; 32]> {
    let mut shares = Vec::with_capacity(share_paths.len());
    let sharks = Sharks(threshold);
    let mut quorum_id = [0u8; QUORUM_ID_SIZE];

    // Extract the quorum ID from the first provided share.
    // All shares must have this same ID to prevent accidentally
    // combining shares that do not match.
    if let Some(path) = share_paths.first() {
        let file = fs::read(path)?;
        let pem = parse(file)?;
        quorum_id.copy_from_slice(&pem.contents[pem.contents.len() - QUORUM_ID_SIZE..]);
    }

    for path in share_paths {
        let file = fs::read(path)?;
        let mut pem = parse(file)?;

        let mut share_quorum_id = [0u8; QUORUM_ID_SIZE];
        share_quorum_id.copy_from_slice(&pem.contents[pem.contents.len() - QUORUM_ID_SIZE..]);

        if share_quorum_id != quorum_id {
            bail!("Failed to recover secret: Shares are from different groups");
        }

        pem.contents.truncate(pem.contents.len() - QUORUM_ID_SIZE);

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
