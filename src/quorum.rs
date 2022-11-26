use crate::Generate;
use anyhow::{bail, Result};
use ecies::utils::generate_keypair;
use pem::{encode, parse, Pem};
use sharks::{Share, Sharks};
use std::{fs, path::Path};

pub(crate) fn generate(args: &Generate) -> Result<()> {
    let sharks = Sharks(args.threshold);
    let (sk, pk) = generate_keypair();

    let shares: Vec<Vec<u8>> = sharks
        .dealer(&sk.serialize())
        .take(args.shares as usize)
        .map(|s| Vec::from(&s))
        .collect();

    let out_path = Path::new(&args.out);

    for (i, share) in shares.iter().enumerate() {
        let pem = Pem {
            tag: String::from("QUORUM SHARE"),
            contents: share.clone(),
        };

        fs::write(
            out_path.join(format!("quorum_share_{}.priv", i)),
            encode(&pem),
        )?;
    }

    let pem = Pem {
        tag: String::from("QUORUM PUBKEY"),
        contents: Vec::from(pk.serialize()),
    };

    fs::write(out_path.join("quorum.pub"), encode(&pem))?;

    Ok(())
}

pub(crate) fn recover_secret(share_paths: Vec<String>, threshold: u8) -> Result<[u8; 32]> {
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
