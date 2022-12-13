use std::fs;
use std::io;
use std::num::NonZeroU8;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use libsecp256k1::util::SECRET_KEY_SIZE;
use pem::Pem;
use rand::{CryptoRng, RngCore};
use sharks::{Share, Sharks};
use zeroize::{Zeroize, Zeroizing};

use crate::utils;

const QUORUM_ID_SIZE: usize = 32;

pub struct Pems {
    pk: String,
    sks: Vec<Zeroizing<String>>,
}

impl Pems {
    pub fn pk(&self) -> &str {
        &self.pk
    }

    pub fn sks(&self) -> &[Zeroizing<String>] {
        &self.sks
    }

    pub fn into_parts(self) -> (String, Vec<Zeroizing<String>>) {
        (self.pk, self.sks)
    }

    pub fn write<W>(&self, writer: &mut W) -> Result<()>
    where
        W: io::Write,
    {
        for sk in &self.sks {
            writer.write_all(sk.as_bytes())?;
        }
        writer.write_all(self.pk.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    pub fn write_to_directory<P>(&self, dir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let dir = dir.as_ref();
        for (i, sk) in self.sks.iter().enumerate() {
            let filename = format!("quorum_share_{}.priv", i);
            let path = dir.join(filename);
            fs::write(&path, sk.as_bytes())
                .with_context(|| format!("Failed to write to {}", path.display()))?;
        }

        let path = dir.join("quorum.pub");
        fs::write(&path, self.pk.as_bytes())
            .with_context(|| format!("Failed to write to {}", path.display()))?;

        Ok(())
    }
}

pub fn generate<R>(threshold: NonZeroU8, shares: NonZeroU8, rng: &mut R) -> Result<Pems>
where
    R: RngCore + CryptoRng,
{
    let shares = shares.get();
    let threshold = threshold.get();

    if threshold > shares {
        bail!("Number of shares must be greater than or equal to threshold");
    }

    let (sk, pk) = utils::generate_keypair(rng);

    // Secret keys

    let quorum_id = {
        let mut vec = vec![0u8; QUORUM_ID_SIZE];
        rng.fill_bytes(&mut vec);
        vec
    };

    let mut sks = Vec::with_capacity(shares as usize);
    for share in Sharks(threshold)
        .dealer_rng(&sk[..], rng)
        .take(shares as usize)
    {
        let mut share = Vec::from(&share);
        share.extend_from_slice(&quorum_id[..]);

        let encoded_pem = {
            let mut sk_pem = Pem {
                tag: String::from("QUORUM SHARE"),
                contents: share,
            };
            let encoded_pem = Zeroizing::new(pem::encode_config(&sk_pem, utils::ENCODE_CONFIG));
            sk_pem.tag.zeroize();
            sk_pem.contents.zeroize();
            encoded_pem
        };

        sks.push(encoded_pem);
    }

    // Public key

    let pk = {
        let pk_pem = Pem {
            tag: String::from("QUORUM PUBKEY"),
            contents: Vec::from(pk.serialize()),
        };
        pem::encode_config(&pk_pem, utils::ENCODE_CONFIG)
    };

    Ok(Pems { pk, sks })
}

pub fn recover_secret<B>(
    share_bytes: &[B],
    threshold: NonZeroU8,
) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>>
where
    B: AsRef<[u8]>,
{
    let threshold = threshold.get();

    if share_bytes.is_empty() {
        bail!("You must provide at least one share");
    }

    if share_bytes.len() < threshold as usize {
        bail!("Not enough private shares provided for threshold");
    }

    if share_bytes.len() > std::u8::MAX as usize {
        bail!("Too many shares provided; max of 255");
    }

    let mut quorum_id: Option<[u8; QUORUM_ID_SIZE]> = None;
    let mut share_quorum_id = [0u8; QUORUM_ID_SIZE];

    let mut shares = Vec::with_capacity(share_bytes.len());
    for (i, bytes) in share_bytes.iter().enumerate() {
        let bytes = bytes.as_ref();

        let mut pem = pem::parse(bytes)
            .with_context(|| format!("Failed to parse PEM share (index {})", i))?;

        share_quorum_id.copy_from_slice(&pem.contents[pem.contents.len() - QUORUM_ID_SIZE..]);

        match quorum_id {
            Some(quorum_id) if share_quorum_id != quorum_id => {
                bail!("Failed to recover secret: Shares are from different groups")
            }
            Some(_) => (),
            None => quorum_id = Some(share_quorum_id),
        }

        pem.contents.truncate(pem.contents.len() - QUORUM_ID_SIZE);

        let share = Share::try_from(pem.contents.as_slice())
            .map_err(|e| anyhow!("Failed to convert PEM to Share: {}", e))?;

        pem.tag.zeroize();
        pem.contents.zeroize();

        shares.push(share);
    }

    let secret: Zeroizing<[u8; SECRET_KEY_SIZE]> = Zeroizing::new(
        Sharks(threshold)
            .recover(&shares)
            .map_err(|e| anyhow!("Failed to recover secret: {:?}", e))?
            .try_into()
            .map_err(|e| anyhow!("Failed to convert secret into 32-byte array: {:?}", e))?,
    );

    Ok(secret)
}

pub fn recover_secret_from_paths<P>(
    share_paths: &[P],
    threshold: NonZeroU8,
) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>>
where
    P: AsRef<Path>,
{
    let share_bytes = share_paths
        .iter()
        .map(|path| {
            let path = path.as_ref();
            let bytes = fs::read(path)
                .with_context(|| format!("Failed to read path {}", path.display()))?;
            Ok::<_, anyhow::Error>(bytes)
        })
        .collect::<Result<Vec<_>>>()?;
    recover_secret(&share_bytes, threshold)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    const SHARES: u8 = 5;
    const THRESHOLD: u8 = 3;

    const GENERATED: &[&str] = &[
        r#"
-----BEGIN QUORUM SHARE-----
AfQStZug4TZRODovYor4dbOaCtw1+IIgDhyBRFt0GYWQlsIbIc/0iyY+CX7rlFSQ
WLzvAZ46ClaSoyx5jvNH2Ck=
-----END QUORUM SHARE-----
"#,
        r#"
-----BEGIN QUORUM SHARE-----
AnDlmXgJ6Rhyr5Tvt8OcxyLcDf5sT6E9daP4igjtF3DolsIbIc/0iyY+CX7rlFSQ
WLzvAZ46ClaSoyx5jvNH2Ck=
-----END QUORUM SHARE-----
"#,
        r#"
-----BEGIN QUORUM SHARE-----
Axm/51D7UcdBwU3822RWvW5bR8K9iRLQ4/f+WHCyow4olsIbIc/0iyY+CX7rlFSQ
WLzvAZ46ClaSoyx5jvNH2Ck=
-----END QUORUM SHARE-----
"#,
        r#"
-----BEGIN QUORUM SHARE-----
BKZr7W5Wd0OHLUp0+CLvclHtmVk1e4fsCJKoAD5H3zGplsIbIc/0iyY+CX7rlFSQ
WLzvAZ46ClaSoyx5jvNH2Ck=
-----END QUORUM SHARE-----
"#,
        r#"
-----BEGIN QUORUM SHARE-----
Bc8xk0akz5y0Q5NnlIUlCB1q02XkvTQBnsau0kYYa09plsIbIc/0iyY+CX7rlFSQ
WLzvAZ46ClaSoyx5jvNH2Ck=
-----END QUORUM SHARE-----
"#,
        r#"
-----BEGIN QUORUM PUBKEY-----
BGmHRxBQQjAT4FyB6UD9mMqYasrC1KBHNmCEa6FzFvGSZt4Mv9oJUoEe40UufxcS
Pc+8cpsx97SgfQ8+6SD3Vig=
-----END QUORUM PUBKEY-----
    "#,
    ];

    #[test]
    fn test_generate() -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(1234);
        let pems = generate(
            NonZeroU8::new(THRESHOLD).unwrap(),
            NonZeroU8::new(SHARES).unwrap(),
            &mut rng,
        )?;
        let mut actual = Vec::new();
        for sk in &pems.sks {
            actual.push(sk.as_str().trim().to_string());
        }
        actual.push(pems.pk.trim().to_string());
        let expected = GENERATED
            .iter()
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>();
        assert_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn test_recover_secret() -> Result<()> {
        const EXPECTED: [u8; SECRET_KEY_SIZE] = [
            157, 72, 203, 179, 82, 89, 233, 98, 86, 227, 60, 14, 45, 50, 15, 255, 29, 64, 224, 228,
            62, 49, 205, 152, 72, 135, 150, 35, 43, 173, 251, 80,
        ];
        let actual = recover_secret(
            &GENERATED[..GENERATED.len() - 1],
            NonZeroU8::new(THRESHOLD).unwrap(),
        )?;
        assert_eq!(&EXPECTED, &*actual);
        Ok(())
    }
}
