use std::ops::Deref;

pub use ecies::PublicKey;
use libsecp256k1::util::SECRET_KEY_SIZE;
use pem::{EncodeConfig, LineEnding};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub(crate) const ENCODE_CONFIG: EncodeConfig = EncodeConfig {
    line_ending: LineEnding::LF,
};

pub struct SecretKey(Zeroizing<[u8; SECRET_KEY_SIZE]>);

impl Deref for SecretKey {
    type Target = [u8; SECRET_KEY_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn generate_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
where
    R: RngCore + CryptoRng,
{
    loop {
        let mut sk_bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        rng.fill_bytes(sk_bytes.as_mut());
        if let Ok(sk) = ecies::SecretKey::parse(&sk_bytes) {
            let pk = PublicKey::from_secret_key(&sk);
            break (SecretKey(sk_bytes), pk);
        }
    }
}
