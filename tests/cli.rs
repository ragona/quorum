use anyhow::Result;
use assert_cmd::Command;
use assert_fs::{self, prelude::*};
use predicates::prelude::*;
use predicates::{self, path::exists};
use std::fs;

#[test]
fn runs_at_all() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.assert().code(2);
    cmd.assert().stderr(predicate::str::contains(
        "-h, --help     Print help information",
    ));

    Ok(())
}

#[test]
fn generate() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;
    let tmp = assert_fs::TempDir::new()?;

    cmd.arg("generate")
        .arg("--threshold")
        .arg("2")
        .arg("--shares")
        .arg("3")
        .arg(tmp.as_os_str())
        .assert()
        .success();

    tmp.child("quorum.pub").assert(exists());

    for i in 0..3 {
        let filename = format!("quorum_share_{}.priv", i);
        let path = tmp.child(filename);

        path.assert(exists());

        let share = fs::read_to_string(&path)?;

        assert!(share.contains("-----BEGIN QUORUM SHARE-----"));
        assert!(share.contains("-----END QUORUM SHARE-----"));
    }

    Ok(())
}

#[test]
fn encrypt_decrypt() -> Result<()> {
    let mut gen = Command::cargo_bin("quorum")?;
    let tmp = assert_fs::TempDir::new()?;

    gen.arg("generate")
        .arg("--threshold")
        .arg("2")
        .arg("--shares")
        .arg("3")
        .arg(tmp.as_os_str())
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("quorum")?;
    let pub_key = tmp.child("quorum.pub");
    let message = b"attack at dawn".to_vec();

    cmd.arg("encrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--out")
        .arg(tmp.join("ciphertext"))
        .arg(pub_key.as_os_str())
        .write_stdin(message.clone())
        .assert()
        .success();

    let ciphertext_path = tmp.child("ciphertext");
    ciphertext_path.assert(exists());

    let ciphertext = fs::read_to_string(&ciphertext_path)?;

    assert!(ciphertext.contains("-----BEGIN QUORUM CIPHERTEXT-----"));
    assert!(ciphertext.contains("-----END QUORUM CIPHERTEXT-----"));

    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(ciphertext_path.as_os_str())
        .arg(tmp.child("quorum_share_0.priv").as_os_str())
        .arg(tmp.child("quorum_share_1.priv").as_os_str())
        .assert()
        .stdout(predicate::eq(message.as_slice() as &[u8]));

    Ok(())
}
