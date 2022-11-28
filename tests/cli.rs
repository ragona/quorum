use anyhow::Result;
use assert_cmd::Command;
use assert_fs::{self, prelude::*, TempDir};
use predicates::prelude::*;
use predicates::{self, path::exists};
use std::fs;

#[test]
fn test_runs_at_all() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.assert().code(2);
    cmd.assert().stderr(predicate::str::contains(
        "-h, --help     Print help information",
    ));

    Ok(())
}

#[test]
fn test_generate() -> Result<()> {
    let mut tmp = assert_fs::TempDir::new()?;

    generate(&mut tmp)?;
    generate_to_stdout()?;

    Ok(())
}

#[test]
fn test_zero_share_generate() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;
    let tmp = assert_fs::TempDir::new()?;

    cmd.arg("generate")
        .arg("--threshold")
        .arg("2")
        .arg("--shares")
        .arg("0")
        .arg(tmp.as_os_str())
        .assert()
        .failure();

    Ok(())
}

#[test]
fn test_threshold_larger_than_shares_generate() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;
    let tmp = assert_fs::TempDir::new()?;

    cmd.arg("generate")
        .arg("--threshold")
        .arg("5")
        .arg("--shares")
        .arg("3")
        .arg(tmp.as_os_str())
        .assert()
        .failure();

    Ok(())
}

#[test]
fn test_encrypt() -> Result<()> {
    let mut tmp = assert_fs::TempDir::new()?;
    let message = b"attack at dawn";

    generate(&mut tmp)?;
    encrypt_to_file(&mut tmp, message.clone().to_vec())?;
    encrypt_from_file(&mut tmp, message.clone().to_vec())?;
    encrypt_to_stdout(&mut tmp, message.clone().to_vec())?;

    Ok(())
}

#[test]
fn test_decrypt() -> Result<()> {
    let mut tmp = assert_fs::TempDir::new()?;
    let message = b"attack at dawn".to_vec();

    generate(&mut tmp)?;
    encrypt_to_file(&mut tmp, message.clone())?;
    decrypt_from_file(&mut tmp, message.clone())?;

    let ciphertext = fs::read(tmp.join("ciphertext").as_os_str())?;

    decrypt_from_stdin(&mut tmp, message.clone(), ciphertext)?;
    decrypt_to_file(&mut tmp, message.clone())?;

    Ok(())
}

#[test]
fn test_mismatched_shares_recovert_fails() -> Result<()> {
    let mut tmp_a = assert_fs::TempDir::new()?;
    let mut tmp_b = assert_fs::TempDir::new()?;

    generate(&mut tmp_a)?;
    generate(&mut tmp_b)?;

    let message = b"attack at dawn".to_vec();

    encrypt_to_file(&mut tmp_a, message.clone())?;

    Command::cargo_bin("quorum")?
        .arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(tmp_a.child("ciphertext").as_os_str())
        .arg(tmp_a.child("quorum_share_0.priv").as_os_str())
        .arg(tmp_b.child("quorum_share_1.priv").as_os_str())
        .assert()
        .failure();

    Ok(())
}

#[test]
fn test_not_enough_shares_fails() -> Result<()> {
    let mut tmp = assert_fs::TempDir::new()?;
    let message = b"attack at dawn".to_vec();

    generate(&mut tmp)?;
    encrypt_to_file(&mut tmp, message.clone())?;

    Command::cargo_bin("quorum")?
        .arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(tmp.child("ciphertext").as_os_str())
        .arg(tmp.child("quorum_share_0.priv").as_os_str())
        .assert()
        .failure();

    Ok(())
}

#[test]
fn test_no_shares_fails() -> Result<()> {
    let mut tmp = assert_fs::TempDir::new()?;
    let message = b"attack at dawn".to_vec();

    generate(&mut tmp)?;
    encrypt_to_file(&mut tmp, message.clone())?;

    Command::cargo_bin("quorum")?
        .arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(tmp.child("ciphertext").as_os_str())
        .assert()
        .failure();

    Ok(())
}

// Helper Functions

fn generate(tmp: &mut TempDir) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

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

    Ok(cmd)
}

fn generate_to_stdout() -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.arg("generate")
        .arg("--threshold")
        .arg("2")
        .arg("--shares")
        .arg("3")
        .assert()
        .stdout(predicate::str::contains("-----BEGIN QUORUM SHARE-----"))
        .stdout(predicate::str::contains("-----END QUORUM SHARE-----"))
        .stdout(predicate::str::contains("-----BEGIN QUORUM PUBKEY-----"))
        .stdout(predicate::str::contains("-----END QUORUM PUBKEY-----"));

    Ok(cmd)
}
fn encrypt_to_file(tmp: &mut TempDir, message: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    let pub_key = tmp.child("quorum.pub");

    cmd.arg("encrypt")
        .arg("--out")
        .arg(tmp.join("ciphertext"))
        .arg(pub_key.as_os_str())
        .write_stdin(message)
        .assert()
        .success();

    let file = fs::read_to_string(tmp.child("ciphertext").as_os_str())?;

    assert!(file.contains("-----BEGIN QUORUM CIPHERTEXT-----"));
    assert!(file.contains("-----END QUORUM CIPHERTEXT-----"));

    Ok(cmd)
}

fn encrypt_to_stdout(tmp: &mut TempDir, message: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    let pub_key = tmp.child("quorum.pub");

    cmd.arg("encrypt")
        .arg(pub_key.as_os_str())
        .write_stdin(message)
        .assert()
        .success();

    Ok(cmd)
}

fn encrypt_from_file(tmp: &mut TempDir, message: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    let pub_key = tmp.child("quorum.pub");
    let plaintext = tmp.child("plaintext");

    fs::write(plaintext.as_os_str(), message)?;

    cmd.arg("encrypt")
        .arg("--in")
        .arg(plaintext.as_os_str())
        .arg(pub_key.as_os_str())
        .assert()
        .stdout(predicate::str::contains(
            "-----BEGIN QUORUM CIPHERTEXT-----",
        ))
        .stdout(predicate::str::contains("-----END QUORUM CIPHERTEXT-----"));

    Ok(cmd)
}

fn decrypt_from_file(tmp: &mut TempDir, message: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(tmp.child("ciphertext").as_os_str())
        .arg(tmp.child("quorum_share_0.priv").as_os_str())
        .arg(tmp.child("quorum_share_1.priv").as_os_str())
        .assert()
        .stdout(predicate::eq(message.as_slice() as &[u8]));

    Ok(cmd)
}

fn decrypt_from_stdin(tmp: &mut TempDir, message: Vec<u8>, ciphertext: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg(tmp.child("quorum_share_0.priv").as_os_str())
        .arg(tmp.child("quorum_share_1.priv").as_os_str())
        .write_stdin(ciphertext)
        .assert()
        .stdout(predicate::eq(message.as_slice() as &[u8]));

    Ok(cmd)
}

fn decrypt_to_file(tmp: &mut TempDir, message: Vec<u8>) -> Result<Command> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.arg("decrypt")
        .arg("--threshold")
        .arg("2")
        .arg("--in")
        .arg(tmp.child("ciphertext").as_os_str())
        .arg("--out")
        .arg(tmp.child("plaintext").as_os_str())
        .arg(tmp.child("quorum_share_0.priv").as_os_str())
        .arg(tmp.child("quorum_share_1.priv").as_os_str())
        .assert()
        .success();

    let out = fs::read(tmp.child("plaintext").as_os_str())?;

    assert_eq!(message, out);

    Ok(cmd)
}
