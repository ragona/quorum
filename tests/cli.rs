use anyhow::Result;
use assert_cmd::prelude::*;
use assert_fs::{self, prelude::*};
use predicates::{self, path::exists};
use std::{fs, process::Command};

#[test]
fn runs_at_all() -> Result<()> {
    let mut cmd = Command::cargo_bin("quorum")?;

    cmd.assert().code(2);
    cmd.assert().stderr(predicates::str::contains(
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

    for i in 0..3 {
        let filename = format!("share_{}.priv", i);
        let path = tmp.child(filename);

        path.assert(exists());

        let share = fs::read_to_string(&path)?;

        assert!(share.contains("-----BEGIN QUORUM SHARE-----"));
        assert!(share.contains("-----END QUORUM SHARE-----"));
    }

    Ok(())
}
