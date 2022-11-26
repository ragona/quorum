# Quorum

Quorum is a simple CLI for generating key shares, and using them to encrypt data.
It's intended to wrap small files, like sensitive private keys.
Quorum uses Shamir Secret Sharing to split an ed25519 private key.
Messages are encrypted using ECIES with AES-GCM.
You should use it in a highly monitored key ceremony,
and then distribute the key shares to trusted parties.
After the ceremony, ensure that no one party has a full quorum of shares.

```
Usage: quorum <COMMAND>

Commands:
  generate  Generate key shares to be distributed among share-holders
  encrypt   Encrypt using key shares
  decrypt   Decrypt using key shares
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

## Examples

### Generate a default quorum

Three of five shares will be required to decrypt ciphertext.
Public key and private share key files are written to the provided path.

```
➜  ~ quorum generate /tmp
➜  ~ ls /tmp/
quorum.pub
quorum_share_0.priv
quorum_share_1.priv
quorum_share_2.priv
quorum_share_3.priv
quorum_share_4.priv
➜  ~ cat /tmp/quorum.pub
-----BEGIN QUORUM PUBKEY-----
BONpYZpA8M2wcYIRvHY3CK529Fmnz+uKim2f2sUqRRnpVdroCu+ODDa+T2Hh2P8V
dlZml1BFWQSqouSff8bYdbI=
-----END QUORUM PUBKEY-----
➜  ~ cat /tmp/quorum_share_0.priv
-----BEGIN QUORUM SHARE-----
AXZA8SCcpRbRceRZjxwksopOKSbFwW3rOVS1QSmzIsyQ
-----END QUORUM SHARE-----
```
  
### Encrypt a message

Encrypt a message with the quorum public key.

```
➜  ~ echo "attack at dawn" | quorum encrypt /tmp/quorum.pub
-----BEGIN QUORUM CIPHERTEXT-----
BOe+ISgYxTST4xcUxiCIGxi1Rn0ELXLZyADE95YClwGOfG+qYrEz71v/uy1STXXO
63Bzi/6FI8XZbDG+tPfCfNlHyVezne7BHBaIKiOPiNBcqqFcJsAi289Se53PmiGa
92gmllkaug5W/hvCN6NQLA==
-----END QUORUM CIPHERTEXT-----
```

### Decrypt the ciphertext

Decrypt the ciphertext with a different three shares to recover the message.

```
➜  ~ quorum decrypt /tmp/quorum_share_0.priv /tmp/quorum_share_1.priv /tmp/quorum_share_2.priv
-----BEGIN QUORUM CIPHERTEXT-----
BOe+ISgYxTST4xcUxiCIGxi1Rn0ELXLZyADE95YClwGOfG+qYrEz71v/uy1STXXO
63Bzi/6FI8XZbDG+tPfCfNlHyVezne7BHBaIKiOPiNBcqqFcJsAi289Se53PmiGa
92gmllkaug5W/hvCN6NQLA==
-----END QUORUM CIPHERTEXT-----
attack at dawn
```