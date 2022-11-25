# Quorum

Quorum is a simple CLI for generating key shares, and using them to encrypt data.
It's intended to wrap small files, like sensitive private keys.
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

### Generate a default quorum where 3 of 5 shares are required for operations 

Private share key files are written to the provided path. 

```
➜  ~ quorum generate /tmp
➜  ~ ls /tmp/
share_0.priv
share_1.priv
share_2.priv
share_3.priv
share_4.priv
➜  ~ cat /tmp/share_0.priv
-----BEGIN QUORUM SHARE-----
AXZA8SCcpRbRceRZjxwksopOKSbFwW3rOVS1QSmzIsyQ
-----END QUORUM SHARE-----
```
  
### Encrypt a message

Use any three of the five shares to encrypt the message.

```
➜  ~ echo "attack at dawn" | quorum encrypt /tmp/share_0.priv /tmp/share_2.priv /tmp/share_4.priv
-----BEGIN QUORUM CIPHERTEXT-----
t+J9WTSQ4FNNGY6JUM4PNF6jKNe6GbgBlJrx7uChIlROhXSKmtQpQX5bdg==
-----END QUORUM CIPHERTEXT-----
```

### Decrypt the ciphertext

Decrypt the ciphertext with a different three shares to recover the message.

```
➜  ~ quorum decrypt /tmp/share_0.priv /tmp/share_1.priv /tmp/share_2.priv
-----BEGIN QUORUM CIPHERTEXT-----
t+J9WTSQ4FNNGY6JUM4PNF6jKNe6GbgBlJrx7uChIlROhXSKmtQpQX5bdg==
-----END QUORUM CIPHERTEXT-----

attack at dawn
```