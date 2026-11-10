# Packaging notes

These files are examples, not a complete distribution package.

## Controller server

1. Install the static binary at `/usr/local/bin/hibp`.
2. Create the `hibp` system user and `/var/lib/hibp` with mode `0700`.
3. Start the server manually once to create the encrypted database:

   ```bash
   sudo -u hibp /usr/local/bin/hibp server \
     --db /var/lib/hibp/hibp.db --create --listen 127.0.0.1:8443
   ```

4. Open the printed `http://127.0.0.1:8443/?token=...` URL through an SSH
   tunnel:

   ```bash
   ssh -L 8443:127.0.0.1:8443 user@server
   ```

5. For a systemd service, choose an unlock policy:
   - start the service manually and enter the passphrase on its terminal, or
   - use a `0600` passphrase file with full-disk encryption and
     `--passphrase-file`, accepting the at-rest trade-off.

The included `hibp.service` is a hardening baseline. It intentionally does not
contain a passphrase. Adjust `SystemCallFilter` and `ProtectSystem` if your
distribution or SQLCipher build needs additional access.

## Target helper

The app can install the helper from the host row's **Setup** button. It uploads
the controller binary, writes the restricted rule for the configured SSH
account, validates it with `visudo`, and verifies passwordless execution. The
controller must be the static release build and the CPU architectures must
match. Use the manual steps below for a different architecture or a custom
path.

Install the same binary on each managed target as:

```text
/usr/local/libexec/hibp/hibp-helper
```

It must be owned by `root:root` and must not be writable by the SSH account.
Install `hibp-helper.sudoers` in `/etc/sudoers.d/` after replacing the `hibp`
account name, then validate with:

```bash
visudo -cf /etc/sudoers.d/hibp-helper
```

The controller invokes only:

```text
sudo -n /usr/local/libexec/hibp/hibp-helper facts
sudo -n /usr/local/libexec/hibp/hibp-helper check
sudo -n /usr/local/libexec/hibp/hibp-helper apply
sudo -n /usr/local/libexec/hibp/hibp-helper reboot-check
```

No package names, host names, or shell fragments are accepted from the
controller.

## Security debt

The development build uses the `mutecomm/go-sqlcipher` spike driver. Production
deployments must use the `make production` artifact, which builds current
SQLCipher 4.20 with the patched `third_party/go-sqlite3` driver in a pinned
Alpine/musl image.
