# Third-party notices

HIBP is distributed under the MIT license. The following third-party components
are compiled into or used by the application. Their licenses remain in effect.

| Component | License | Use |
|---|---|---|
| `github.com/mattn/go-sqlite3` (local patch in `third_party/go-sqlite3`) | MIT | SQLite database driver |
| SQLCipher | BSD-style | Encrypted SQLite database |
| `github.com/mutecomm/go-sqlcipher` | MIT | Development-only SQLCipher driver |
| `github.com/go-webauthn/webauthn` | BSD-3-Clause | WebAuthn/passkey authentication |
| `github.com/shirou/gopsutil/v4` | BSD-3-Clause | Read-only host metrics and system information |
| `github.com/vmware/govmomi` | Apache-2.0 | Read-only vCenter alarm polling |
| `github.com/skip2/go-qrcode` | MIT | TOTP enrollment QR |
| `golang.org/x/crypto` | BSD-3-Clause | SSH, Argon2id, BLAKE2b |
| `golang.org/x/sys` | BSD-3-Clause | Low-level system calls |
| `golang.org/x/term` | BSD-3-Clause | Terminal passphrase input |
| `github.com/google/uuid` | BSD-3-Clause | UUID generation |

The source distributions of these projects contain the full license texts.
Transitive Go modules and their versions are recorded in `go.sum`; this table
is not a complete SBOM. Generate a dependency/license report before
redistribution in a regulated environment.
The production Docker build downloads SQLCipher from its upstream release and
compiles it into the binary; review the SQLCipher license and OpenSSL license
before redistribution.
