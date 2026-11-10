# Local patch

This is `github.com/mattn/go-sqlite3` v1.14.53, vendored only for the production
SQLCipher build.

Changes from upstream:

1. `SQLiteDriver` has a `Key []byte` field.
2. `SQLiteDriver.Open` calls `sqlite3_key` immediately after `sqlite3_open_v2`
   and before any SQL statement or schema read.
3. `sqlite3_libsqlcipher.go` adds the `libsqlcipher` build tag, defines
   `SQLITE_HAS_CODEC` and `USE_LIBSQLITE3`, and links `-lsqlcipher`.
4. `sqlite3-binding.c` and `sqlite3-binding.h` are intentionally removed; this
   copy must be built with `-tags libsqlcipher` against an external SQLCipher.

Do not update this directory without re-applying and testing the key-before-read
change. The production Dockerfile builds and tests the patched driver.
