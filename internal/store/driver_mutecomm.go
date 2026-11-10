//go:build !sqlcipher_mattn

package store

import (
	"database/sql"
	"encoding/hex"
	"net/url"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// DriverName is shown by the CLI and README.
const DriverName = "mutecomm/go-sqlcipher v4.4.2 (SQLCipher 4.4.2; M1 spike driver)"

// ProductionDriver is false for the M1 spike driver.
const ProductionDriver = false

func openSQLCipher(path string, key []byte) (*sql.DB, error) {
	return sql.Open("sqlite3", dsn(path, key))
}

func dsn(path string, key []byte) string {
	u := url.URL{Scheme: "file", Path: path}
	return u.String() + "?_pragma_key=x'" + hex.EncodeToString(key) + "'&_pragma_cipher_page_size=4096&_busy_timeout=5000"
}
