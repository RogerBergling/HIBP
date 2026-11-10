//go:build sqlcipher_mattn && libsqlcipher

package store

import (
	"database/sql"
	"fmt"
	"sync/atomic"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// DriverName is shown by the CLI and README.
const DriverName = "mattn/go-sqlite3 + current SQLCipher (production build)"

// ProductionDriver is true for the maintained-driver build.
const ProductionDriver = true

var driverSequence atomic.Uint64

func openSQLCipher(path string, key []byte) (*sql.DB, error) {
	name := fmt.Sprintf("hibp-sqlcipher-%d", driverSequence.Add(1))
	driver := &sqlite3.SQLiteDriver{
		// The local driver patch passes Key to sqlite3_key immediately after
		// sqlite3_open_v2 and before any schema read or PRAGMA.
		Key: key,
	}
	sql.Register(name, driver)
	return sql.Open(name, path)
}
