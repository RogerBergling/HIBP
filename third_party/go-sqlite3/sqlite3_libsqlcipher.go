//go:build libsqlcipher

package sqlite3

/*
#cgo CFLAGS: -DUSE_LIBSQLITE3 -DSQLITE_HAS_CODEC
#cgo linux LDFLAGS: -lsqlcipher
#cgo darwin LDFLAGS: -lsqlcipher
*/
import "C"
