module github.com/RogerBergling/hibp

go 1.27.3

require (
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.53
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.58.0
	golang.org/x/term v0.48.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/mattn/go-sqlite3 => ./third_party/go-sqlite3
