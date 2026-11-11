module github.com/RogerBergling/hibp

go 1.27.3

require (
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.53
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/robfig/cron/v3 v3.0.1
	github.com/shirou/gopsutil/v4 v4.26.10
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/vmware/govmomi v0.56.2
	golang.org/x/crypto v0.58.0
	golang.org/x/term v0.48.0
)

require (
	github.com/ebitengine/purego v0.11.2 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20260805114148-88456608a4f6 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/sys v0.50.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mattn/go-sqlite3 => ./third_party/go-sqlite3
