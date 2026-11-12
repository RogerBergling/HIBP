# Production build: current SQLCipher + patched mattn/go-sqlite3, static musl ELF.
# Build from the repository root:
#   docker build -f packaging/Dockerfile -t hibp-production .
#   docker run --rm hibp-production version

FROM golang:1.27.4-alpine AS build

ARG VERSION=0.1.0-dev
ARG BUILD_NUMBER=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG BUILD_TARGET=linux/amd64
ARG BUILD_TYPE=production

ARG SQLCIPHER_VERSION=4.20.0

RUN apk add --no-cache \
    build-base \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    zstd-dev \
    zstd-static \
    curl \
    perl \
    tar \
    linux-headers \
    ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
COPY third_party ./third_party
COPY cmd ./cmd
COPY internal ./internal
RUN go mod download

RUN curl -fsSL \
      "https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v${SQLCIPHER_VERSION}.tar.gz" \
      -o /tmp/sqlcipher.tar.gz \
    && tar -xzf /tmp/sqlcipher.tar.gz -C /tmp \
    && cd "/tmp/sqlcipher-${SQLCIPHER_VERSION}" \
    && CFLAGS="-DSQLITE_HAS_CODEC -DSQLCIPHER_CRYPTO_OPENSSL -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown -DSQLITE_TEMP_STORE=2" LDFLAGS="-lcrypto" ./configure \
         --disable-shared \
         --enable-static \
         --disable-tcl \
    && make -j"$(nproc)" \
    && make install DESTDIR=/opt/sqlcipher \
    && ln -sf libsqlite3.a /opt/sqlcipher/usr/local/lib/libsqlcipher.a

RUN CGO_ENABLED=1 \
       CGO_CFLAGS="-I/opt/sqlcipher/usr/local/include" \
       CGO_LDFLAGS="-L/opt/sqlcipher/usr/local/lib -lsqlcipher -lssl -lcrypto -lz -lzstd -lm -lpthread -ldl" \
       go test -tags "sqlcipher_mattn libsqlcipher netgo osusergo sqlite_omit_load_extension" ./...

RUN mkdir -p /out \
    && CGO_ENABLED=1 \
       CGO_CFLAGS="-I/opt/sqlcipher/usr/local/include" \
       CGO_LDFLAGS="-L/opt/sqlcipher/usr/local/lib -lsqlcipher -lssl -lcrypto -lz -lzstd -lm -lpthread -ldl" \
       go build -trimpath \
         -tags "sqlcipher_mattn libsqlcipher netgo osusergo sqlite_omit_load_extension" \
         -ldflags "-s -w -linkmode external -extldflags '-static' -X main.version=${VERSION} -X main.buildNumber=${BUILD_NUMBER} -X main.buildCommit=${BUILD_COMMIT} -X main.buildDate=${BUILD_DATE} -X main.buildTarget=${BUILD_TARGET} -X main.buildType=${BUILD_TYPE}" \
         -o /out/hibp ./cmd/hibp \
    && file /out/hibp \
    && (ldd /out/hibp 2>&1 || true) | tee /tmp/ldd \
    && ! grep -q '=>' /tmp/ldd

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hibp /hibp
USER 65532:65532
ENTRYPOINT ["/hibp"]
CMD ["server", "--db", "/var/lib/hibp/hibp.db", "--listen", "127.0.0.1:8443"]
