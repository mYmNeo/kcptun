#!/usr/bin/env bash

BUILD_DIR=$(dirname "$0")/build
mkdir -p $BUILD_DIR
cd $BUILD_DIR

export GO111MODULE=on
echo "Setting GO111MODULE to" $GO111MODULE

SALT=${SALT:-$(dd bs=18 count=1 if=/dev/urandom | base64 | tr +/ _.)}
VERSION=`date -u +%Y%m%d`
LDFLAGS="-X main.VERSION=$VERSION -s -w -X main.SALT=${SALT}"
GCFLAGS=""

# AMD64
OSES=(linux)
for os in ${OSES[@]}; do
  suffix=""
  if [[ "$os" == "windows" ]]; then
    suffix=".exe"
  fi
  env CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build -pgo=auto -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o client_${os}_amd64${suffix} github.com/xtaci/kcptun/client
  env CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build -pgo=auto -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o server_${os}_amd64${suffix} github.com/xtaci/kcptun/server
done

# ARM64
OSES=(linux darwin)
for os in ${OSES[@]}; do
  env CGO_ENABLED=0 GOOS=$os GOARCH=arm64 go build -pgo=auto -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o client_${os}_arm64${suffix} github.com/xtaci/kcptun/client
  env CGO_ENABLED=0 GOOS=$os GOARCH=arm64 go build -pgo=auto -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o server_${os}_arm64${suffix} github.com/xtaci/kcptun/server
done