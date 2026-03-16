#!/bin/sh
set -eu

VERSION_PATH='github.com/dstackai/sshproxy/internal/sshproxy.Version'

if [ ${#} -ne 2 ]; then
    echo "usage: $(basename -- "${0}") OUTPUT VERSION" >&2
    exit 1
fi

output=$(pwd)/${1}; shift
version=${1}; shift
root_dir=$(cd "$(dirname -- "${0}")"/..; pwd)

export CGO_ENABLED=0

go build \
    -C "${root_dir}" \
    -ldflags "-X '${VERSION_PATH}=${version}' -s -w -extldflags '-static'" \
    -o "${output}" \
    ./cmd

if ! "${output}" --version 2>&1 | grep "version ${version}\$" >/dev/null; then
    echo 'failed to check version'
    exit 2
fi
