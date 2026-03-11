#!/bin/sh
set -eu

if ! command -v ssh-keygen > /dev/null 2>&1; then
    echo 'ssh-keygen not found'>&2
    exit 1
fi

temp_dir=$(mktemp -d)
trap 'rm -r "${temp_dir}"; trap - EXIT; exit' EXIT INT TERM HUP

keys_dir=${temp_dir}/etc/ssh
mkdir -p "${keys_dir}"
ssh-keygen -A -f "${temp_dir}" > /dev/null
cat "${keys_dir}"/ssh_host_*_key
