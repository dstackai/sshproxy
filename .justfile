bin_name := 'dstack-sshproxy'
build_dir := 'build'

[default]
@_list:
  just --list --unsorted

@build version='dev':
  scripts/build.sh {{build_dir}}/{{bin_name}} {{version}}

@run *args: build
  {{build_dir}}/{{bin_name}} {{args}}

@lint:
  pre-commit run --files cmd/main.go
