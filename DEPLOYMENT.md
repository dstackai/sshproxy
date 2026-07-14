# Deployment guide

## Requirements

* `dstack` [0.20.14][dstack-0.20.14] ([0.20.16][dstack-0.20.16] for user-managed SSH public keys support) or newer
* A host with access to the `dstack` server and fleets instances (HTTP and SSH egress traffic, respectively), which is accessible to `dstack` users (ingress SSH traffic)

## Build

There are pre-built `x86-64` Linux binaries on the GitHub [Releases][sshproxy-releases] page and Docker images on the [Docker Hub][sshproxy-docker-hub].

If you prefer to build from source, see [`scripts/build.sh`][build-script] for a build command.

## Configuration

`dstack-sshproxy` is configured via command-line arguments and/or environment variables. Command-line arguments have higher priority than environment variables.
See `dstack-proxy --help` for a list of configuration settings and corresponding variables.

There are two mandatory settings:

* **Host private keys**

  Used for SSH server host authentication as described in [RFC 4251 Section 4.1][rfc-server-host-auth].

  * CLI: `--host-key PATH` – a path to a private key file. May be used multiple times. Each file may contain multiple concatenated keys: `cat ssh_host_*_key > ssh_host_keys`
  * environment variable: `DSTACK_SSHPROXY_HOST_KEYS` – concatenated key files contents

  Keys must be in the OpenSSH format. For convenience, there is [`scripts/generate-host-keys.sh`][generate-host-keys-script] script which generates host keys of all default key types (rsa, ecdsa, and ed25519) using `ssh-keygen -A` and prints their contents to stdout.


* **`dstack` server API token**

  Used to authenticate `dstack-sshproxy` API calls to `dstack` server

  * CLI: `--api-token TOKEN`
  * environment variable: `DSTACK_SSHPROXY_API_TOKEN`

  The `dstack` server URL is configured via `--api-url`/`DSTACK_SSHPROXY_API_URL` (defaults to `http://localhost:3000`, the default address of a locally running server if it's started with the `dstack server` command).

To enable `dstack-sshproxy` integration on the `dstack` server side, see [Server deployment][dstack-docs-server-deployment-ssh-proxy] guide in the `dstack` docs.

## Upgrade

Before upgrading, check both [`dstack`][dstack-releases] and [`dstack-sshproxy`][sshproxy-releases] releases pages for any `dstack`↔`dstack-sshproxy` compatibility notes.

`dstack-sshproxy` – given there are no breaking changes in the `dstack` server integration – supports rolling upgrade. Be aware that `dstack-sshproxy` does not currently support graceful connection termination, that is, on a shutdown request (`SIGTERM`/`SIGINIT` signal) it closes all downstream and upstream TCP connections immediately, **interrupting active SSH sessions**, but it's still possible to implement a graceful shutdown with an external load balancer (i.e., the deployment strategy would be to stop forwarding new connections to the old replica, drain it – wait for active connections to terminate, interrupt still active connections after a reasonable timeout, and only then stop the replica).

## Host key rotation

Since version [0.0.3][dstack-sshproxy-0.0.3], `dstack-sshproxy` supports the [Host key update mechanism][draft-ietf-sshm-hostkey-update] protocol extension, which can be used to gracefully rotate host keys. This is a two-phase process:

1. Start advertising the new keys while keeping the old ones for key exchange. The new keys must be placed after the currently used keys – only the first key of each type (Ed25519, ECDSA, RSA) is used for key exchange. If the keys are configured via the `DSTACK_SSHPROXY_HOST_KEYS` variable, add the new keys to the end of the variable's value; if the keys are configured via the `--host-key` CLI argument, it's also possible to store the old keys and the new keys in separate files: `dstack-sshproxy --host-key host_key --host-key host_key_new` – the order does matter.
2. Once all clients have connected at least once to learn the new keys, remove the old ones.

[dstack-0.20.14]: https://github.com/dstackai/dstack/releases/tag/0.20.14
[dstack-0.20.16]: https://github.com/dstackai/dstack/releases/tag/0.20.16
[dstack-sshproxy-0.0.3]: https://github.com/dstackai/sshproxy/releases/tag/0.0.3
[dstack-releases]: https://github.com/dstackai/dstack/releases
[dstack-docs-server-deployment-ssh-proxy]: https://dstack.ai/docs/guides/server-deployment/#ssh-proxy
[sshproxy-releases]: https://github.com/dstackai/sshproxy/releases
[sshproxy-docker-hub]: https://hub.docker.com/r/dstackai/sshproxy/tags
[build-script]: https://github.com/dstackai/sshproxy/blob/main/scripts/build.sh
[generate-host-keys-script]: https://github.com/dstackai/sshproxy/blob/main/scripts/generate-host-keys.sh
[rfc-server-host-auth]: https://datatracker.ietf.org/doc/html/rfc4251#section-4.1
[draft-ietf-sshm-hostkey-update]: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-hostkey-update/
