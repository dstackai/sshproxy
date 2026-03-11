# dstack-sshproxy

## Usage

1. Provide private host keys via `--host-key` (a key file path, may be specified multiple times)
or `$DSTACK_SSHPROXY_HOST_KEYS` (concatenated key files contents). At least one key must be provided.
2. Provide dstack server API token via `--api-token` or `$DSTACK_SSHPROXY_API_TOKEN`.

## Options

```
--address string                         address for incoming SSH connections (default: all interfaces) [$DSTACK_SSHPROXY_ADDRESS]
--port int                               port for incoming SSH connections (default: 30022) [$DSTACK_SSHPROXY_PORT]
--host-key string [ --host-key string ]  private host key path
--api-url string                         dstack server API URL (default: "http://localhost:3000") [$DSTACK_SSHPROXY_API_URL]
--api-token string                       dstack server API token [$DSTACK_SSHPROXY_API_TOKEN]
--api-timeout int                        timeout of requests to dstack API, seconds (default: 10) [$DSTACK_SSHPROXY_API_TIMEOUT]
--log-level string                       logging level (default: "info") [$DSTACK_SSHPROXY_LOG_LEVEL]
```

## Build and run locally

```shell
scripts/generate-host-keys.sh > .host_keys
just run --host-key .host-key --api-token <token> ...
```
