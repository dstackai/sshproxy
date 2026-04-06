# dstack-sshproxy

`dstack-sshproxy` is an optional component of the [`dstack`][dstack-site] infrastructure that provides direct SSH access to workloads. It acts as a reverse SSH proxy that sits between `dstack` users (SSH clients, IDEs, etc.) and upstream SSH servers running inside `dstack` workloads.

## Deployment

See [DEPLOYMENT.md]

## Local development

```shell
scripts/generate-host-keys.sh > .host_keys
just run --host-key .host-keys --api-token <token> ...
```

[dstack-site]: https://dstack.ai/
[DEPLOYMENT.md]: https://github.com/dstackai/sshproxy/blob/main/DEPLOYMENT.md
