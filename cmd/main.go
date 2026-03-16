package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dstackai/sshproxy/internal/dstack"
	"github.com/dstackai/sshproxy/internal/log"
	"github.com/dstackai/sshproxy/internal/sshproxy"
)

const (
	appName        = "dstack-sshproxy"
	hostKeysEnvVar = "DSTACK_SSHPROXY_HOST_KEYS"
	apiTokenEnvVar = "DSTACK_SSHPROXY_API_TOKEN"
)

const usageText = `
1.  Provide private host keys via --host-key (a key file path, may be specified multiple times)
    or $` + hostKeysEnvVar + ` (concatenated key files contents).
    At least one key must be provided.
2.  Provide dstack server API token via --api-token or $` + apiTokenEnvVar + `.`

var errNoHostKeys = errors.New("no host keys provided")

func main() {
	os.Exit(mainInner())
}

func mainInner() int {
	ctx := context.Background()
	logger := log.GetLogger(ctx)

	var (
		address       string
		port          int
		hostKeysPaths []string
		apiURL        string
		apiToken      string
		apiTimeout    int
		logLevel      string
	)

	cmd := &cli.Command{
		Name:            appName,
		Version:         sshproxy.Version,
		Usage:           "SSH proxy for dstack jobs",
		UsageText:       usageText,
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "address",
				Usage:       "address for incoming SSH connections",
				Value:       "",
				DefaultText: "all interfaces",
				Sources:     cli.EnvVars("DSTACK_SSHPROXY_ADDRESS"),
				OnlyOnce:    true,
				Destination: &address,
			},
			&cli.IntFlag{
				Name:        "port",
				Usage:       "port for incoming SSH connections",
				Value:       30022,
				Sources:     cli.EnvVars("DSTACK_SSHPROXY_PORT"),
				OnlyOnce:    true,
				Destination: &port,
			},
			&cli.StringSliceFlag{
				Name:        "host-key",
				Usage:       "private host key path",
				TakesFile:   true,
				Destination: &hostKeysPaths,
			},
			&cli.StringFlag{
				Name:        "api-url",
				Usage:       "dstack server API URL",
				Value:       "http://localhost:3000",
				Sources:     cli.EnvVars("DSTACK_SSHPROXY_API_URL"),
				OnlyOnce:    true,
				Destination: &apiURL,
			},
			&cli.StringFlag{
				Name:        "api-token",
				Usage:       "dstack server API token",
				Required:    true,
				Sources:     cli.EnvVars(apiTokenEnvVar),
				OnlyOnce:    true,
				Destination: &apiToken,
			},
			&cli.IntFlag{
				Name:        "api-timeout",
				Usage:       "timeout of requests to dstack API, seconds",
				Value:       10,
				Sources:     cli.EnvVars("DSTACK_SSHPROXY_API_TIMEOUT"),
				OnlyOnce:    true,
				Destination: &apiTimeout,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Usage:       "logging level",
				Value:       "info",
				Sources:     cli.EnvVars("DSTACK_SSHPROXY_LOG_LEVEL"),
				OnlyOnce:    true,
				Destination: &logLevel,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if err := log.SetLogLevel(logLevel); err != nil {
				return err
			}

			logger = log.GetLogger(ctx)
			logger.WithField("version", sshproxy.Version).Debug("starting " + appName)

			dstackClient, err := dstack.NewClient(apiURL, apiToken, time.Duration(apiTimeout)*time.Second)
			if err != nil {
				return err
			}

			hostKeys, err := loadHostKeys(ctx, hostKeysPaths)
			if err != nil {
				return err
			}

			return serve(ctx, address, port, hostKeys, dstackClient.GetUpstream)
		},
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	err := cmd.Run(ctx, os.Args)
	if err != nil {
		logger.Error(err)

		return 1
	}

	return 0
}

func loadHostKeys(ctx context.Context, hostKeysPaths []string) ([]sshproxy.HostKey, error) {
	logger := log.GetLogger(ctx)
	envVarBlob, envVarIsSet := os.LookupEnv(hostKeysEnvVar)

	if len(hostKeysPaths) > 0 {
		if envVarIsSet {
			logger.Debugf("%s is set, ignoring", hostKeysEnvVar)
		}

		var hostKeys []sshproxy.HostKey

		for _, path := range hostKeysPaths {
			logger.WithField("path", path).Debug("loading host keys from file")

			keys, err := sshproxy.LoadHostKeysFromFile(path)
			if err != nil {
				return nil, fmt.Errorf("load host keys from %s: %w", path, err)
			}

			hostKeys = append(hostKeys, keys...)
		}

		return hostKeys, nil
	}

	if envVarIsSet {
		logger.Debug("loading host keys from env")

		hostKeys, err := sshproxy.LoadHostKeysFromBlob([]byte(envVarBlob))
		if err != nil {
			return nil, fmt.Errorf("load host keys from env: %w", err)
		}

		return hostKeys, nil
	}

	return nil, errNoHostKeys
}

func serve(
	ctx context.Context, address string, port int,
	hostKeys []sshproxy.HostKey, getUpstream sshproxy.GetUpstreamCallback,
) error {
	server := sshproxy.NewServer(ctx, address, port, hostKeys, getUpstream)

	var serveErr error

	serveErrCh := make(chan error)

	go func() {
		err := server.ListenAndServe(ctx)
		if err != nil {
			serveErrCh <- err
		}

		close(serveErrCh)
	}()

	select {
	case serveErr = <-serveErrCh:
	case <-ctx.Done():
	}

	shutdownErr := server.Close(ctx)

	if serveErr != nil {
		return serveErr
	}

	return shutdownErr
}
