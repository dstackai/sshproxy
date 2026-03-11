package dstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dstackai/sshproxy/internal/log"
	"github.com/dstackai/sshproxy/internal/sshproxy"
)

const getUpstreamURL = "/api/sshproxy/get_upstream"

const errCodeNotExists = "resource_not_exists"

type GetUpstreamRequest struct {
	ID string `json:"id"`
}

type GetUpstreamResponse struct {
	Hosts          []UpstreamHost `json:"hosts"`
	AuthorizedKeys []string       `json:"authorized_keys"`
}

type UpstreamHost struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	PrivateKey string `json:"private_key"`
}

type ErrorResponse struct {
	Detail []ErrorDetail `json:"detail"`
}

type ErrorDetail struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

type APIError struct {
	statusCode int
	body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error: %d: %s", e.statusCode, e.body)
}

type Client struct {
	url        *url.URL
	authHeader string
	client     *http.Client
}

func NewClient(baseURL string, authToken string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}

	rel := &url.URL{Path: getUpstreamURL}
	u = u.ResolveReference(rel)

	return &Client{
		url:        u,
		authHeader: "bearer " + authToken,
		client: &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   timeout,
		},
	}, nil
}

// GetUpstream implements sshproxy.GetUpstreamCallback
func (c *Client) GetUpstream(ctx context.Context, id string) (sshproxy.Upstream, error) {
	logger := log.GetLogger(ctx)

	var zeroUpstream sshproxy.Upstream

	reqBody := GetUpstreamRequest{
		ID: id,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return zeroUpstream, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url.String(), bytes.NewReader(body))
	if err != nil {
		return zeroUpstream, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.authHeader)

	resp, err := c.client.Do(req)
	if err != nil {
		return zeroUpstream, fmt.Errorf("request server: %w", err)
	}

	defer func() {
		// Ensure the connection is returned to the connection pool
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)

		var respBody ErrorResponse

		err := json.Unmarshal(respBytes, &respBody)
		if err != nil {
			logger.WithError(err).Debug("failed to decode error response")
		} else {
			for _, detail := range respBody.Detail {
				if detail.Code == errCodeNotExists {
					return zeroUpstream, sshproxy.ErrUpstreamNotFound
				}
			}
		}

		return zeroUpstream, &APIError{
			statusCode: resp.StatusCode,
			body:       string(respBytes),
		}
	}

	var respBody GetUpstreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return zeroUpstream, fmt.Errorf("decode response: %w", err)
	}

	hosts := make([]sshproxy.Host, 0, len(respBody.Hosts))
	for i, host := range respBody.Hosts {
		address := net.JoinHostPort(host.Host, strconv.Itoa(host.Port))
		privateKey, err := ssh.ParsePrivateKey([]byte(host.PrivateKey))
		if err != nil {
			return zeroUpstream, fmt.Errorf("parse private key: %d: %w", i, err)
		}
		hosts = append(hosts, sshproxy.NewHost(address, host.User, privateKey))
	}

	authorizedKeys := make([]ssh.PublicKey, 0, len(respBody.AuthorizedKeys))
	for i, authKey := range respBody.AuthorizedKeys {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKey))
		if err != nil {
			return zeroUpstream, fmt.Errorf("parse authorized key: %d: %w", i, err)
		}
		authorizedKeys = append(authorizedKeys, publicKey)
	}

	return sshproxy.NewUpstream(hosts, authorizedKeys), nil
}
