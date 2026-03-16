package dstack

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

type TextErrorResponse struct {
	Detail string `json:"detail"`
}

type ErrorDetail struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}
