package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// buildRequest prepares the request with authentication headers and optional payload
func (s *SDK) buildRequest(ctx context.Context, method, url string, payload any) (req *http.Request, err error) {
	if s.Username == "" || s.Password == "" {
		err = fmt.Errorf("missing username and/or password")
		return
	}

	req, err = http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		err = fmt.Errorf("error creating request: %v", err)
		return
	}

	if payload != nil {
		buf := new(bytes.Buffer)
		if err = json.NewEncoder(buf).Encode(payload); err != nil {
			err = fmt.Errorf("Error encoding JSON: %v", err)
			return
		}
		req.Body = io.NopCloser(buf)
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("X-Domainrobot-Context", s.getAutoDNSContext())
	req.Header.Set("User-Agent", "libdns-autodns/x.y (+https://github.com/libdns/autodns)")
	req.SetBasicAuth(s.Username, s.Password)
	return
}

// buildURL prepends the endpoint to the requested API URL.
func (s *SDK) buildURL(path string) string {
	if s.Endpoint == "" {
		return autoDNSendpoint + "/" + path
	}

	return s.Endpoint + "/" + path
}

// getAutoDNSContext returns the provider / API context of the account.
func (s *SDK) getAutoDNSContext() string {
	if s.Context == "" {
		return autoDNScontext
	}

	return s.Context
}

// makeRequest executes the request.
func (s *SDK) makeRequest(req *http.Request) (*http.Response, error) {
	var client *http.Client
	if s.HttpClient == nil {
		client = &http.Client{}
	} else {
		client = s.HttpClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %s", err)
	}
	return resp, nil
}

// parseResponse parses the response into the struct.
func (s *SDK) parseResponse(resp *http.Response, into any) error {
	return json.NewDecoder(resp.Body).Decode(&into)
}

func check(statusResponse, statusExpected int, result any) error {
	if statusResponse == statusExpected {
		return nil
	}

	switch rt := result.(type) {
	case AutoDNSResponse:
		if rt.Status.Type != "ERROR" {
			return nil
		}
		return NewError(rt.Messages)
	case ResponseZone:
		if rt.Status.Type != "ERROR" {
			return nil
		}
		return NewError(rt.Messages)
	}

	return fmt.Errorf("unknown response type, but there is an error")
}
