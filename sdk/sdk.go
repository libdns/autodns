package sdk

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type SDK struct {
	Username   string
	Password   string
	Endpoint   string
	Context    string
	HttpClient *http.Client
}

// CheckZone verifies that the zone exists and returns the data required
// (origin and nameserver) to fetch the full zone via GetZone.
func (s *SDK) CheckZone(ctx context.Context, zone string) (*ZoneItem, error) {
	zone = strings.TrimSuffix(zone, ".")

	filter := map[string]string{
		"key":      "name",
		"operator": "EQUAL",
		"value":    zone,
	}

	payload := map[string][]map[string]string{}
	payload["filters"] = make([]map[string]string, 0)
	payload["filters"] = append(payload["filters"], filter)

	req, err := s.buildRequest(ctx, http.MethodPost, s.buildURL("zone/_search"), payload)
	if err != nil {
		return nil, err
	}

	resp, err := s.makeRequest(req)
	if err != nil {
		return nil, err
	}

	var result ResponseZone
	if err := s.parseResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("checkZone: %s", err)
	}

	if err := check(resp.StatusCode, 200, result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("checkZone: %q not found", zone)
	}

	return &result.Data[0], nil
}

// GetZone returns the zone.
func (s *SDK) GetZone(ctx context.Context, origin, nameserver, zone string) (*ResponseZone, error) {
	req, err := s.buildRequest(ctx, http.MethodGet, s.buildURL("zone/"+origin+"/"+nameserver), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.makeRequest(req)
	if err != nil {
		return nil, err
	}

	var result ResponseZone
	if err := s.parseResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("getZone: %s", err)
	}

	if err := check(resp.StatusCode, 200, result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("getZone: could not find %q", zone)
	}

	if len(result.Data) != 1 {
		return nil, fmt.Errorf("getZone: ambigous result for %q", zone)
	}

	return &result, nil
}

// UpdateZone updates the zone.
func (s *SDK) UpdateZone(ctx context.Context, origin, nameserver string, zone ZoneItem) error {
	req, err := s.buildRequest(ctx, http.MethodPut, s.buildURL("zone/"+origin+"/"+nameserver), zone)
	if err != nil {
		return err
	}

	resp, err := s.makeRequest(req)
	if err != nil {
		return err
	}

	var result AutoDNSResponse
	if err := s.parseResponse(resp, &result); err != nil {
		return fmt.Errorf("updateZone: %s", err)
	}

	if err := check(resp.StatusCode, 200, result); err != nil {
		return err
	}
	return nil
}

// PatchZone applies a changeset to a zone. Unlike UpdateZone, which
// sends the full zone, PatchZone sends only the records to add and
// remove. The returned ResponseZone carries the zone in its updated
// form.
func (s *SDK) PatchZone(ctx context.Context, origin, nameserver string, patch ZonePatch) (*ResponseZone, error) {
	req, err := s.buildRequest(ctx, http.MethodPatch, s.buildURL("zone/"+origin+"/"+nameserver), patch)
	if err != nil {
		return nil, err
	}

	resp, err := s.makeRequest(req)
	if err != nil {
		return nil, err
	}

	var result ResponseZone
	if err := s.parseResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("patchZone: %s", err)
	}

	if err := check(resp.StatusCode, 200, result); err != nil {
		return nil, err
	}

	return &result, nil
}
