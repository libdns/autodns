package autodns_test

import (
	"net/netip"
	"time"

	"github.com/libdns/autodns"
	"github.com/libdns/libdns"
)

// Test fixtures for AutoDNS provider testing

// Mock AutoDNS API responses
var mockZoneResponse = autodns.ResponseZone{
	AutoDNSResponse: autodns.AutoDNSResponse{
		STID: "test-stid-12345",
		Status: struct {
			Type string  `json:"type"`
			Code *string `json:"resultCode,omitempty"`
			Text *string `json:"text,omitempty"`
		}{
			Type: "SUCCESS",
			Code: stringPtr("S0301"),
			Text: stringPtr("Operation successful"),
		},
	},
	Data: []autodns.ZoneItem{
		{
			Created: "2023-10-18T13:56:47.000+0200",
			Updated: "2024-10-25T13:16:43.000+0200",
			Origin:  "example.org",
			SOA: struct {
				Refresh int    `json:"refresh"`
				Retry   int    `json:"retry"`
				Expire  int    `json:"expire"`
				TTL     int    `json:"ttl"`
				Email   string `json:"email"`
			}{
				Refresh: 43200,
				Retry:   7200,
				Expire:  1209600,
				TTL:     86400,
				Email:   "admin@example.org",
			},
			NSGroup:     "ns14.net",
			DomainSafe:  false,
			PurgeType:   "DISABLED",
			WWWWInclude: false,
			Nameserver:  "a.ns14.net",
			Action:      "COMPLETE",
			Records:     mockZoneRecords,
			ROID:        9149383,
		},
	},
}

// Mock zone records covering all supported record types
var mockZoneRecords = []autodns.ZoneRecord{
	{Name: "@", Type: "A", Value: "192.168.1.1", TTL: 3600},
	{Name: "www", Type: "A", Value: "192.168.1.2", TTL: 3600},
	{Name: "ipv6", Type: "AAAA", Value: "2001:db8::1", TTL: 3600},
	{Name: "mail", Type: "CNAME", Value: "mailserver.example.org", TTL: 3600},
	{Name: "@", Type: "MX", Value: "10 mail.example.org", TTL: 3600},
	{Name: "@", Type: "MX", Value: "20 backup.example.org", TTL: 3600},
	{Name: "@", Type: "NS", Value: "ns1.example.org", TTL: 86400},
	{Name: "@", Type: "NS", Value: "ns2.example.org", TTL: 86400},
	{Name: "_sip._tcp", Type: "SRV", Value: "10 5 5060 sipserver.example.org", TTL: 3600},
	{Name: "@", Type: "TXT", Value: "v=spf1 include:_spf.example.org ~all", TTL: 3600},
	{Name: "test", Type: "TXT", Value: "test-verification-string", TTL: 300},
	{Name: "custom", Type: "CAA", Value: "0 issue \"letsencrypt.org\"", TTL: 86400},
}

// Mock search response for zone lookup
var mockSearchResponse = autodns.ResponseSearch{
	AutoDNSResponse: autodns.AutoDNSResponse{
		STID: "test-search-stid-67890",
		Status: struct {
			Type string  `json:"type"`
			Code *string `json:"resultCode,omitempty"`
			Text *string `json:"text,omitempty"`
		}{
			Type: "SUCCESS",
			Code: stringPtr("S0301"),
			Text: stringPtr("Search successful"),
		},
	},
	Data: []autodns.ResponseSearchItem{
		{
			Created:     "2023-10-18T13:56:47.000+0200",
			Updated:     "2024-10-25T13:16:43.000+0200",
			Origin:      "example.org",
			NSGroup:     "ns14.net",
			DomainSafe:  false,
			WWWWInclude: false,
			Nameserver:  "a.ns14.net",
		},
	},
}

// Test fixtures for libdns.Record types
var testRecords = []libdns.Record{
	&libdns.Address{
		Name: "test-a",
		IP:   netip.MustParseAddr("203.0.113.1"),
		TTL:  3600 * time.Second,
	},
	&libdns.Address{
		Name: "test-aaaa",
		IP:   netip.MustParseAddr("2001:db8::2"),
		TTL:  3600 * time.Second,
	},
	&libdns.CNAME{
		Name:   "test-cname",
		Target: "target.example.org",
		TTL:    3600 * time.Second,
	},
	&libdns.TXT{
		Name: "test-txt",
		Text: "test-txt-value",
		TTL:  3600 * time.Second,
	},
	&libdns.MX{
		Name:       "test-mx",
		Preference: 10,
		Target:     "mx.example.org",
		TTL:        3600 * time.Second,
	},
	&libdns.NS{
		Name:   "test-ns",
		Target: "ns.example.org",
		TTL:    3600 * time.Second,
	},
	&libdns.SRV{
		Name:     "_test._tcp",
		Priority: 10,
		Weight:   5,
		Port:     443,
		Target:   "srv.example.org",
		TTL:      3600 * time.Second,
	},
	&libdns.RR{
		Name: "test-rr",
		Type: "CAA",
		Data: "0 issue \"example.org\"",
		TTL:  300 * time.Second,
	},
}

// Expected AutoDNS ZoneRecord representations
var expectedZoneRecords = []autodns.ZoneRecord{
	{Name: "test-a", Type: "A", Value: "203.0.113.1", TTL: 3600},
	{Name: "test-aaaa", Type: "AAAA", Value: "2001:db8::2", TTL: 3600},
	{Name: "test-cname", Type: "CNAME", Value: "target.example.org", TTL: 3600},
	{Name: "test-txt", Type: "TXT", Value: "test-txt-value", TTL: 3600},
	{Name: "test-mx", Type: "MX", Value: "10 mx.example.org", TTL: 3600},
	{Name: "test-ns", Type: "NS", Value: "ns.example.org", TTL: 3600},
	{Name: "_test._tcp", Type: "SRV", Value: "10 5 443 srv.example.org", TTL: 3600},
	{Name: "test-rr", Type: "CAA", Value: "0 issue \"example.org\"", TTL: 300},
}

// Test cases for record conversion errors
var invalidZoneRecords = []struct {
	name   string
	record autodns.ZoneRecord
	error  string
}{
	{
		name:   "invalid A record",
		record: autodns.ZoneRecord{Name: "test", Type: "A", Value: "invalid-ip"},
		error:  "invalid A record value: invalid-ip",
	},
	{
		name:   "invalid AAAA record",
		record: autodns.ZoneRecord{Name: "test", Type: "AAAA", Value: "invalid-ipv6"},
		error:  "invalid AAAA record value: invalid-ipv6",
	},
	{
		name:   "invalid MX record format",
		record: autodns.ZoneRecord{Name: "test", Type: "MX", Value: "invalid"},
		error:  "invalid MX record format: invalid",
	},
	{
		name:   "invalid MX preference",
		record: autodns.ZoneRecord{Name: "test", Type: "MX", Value: "abc mx.example.org"},
		error:  "invalid MX preference: abc",
	},
	{
		name:   "invalid SRV record format",
		record: autodns.ZoneRecord{Name: "test", Type: "SRV", Value: "10 5 target"},
		error:  "invalid SRV record format: 10 5 target",
	},
	{
		name:   "invalid SRV priority",
		record: autodns.ZoneRecord{Name: "test", Type: "SRV", Value: "abc 5 443 target"},
		error:  "invalid SRV priority: abc",
	},
	{
		name:   "invalid SRV weight",
		record: autodns.ZoneRecord{Name: "test", Type: "SRV", Value: "10 abc 443 target"},
		error:  "invalid SRV weight: abc",
	},
	{
		name:   "invalid SRV port",
		record: autodns.ZoneRecord{Name: "test", Type: "SRV", Value: "10 5 abc target"},
		error:  "invalid SRV port: abc",
	},
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}
