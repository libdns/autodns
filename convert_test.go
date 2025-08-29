package autodns_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/autodns"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
)

func TestConversion(t *testing.T) {
	t.Run("ToLibDNS", func(t *testing.T) {
		// Use the mock zone records from fixtures
		tests := []struct {
			name     string
			input    autodns.ZoneRecord
			expected libdns.Record
		}{
			{
				name:  "A record",
				input: mockZoneRecords[0], // "@", "A", "192.168.1.1"
				expected: &libdns.Address{
					Name: "@",
					IP:   netip.MustParseAddr("192.168.1.1"),
					TTL:  3600 * time.Second,
				},
			},
			{
				name:  "AAAA record",
				input: mockZoneRecords[2], // "ipv6", "AAAA", "2001:db8::1"
				expected: &libdns.Address{
					Name: "ipv6",
					IP:   netip.MustParseAddr("2001:db8::1"),
					TTL:  3600 * time.Second,
				},
			},
			{
				name:  "CNAME record",
				input: mockZoneRecords[3], // "mail", "CNAME", "mailserver.example.org"
				expected: &libdns.CNAME{
					Name:   "mail",
					Target: "mailserver.example.org",
					TTL:    3600 * time.Second,
				},
			},
			{
				name:  "MX record",
				input: mockZoneRecords[4], // "@", "MX", "10 mail.example.org"
				expected: &libdns.MX{
					Name:       "@",
					Preference: 10,
					Target:     "mail.example.org",
					TTL:        3600 * time.Second,
				},
			},
			{
				name:  "NS record",
				input: mockZoneRecords[6], // "@", "NS", "ns1.example.org"
				expected: &libdns.NS{
					Name:   "@",
					Target: "ns1.example.org",
					TTL:    86400 * time.Second,
				},
			},
			{
				name:  "SRV record",
				input: mockZoneRecords[8], // "_sip._tcp", "SRV", "10 5 5060 sipserver.example.org"
				expected: &libdns.SRV{
					Name:     "_sip._tcp",
					Priority: 10,
					Weight:   5,
					Port:     5060,
					Target:   "sipserver.example.org",
					TTL:      3600 * time.Second,
				},
			},
			{
				name:  "TXT record",
				input: mockZoneRecords[9], // "@", "TXT", "v=spf1 include:_spf.example.org ~all"
				expected: &libdns.TXT{
					Name: "@",
					Text: "v=spf1 include:_spf.example.org ~all",
					TTL:  3600 * time.Second,
				},
			},
			{
				name:  "Generic RR record (CAA)",
				input: mockZoneRecords[11], // "custom", "CAA", "0 issue \"letsencrypt.org\""
				expected: &libdns.RR{
					Name: "custom",
					Type: "CAA",
					Data: "0 issue \"letsencrypt.org\"",
					TTL:  86400 * time.Second,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := autodns.ToLibDNS(tt.input)
				assert.NoError(t, err)
				assertRecordIsEqual(t, result, tt.expected)
			})
		}
	})

	t.Run("ToLibDNS_Errors", func(t *testing.T) {
		for _, tt := range invalidZoneRecords {
			t.Run(tt.name, func(t *testing.T) {
				_, err := autodns.ToLibDNS(tt.record)
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.error)
			})
		}
	})

	t.Run("ToAutoDNS", func(t *testing.T) {
		// Use testRecords and expectedZoneRecords from fixtures
		for i, record := range testRecords {
			expectedRecord := expectedZoneRecords[i]

			t.Run(expectedRecord.Type+" record", func(t *testing.T) {
				result, err := autodns.ToAutoDNS(record)
				assert.NoError(t, err)
				assert.Equal(t, expectedRecord, result)
			})
		}
	})

	t.Run("Roundtrip", func(t *testing.T) {
		// Test that conversion works both ways
		for _, record := range testRecords {
			t.Run(record.RR().Type, func(t *testing.T) {
				// Convert libdns -> AutoDNS
				zoneRecord, err := autodns.ToAutoDNS(record)
				assert.NoError(t, err)

				// Convert back AutoDNS -> libdns
				libdnsRecord, err := autodns.ToLibDNS(zoneRecord)
				assert.NoError(t, err)

				// Compare original with round-trip result
				assertRecordIsEqual(t, record, libdnsRecord)
			})
		}
	})
}

// Helper assertion function
func assertRecordIsEqual(t *testing.T, a, b libdns.Record) {
	t.Helper()
	switch ra := a.(type) {
	case *libdns.Address:
		assert.IsType(t, ra, b.(*libdns.Address))
		assert.Equal(t, a, b)
	case *libdns.CNAME:
		assert.IsType(t, ra, b.(*libdns.CNAME))
		assert.Equal(t, a, b)
	case *libdns.TXT:
		assert.IsType(t, ra, b.(*libdns.TXT))
		assert.Equal(t, a, b)
	case *libdns.MX:
		assert.IsType(t, ra, b.(*libdns.MX))
		assert.Equal(t, a, b)
	case *libdns.NS:
		assert.IsType(t, ra, b.(*libdns.NS))
		assert.Equal(t, a, b)
	case *libdns.SRV:
		assert.IsType(t, ra, b.(*libdns.SRV))
		assert.Equal(t, a, b)
	case *libdns.RR:
		assert.IsType(t, ra, b.(*libdns.RR))
		assert.Equal(t, a, b)
	default:
		t.Logf("Unsupported RR: %#v", a)
		t.Fail()
	}
}
