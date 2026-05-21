package autodns_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/libdns/autodns"
	"github.com/libdns/autodns/sdk"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWWWInclude(t *testing.T) {
	content, err := os.ReadFile("./fixtures/mainWWW.json")
	require.NoError(t, err)

	var item sdk.ZoneItem
	require.NoError(t, json.NewDecoder(bytes.NewBuffer(content)).Decode(&item))

	assert.True(t, autodns.HasWWWInclude(item))
}

func TestMatchesZoneRecord(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		target sdk.ZoneRecord
		zr     sdk.ZoneRecord
		want   bool
	}{
		{
			desc:   "exact match",
			target: sdk.ZoneRecord{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 3600},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A", Value: "1.2.3.4", TTL: 3600},
			want:   true,
		},
		{
			desc:   "name mismatch",
			target: sdk.ZoneRecord{Name: "www", Type: "A"},
			zr:     sdk.ZoneRecord{Name: "api", Type: "A"},
			want:   false,
		},
		{
			desc:   "type mismatch when target.Type set",
			target: sdk.ZoneRecord{Name: "www", Type: "A"},
			zr:     sdk.ZoneRecord{Name: "www", Type: "AAAA"},
			want:   false,
		},
		{
			desc:   "type wildcard",
			target: sdk.ZoneRecord{Name: "www"},
			zr:     sdk.ZoneRecord{Name: "www", Type: "TXT", Value: "hello"},
			want:   true,
		},
		{
			desc:   "value mismatch when target.Value set",
			target: sdk.ZoneRecord{Name: "www", Type: "A", Value: "1.2.3.4"},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A", Value: "5.6.7.8"},
			want:   false,
		},
		{
			desc:   "value wildcard",
			target: sdk.ZoneRecord{Name: "www", Type: "A"},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A", Value: "1.2.3.4"},
			want:   true,
		},
		{
			desc:   "ttl mismatch when target.TTL set",
			target: sdk.ZoneRecord{Name: "www", Type: "A", TTL: 3600},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A", TTL: 60},
			want:   false,
		},
		{
			desc:   "ttl wildcard",
			target: sdk.ZoneRecord{Name: "www", Type: "A"},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A", TTL: 3600},
			want:   true,
		},
		{
			desc:   "name-only target matches any type at that name",
			target: sdk.ZoneRecord{Name: ""},
			zr:     sdk.ZoneRecord{Name: "", Type: "MX", Value: "mx.example.org", TTL: 300},
			want:   true,
		},
		{
			desc:   "empty target name does not match named record",
			target: sdk.ZoneRecord{Name: ""},
			zr:     sdk.ZoneRecord{Name: "www", Type: "A"},
			want:   false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.want, autodns.MatchesZoneRecord(tc.target, tc.zr))
		})
	}
}

func TestHasRecord(t *testing.T) {
	content, err := os.ReadFile("./fixtures/mainWWW.json")
	require.NoError(t, err)

	var item sdk.ZoneItem
	require.NoError(t, json.NewDecoder(bytes.NewBuffer(content)).Decode(&item))

	// convert
	var records []libdns.Record
	for _, r := range item.Records {
		rr, err := autodns.ToLibDNS(r)
		assert.NoError(t, err)

		records = append(records, rr)
	}

	for _, tc := range []struct {
		desc   string
		record string
		result bool
	}{
		{
			desc:   "has no www",
			record: "www",
			result: false,
		},
		{
			desc:   "has no A for root",
			record: "",
			result: false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.result, autodns.HasRecord(tc.record, "A", records))
		})
	}
}
