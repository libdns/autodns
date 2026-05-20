package autodns_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/libdns/autodns"
	"github.com/stretchr/testify/assert"
)

func TestZoneItemJSONMarshalUnmarshal(t *testing.T) {
	t.Run("Test with nil address", func(t *testing.T) {
		zoneNil := autodns.ZoneItem{
			Origin: "example.org",
			Main: autodns.ZoneItemMain{
				Address: nil,
				TTL:     3600,
			},
		}

		jsonData, err := json.Marshal(zoneNil)
		assert.NoError(t, err)
		assert.Contains(t, string(jsonData), `"address":null`)

		var unmarshaled autodns.ZoneItem
		err = json.Unmarshal(jsonData, &unmarshaled)
		assert.NoError(t, err)
		assert.Nil(t, unmarshaled.Main.Address)
		assert.Equal(t, 3600, unmarshaled.Main.TTL)
	})

	t.Run("valid IPv4 address", func(t *testing.T) {
		addr := netip.MustParseAddr("192.168.1.1")
		zoneIPv4 := autodns.ZoneItem{
			Origin: "example.org",
			Main: autodns.ZoneItemMain{
				Address: &addr,
				TTL:     7200,
			},
		}

		jsonData, err := json.Marshal(zoneIPv4)
		assert.NoError(t, err)
		assert.Contains(t, string(jsonData), `"address":"192.168.1.1"`)

		var unmarshaledIPv4 autodns.ZoneItem
		err = json.Unmarshal(jsonData, &unmarshaledIPv4)
		assert.NoError(t, err)
		assert.NotNil(t, unmarshaledIPv4.Main.Address)
		assert.Equal(t, addr, *unmarshaledIPv4.Main.Address)
		assert.Equal(t, 7200, unmarshaledIPv4.Main.TTL)
	})

	t.Run("valid IPv6 address", func(t *testing.T) {
		addrIPv6 := netip.MustParseAddr("2001:db8::1")
		zoneIPv6 := autodns.ZoneItem{
			Origin: "example.org",
			Main: struct {
				Address *netip.Addr `json:"address"`
				TTL     int         `json:"ttl"`
			}{
				Address: &addrIPv6,
				TTL:     1800,
			},
		}

		jsonData, err := json.Marshal(zoneIPv6)
		assert.NoError(t, err)
		assert.Contains(t, string(jsonData), `"address":"2001:db8::1"`)

		var unmarshaledIPv6 autodns.ZoneItem
		err = json.Unmarshal(jsonData, &unmarshaledIPv6)
		assert.NoError(t, err)
		assert.NotNil(t, unmarshaledIPv6.Main.Address)
		assert.Equal(t, addrIPv6, *unmarshaledIPv6.Main.Address)
		assert.Equal(t, 1800, unmarshaledIPv6.Main.TTL)
	})

	t.Run("invalid IP address", func(t *testing.T) {
		invalidJSON := `{"origin":"example.org","main":{"address":"invalid-ip","ttl":3600}}`
		var invalidUnmarshaled autodns.ZoneItem
		err := json.Unmarshal([]byte(invalidJSON), &invalidUnmarshaled)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP address")
	})

	t.Run("empty string address (should result in nil)", func(t *testing.T) {
		emptyJSON := `{"origin":"example.org","main":{"address":"","ttl":3600}}`
		var emptyUnmarshaled autodns.ZoneItem
		err := json.Unmarshal([]byte(emptyJSON), &emptyUnmarshaled)
		assert.NoError(t, err)
		assert.Nil(t, emptyUnmarshaled.Main.Address)
		assert.Equal(t, 3600, emptyUnmarshaled.Main.TTL)
	})
}
