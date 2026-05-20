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
)

func TestWWWInclude(t *testing.T) {
	content, err := os.ReadFile("./fixtures/mainWWW.json")
	assert.NoError(t, err)

	var item sdk.ZoneItem
	err = json.NewDecoder(bytes.NewBuffer(content)).Decode(&item)
	assert.NoError(t, err)

	assert.True(t, autodns.HasWWWInclude(item))
}

func TestHasRecord(t *testing.T) {
	content, err := os.ReadFile("./fixtures/mainWWW.json")
	assert.NoError(t, err)

	var item sdk.ZoneItem
	err = json.NewDecoder(bytes.NewBuffer(content)).Decode(&item)
	assert.NoError(t, err)

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
