package autodns

import (
	"github.com/libdns/autodns/sdk"
	"github.com/libdns/libdns"
)

func HasRecord(name, rrType string, records []libdns.Record) bool {
	for _, record := range records {
		if record.RR().Name == name && record.RR().Type == rrType {
			return true
		}
	}
	return false
}

func HasWWWInclude(zone sdk.ZoneItem) bool {
	if zone.WWWInclude && zone.Main.Address != nil {
		return true
	}
	return false
}
