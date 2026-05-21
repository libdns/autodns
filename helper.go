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

// MatchesZoneRecord reports whether zr matches target using libdns's
// wildcard rules: Name must match exactly; empty Type/TTL/Value in
// target act as wildcards.
func MatchesZoneRecord(target, zr sdk.ZoneRecord) bool {
	if zr.Name != target.Name {
		return false
	}
	if target.Type != "" && zr.Type != target.Type {
		return false
	}
	if target.Value != "" && zr.Value != target.Value {
		return false
	}
	if target.TTL != 0 && zr.TTL != target.TTL {
		return false
	}
	return true
}
