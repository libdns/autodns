package autodns

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/libdns/autodns/sdk"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Autodns.
type Provider struct {
	Client *sdk.SDK
}

// NewWithDefaults is a convenience method to create the provider with sensible defaults.
func NewWithDefaults(username, password string) *Provider {
	return &Provider{
		Client: &sdk.SDK{
			Username:   username,
			Password:   password,
			HttpClient: &http.Client{},
		},
	}
}

func NewWithSDK(client *sdk.SDK) *Provider {
	return &Provider{
		Client: client,
	}
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneInfo, err := p.Client.CheckZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.Client.GetZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("no result for the zone %q", zone)
	}

	var data = result.Data[0]

	var countRecords = len(data.Records)
	if HasWWWInclude(data) {
		countRecords++
	}

	var records = make([]libdns.Record, 0, countRecords)

	for _, r := range data.Records {
		record, err := ToLibDNS(r)
		if err != nil {
			// TODO: Log the error but continue processing other records
			continue
		}
		records = append(records, record)
	}

	// the following "validate" the response to account for two AutoDNS features

	// check if the user created an A record and set the default IP additionally
	// parsing this is a bit messy, so we don't want to allow both as we don't know
	// which one to update
	if HasRecord("", "A", records) && data.Main.Address != nil {
		return nil, fmt.Errorf(
			"misconfigured AutoDNS zone: when setting the main IP, an A record is automatically created, but you have both",
		)
	}

	if HasRecord("www", "A", records) && HasWWWInclude(data) {
		return nil, fmt.Errorf(
			"misconfigured AutoDNS zone: you enabled `www include`, but you have another `www` (A) record as well",
		)
	}

	// Extract the apex (and optionally www) A record from Main.Address.
	// AutoDNS keeps these outside resourceRecords, so SetRecords/DeleteRecords
	// cannot update them — change Main.Address directly to update or remove
	// the apex/www A.
	if data.Main.Address != nil {
		mainTTL := time.Duration(data.Main.TTL) * time.Second
		records = append(records, libdns.Address{
			Name: "",
			TTL:  mainTTL,
			IP:   *data.Main.Address,
		})

		if HasWWWInclude(data) {
			records = append(records, libdns.Address{
				Name: "www",
				TTL:  mainTTL,
				IP:   *data.Main.Address,
			})
		}
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneInfo, err := p.Client.CheckZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	patch := sdk.ZonePatch{}
	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}
		patch.ResourceRecordsAdd = append(patch.ResourceRecordsAdd, zoneRecord)
	}

	if _, err := p.Client.PatchZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, patch); err != nil {
		return nil, err
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneInfo, err := p.Client.CheckZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.Client.GetZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	var set []libdns.Record

	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}

		// find record by (name, type) — wildcard on value/TTL.
		target := sdk.ZoneRecord{Name: zoneRecord.Name, Type: zoneRecord.Type}
		idx := slices.IndexFunc(
			result.Data[0].Records,
			func(zr sdk.ZoneRecord) bool {
				return MatchesZoneRecord(target, zr)
			})
		if idx == -1 {
			result.Data[0].Records = append(result.Data[0].Records, zoneRecord)
			set = append(set, r)
			continue
		}

		// update existing record
		result.Data[0].Records[idx] = zoneRecord
		set = append(set, r)
	}

	if err := p.Client.UpdateZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, result.Data[0]); err != nil {
		return nil, err
	}

	return set, nil
}

// DeleteRecords deletes the records from the zone. It returns the records
// that were deleted. Per the libdns contract, records that don't exist
// are silently ignored, matching is exact on Name+Type+TTL+Value, and
// empty Type/TTL/Value act as wildcards.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneInfo, err := p.Client.CheckZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.Client.GetZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	targets := make([]sdk.ZoneRecord, 0, len(records))
	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}
		targets = append(targets, zoneRecord)
	}

	patch := sdk.ZonePatch{}
	var deleted []libdns.Record

	for _, zr := range result.Data[0].Records {
		if !slices.ContainsFunc(targets, func(t sdk.ZoneRecord) bool {
			return MatchesZoneRecord(t, zr)
		}) {
			continue
		}
		libRec, err := ToLibDNS(zr)
		if err != nil {
			continue
		}
		patch.ResourceRecordsRem = append(patch.ResourceRecordsRem, zr)
		deleted = append(deleted, libRec)
	}

	if len(patch.ResourceRecordsRem) == 0 {
		return deleted, nil
	}

	if _, err := p.Client.PatchZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, patch); err != nil {
		return nil, err
	}
	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
