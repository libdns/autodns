package autodns

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/libdns/libdns"
)

const (
	autoDNSendpoint string = "https://api.autodns.com/v1"
	autoDNScontext  string = "4"
)

// Provider facilitates DNS record manipulation with Autodns.
type Provider struct {
	Username   string       `json:"username"`
	Password   string       `json:"password"`
	Endpoint   string       `json:"Endpoint"`
	Context    string       `json:"context"`
	Primary    string       `json:"primary"`
	HttpClient *http.Client `json:"-"`
}

// NewWithDefaults is a convenience method to create the provider with sensible defaults.
func NewWithDefaults(username, password string) *Provider {
	return &Provider{
		Username:   username,
		Password:   password,
		Endpoint:   autoDNSendpoint,
		Context:    autoDNScontext,
		HttpClient: &http.Client{},
	}
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneInfo, err := p.checkZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.getZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
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
	zoneInfo, err := p.checkZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.getZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}
		result.Data[0].Records = append(result.Data[0].Records, zoneRecord)
	}

	if err := p.updateZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, result.Data[0]); err != nil {
		return nil, err
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneInfo, err := p.checkZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.getZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	var set []libdns.Record

	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}

		// find record
		idx := slices.IndexFunc(
			result.Data[0].Records,
			func(zr ZoneRecord) bool {
				return zr.Name == zoneRecord.Name && zr.Type == zoneRecord.Type
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

	if err := p.updateZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, result.Data[0]); err != nil {
		return nil, err
	}

	return set, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneInfo, err := p.checkZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	result, err := p.getZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, zone)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record

	for _, r := range records {
		zoneRecord, err := ToAutoDNS(r)
		if err != nil {
			return nil, fmt.Errorf("failed to convert record: %v", err)
		}

		// find record
		idx := slices.IndexFunc(
			result.Data[0].Records,
			func(zr ZoneRecord) bool {
				return zr.Name == zoneRecord.Name && zr.Type == zoneRecord.Type
			})
		if idx == -1 {
			continue
		}

		// remove
		result.Data[0].Records = append(result.Data[0].Records[:idx], result.Data[0].Records[idx+1:]...)
		deleted = append(deleted, r)
	}

	if err := p.updateZone(ctx, zoneInfo.Origin, zoneInfo.Nameserver, result.Data[0]); err != nil {
		if _, ok := err.(*AutoDNSError); ok {
			return nil, err
		}
		return nil, fmt.Errorf("DeleteRecords: %v", err)
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
