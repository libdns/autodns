// Package sdk is a thin HTTP client for the AutoDNS (Domainrobot) JSON API.
//
// It is the transport used by the libdns/autodns provider, exported so
// callers who need direct access to AutoDNS — for example to read or
// write zone fields that libdns does not model (Main.Address, WWWInclude,
// SOA, nameServerGroup) — can use it on its own.
//
// # Authentication
//
// Requests use HTTP Basic auth (Username, Password) and carry the AutoDNS
// account context in the X-Domainrobot-Context header. When Context is
// empty the SDK falls back to a default value; set it explicitly if your
// account uses a non-default context.
//
// # Usage
//
//	s := &sdk.SDK{
//	    Username: os.Getenv("AUTODNS_USERNAME"),
//	    Password: os.Getenv("AUTODNS_PASSWORD"),
//	}
//
//	zone, err := s.CheckZone(ctx, "example.org")
//	if err != nil {
//	    return err
//	}
//
//	resp, err := s.GetZone(ctx, zone.Origin, zone.Nameserver, "example.org")
//	if err != nil {
//	    return err
//	}
//	// mutate resp.Data[0] ...
//	if err := s.UpdateZone(ctx, zone.Origin, zone.Nameserver, resp.Data[0]); err != nil {
//	    return err
//	}
//
// # Errors
//
// Errors returned by the AutoDNS API surface as *AutoDNSError. Use
// errors.As to inspect the underlying message list:
//
//	var apiErr *sdk.AutoDNSError
//	if errors.As(err, &apiErr) {
//	    for _, m := range apiErr.Messages() {
//	        // m.Text, m.Code, m.Objects
//	    }
//	}
package sdk
