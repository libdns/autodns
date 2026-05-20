package autodns

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

type AutoDNSObject struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AutoDNSUser struct {
	Context int32  `json:"context"`
	User    string `json:"user"`
}

type RequestZone struct {
	Domain string `json:"domain"`
}

type AutoDNSMessage struct {
	Text    string          `json:"text"`
	Objects []AutoDNSObject `json:"objects"`
	Code    string          `json:"code"`
	Status  string          `json:"status"`
}

type AutoDNSResponse struct {
	STID string `json:"stid"`

	Status struct {
		Type string  `json:"type"`
		Code *string `json:"resultCode,omitempty"`
		Text *string `json:"text,omitempty"`
	} `json:"status"`

	Object *AutoDNSObject `json:"object,omitempty"`

	// potential error messages
	Messages []*AutoDNSMessage `json:"messages,omitempty"`
}

type ResponseSearch struct {
	AutoDNSResponse
	Data []ResponseSearchItem `json:"data"`
}

type ResponseZone struct {
	AutoDNSResponse
	Data []ZoneItem `json:"data"`
}

// {
// 	"created": "2023-10-18T13:56:47.000+0200",
// 	"updated": "2024-10-25T13:16:43.000+0200",
// 	"origin": "something.example.org",
// 	"nameServerGroup": "ns14.net",
// 	"owner": {
// 	  "context": 4,
// 	  "user": "user"
// 	},
// 	"updater": {
// 	  "context": 4,
// 	  "user": "user"
// 	},
// 	"domainsafe": false,
// 	"wwwInclude": false,
// 	"virtualNameServer": "a.ns14.net"
// }

type ResponseSearchItem struct {
	Created    string      `json:"created"`
	Updated    string      `json:"updated"`
	Origin     string      `json:"origin"`
	NSGroup    string      `json:"nameServerGroup"`
	Owner      AutoDNSUser `json:"owner"`
	Updater    AutoDNSUser `json:"updater"`
	DomainSafe bool        `json:"domainsafe"`
	WWWInclude bool        `json:"wwwInclude"`
	Nameserver string      `json:"virtualNameserver"`
}

//	{
//		"created": "2023-10-18T13:56:47.000+0200",
//		"updated": "2024-10-25T13:16:43.000+0200",
//		"origin": "something.example.org",
//		"soa": {
//		  "refresh": 43200,
//		  "retry": 7200,
//		  "expire": 1209600,
//		  "ttl": 86400,
//		  "email": "do-not-reply@something.example.org"
//		},
//		"nameServerGroup": "ns14.net",
//		"owner": {
//		  "context": 4,
//		  "user": "user"
//		},
//		"updater": {
//		  "context": 4,
//		  "user": "user"
//		},
//		"domainsafe": false,
//		"purgeType": "DISABLED",
//		"nameServers": [
//		  {
//			"name": "a.ns14.net"
//		  },
//		  {
//			"name": "b.ns14.net"
//		  },
//		  {
//			"name": "c.ns14.net"
//		  },
//		  {
//			"name": "d.ns14.net"
//		  }
//		],
//		"main": {
//		  "address": "127.0.0.1"
//		},
//		"wwwInclude": false,
//		"virtualNameServer": "a.ns14.net",
//		"action": "COMPLETE",
//		"resourceRecords": [
//		  {
//			"name": "*",
//			"type": "A",
//			"value": "127.0.0.1"
//		  }
//		],
//		"roid": 9149383
//	  }
//
// ]

type ZoneRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Pref  *int   `json:"pref"`
	TTL   int    `json:"ttl"`
}

type ZoneItem struct {
	Created string `json:"created"`
	Updated string `json:"updated"`
	Origin  string `json:"origin"`

	SOA struct {
		Refresh int    `json:"refresh"`
		Retry   int    `json:"retry"`
		Expire  int    `json:"expire"`
		TTL     int    `json:"ttl"`
		Email   string `json:"email"`
	} `json:"soa"`

	NSGroup    string      `json:"nameServerGroup"`
	Owner      AutoDNSUser `json:"owner"`
	Updater    AutoDNSUser `json:"updater"`
	DomainSafe bool        `json:"domainsafe"`
	PurgeType  string      `json:"purgeType"`

	Nameservers []struct {
		Name string `json:"name"`
	} `json:"nameservers"`

	Main ZoneItemMain `json:"main"`

	// this enables an automatic `www` record (of type A for the domain)
	WWWInclude bool   `json:"wwwInclude"`
	Nameserver string `json:"virtualNameserver"`
	Action     string `json:"action"`

	Records []ZoneRecord `json:"resourceRecords"`

	ROID int `json:"roid"`
}

type ZoneItemMain struct {
	// the default IP address to be used, e.g. for an A-record for the domain)
	Address *netip.Addr `json:"address"`
	// the default TTL of the record
	TTL int `json:"ttl"`
}

// Custom JSON marshaling for Main struct to handle *netip.Addr
func (m *ZoneItem) MarshalJSON() ([]byte, error) {
	type Alias ZoneItem
	aux := &struct {
		*Alias
		Main struct {
			Address *string `json:"address"`
			TTL     int     `json:"ttl"`
		} `json:"main"`
	}{
		Alias: (*Alias)(m),
	}

	aux.Main.TTL = m.Main.TTL
	if m.Main.Address != nil {
		addr := m.Main.Address.String()
		aux.Main.Address = &addr
	}

	return json.Marshal(aux)
}

func (m *ZoneItem) UnmarshalJSON(data []byte) error {
	type Alias ZoneItem
	aux := &struct {
		*Alias
		Main struct {
			Address *string `json:"address"`
			TTL     int     `json:"ttl"`
		} `json:"main"`
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	m.Main.TTL = aux.Main.TTL
	if aux.Main.Address != nil && *aux.Main.Address != "" {
		addr, err := netip.ParseAddr(*aux.Main.Address)
		if err != nil {
			return fmt.Errorf("invalid IP address: %w", err)
		}
		m.Main.Address = &addr
	}

	return nil
}

type AutoDNSError struct {
	messages []*AutoDNSMessage
}

func (m *AutoDNSError) Error() string {
	if m.messages == nil {
		return "unknown error"
	}

	var errs []string
	for _, m := range m.messages {
		objects := []string{}
		for _, o := range m.Objects {
			objects = append(objects, "%s (type: %s)", o.Value, o.Type)
		}

		errs = append(errs, fmt.Sprintf("%s, code: %s, objects: %s",
			m.Text, m.Code, strings.Join(objects, ", "),
		))
	}

	return strings.Join(errs, "; ")
}

func (m *AutoDNSError) Messages() []*AutoDNSMessage {
	return m.messages
}

func NewError(messages []*AutoDNSMessage) *AutoDNSError {
	return &AutoDNSError{
		messages: messages,
	}
}
