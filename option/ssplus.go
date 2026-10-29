package option

type SSPlusUser struct {
	KeyID              uint32 `json:"key_id,omitempty"`
	PreviousKey        string `json:"previous_key,omitempty"`
	PreviousKeyID      uint32 `json:"previous_key_id,omitempty"`
	PreviousValidUntil int64  `json:"previous_valid_until,omitempty"`
	Name               string `json:"name,omitempty"`
	UserID             uint32 `json:"user_id"`
	Key                string `json:"key"`
}

type SSPlusInboundOptions struct {
	Padding       string `json:"padding,omitempty"`
	PaddingBudget int    `json:"padding_budget,omitempty"`
	ListenOptions
	UDPPadding *int         `json:"udp_padding,omitempty"`
	Method     string       `json:"method,omitempty"`
	IVKey      string       `json:"iv_key"`
	Users      []SSPlusUser `json:"users"`
}

type SSPlusOutboundOptions struct {
	KeyID         uint32 `json:"key_id,omitempty"`
	Padding       string `json:"padding,omitempty"`
	PaddingBudget int    `json:"padding_budget,omitempty"`
	DialerOptions
	ServerOptions
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	UDPPadding *int               `json:"udp_padding,omitempty"`
	Method     string             `json:"method,omitempty"`
	IVKey      string             `json:"iv_key"`
	UserID     uint32             `json:"user_id"`
	Key        string             `json:"key"`
	Network    NetworkList        `json:"network,omitempty"`
}
