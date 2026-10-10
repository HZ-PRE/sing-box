package option

type SSPlusUser struct {
	Name     string `json:"name,omitempty"`
	UserID   uint32 `json:"user_id"`
	Key      string `json:"key"`
	Password string `json:"password,omitempty"`
}

type SSPlusInboundOptions struct {
	ListenOptions
	UDPPadding *int         `json:"udp_padding,omitempty"`
	Method     string       `json:"method,omitempty"`
	Protocol   string       `json:"protocol,omitempty"`
	Obfs       string       `json:"obfs,omitempty"`
	ObfsParam  string       `json:"obfs_param,omitempty"`
	IVKey      string       `json:"iv_key"`
	Users      []SSPlusUser `json:"users"`
}

type SSPlusOutboundOptions struct {
	DialerOptions
	ServerOptions
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	UDPPadding *int               `json:"udp_padding,omitempty"`
	Method     string             `json:"method,omitempty"`
	Protocol   string             `json:"protocol,omitempty"`
	Obfs       string             `json:"obfs,omitempty"`
	ObfsParam  string             `json:"obfs_param,omitempty"`
	IVKey      string             `json:"iv_key"`
	UserID     uint32             `json:"user_id"`
	Key        string             `json:"key"`
	Password   string             `json:"password,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
}
