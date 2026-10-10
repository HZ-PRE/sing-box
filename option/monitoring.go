package option

import "github.com/sagernet/sing/common/json/badoption"

type MonitoringOptions struct {
	EnableNodeIPInfo bool               `json:"enable_node_ip_info,omitempty"`
	Interval         badoption.Duration `json:"interval,omitempty"`
	URLs             []string           `json:"urls,omitempty"` //H
	Workers          int                `json:"workers,omitempty"`
	DebounceWindow   badoption.Duration `json:"debounce_window,omitempty"`
	URLTestTimeout   badoption.Duration `json:"url_test_timeout,omitempty"`
	IdleTimeout      badoption.Duration `json:"idle_timeout,omitempty"`
}
