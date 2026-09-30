package main

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestV2RayGRPCLite(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		testV2RayTransportSelfWith(t, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
				ForceLite:   true,
			},
		}, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
			},
		})
	})
	t.Run("client", func(t *testing.T) {
		testV2RayTransportSelfWith(t, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
			},
		}, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
				ForceLite:   true,
			},
		})
	})
	t.Run("self", func(t *testing.T) {
		testV2RayTransportSelfWith(t, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
				ForceLite:   true,
			},
		}, &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: "TunService",
				ForceLite:   true,
			},
		})
	})
}
