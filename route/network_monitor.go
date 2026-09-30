package route

import (
	"sync"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/x/list"
)

// sing-tun emits Windows route/interface notifications from parallel callbacks,
// but its default-interface debounce timer requires serialized notifications.
// This adapter adds no worker or timer and suppresses callbacks already queued
// by the OS when a listener is unregistered or the monitor is closed.
type serializedNetworkMonitor struct {
	tun.NetworkUpdateMonitor
	mu        sync.Mutex
	closed    bool
	listeners map[*list.Element[tun.NetworkUpdateCallback]]*bool
}

func serializeNetworkMonitor(m tun.NetworkUpdateMonitor) tun.NetworkUpdateMonitor {
	return &serializedNetworkMonitor{NetworkUpdateMonitor: m, listeners: make(map[*list.Element[tun.NetworkUpdateCallback]]*bool)}
}

func (m *serializedNetworkMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	active := new(bool)
	*active = true
	element := m.NetworkUpdateMonitor.RegisterCallback(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.closed && *active {
			callback()
		}
	})
	m.listeners[element] = active
	return element
}

func (m *serializedNetworkMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if active, ok := m.listeners[element]; ok {
		*active = false
		delete(m.listeners, element)
		m.NetworkUpdateMonitor.UnregisterCallback(element)
	}
}

func (m *serializedNetworkMonitor) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.listeners = nil
	m.mu.Unlock()
	return m.NetworkUpdateMonitor.Close()
}
