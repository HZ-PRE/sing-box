package monitoring

import (
	"context"

	"github.com/sagernet/sing-box/sdm/ipinfo"
)

type ipInfoTask struct {
	tag        string
	version    uint64
	permission context.Context
}

func (m *OutboundMonitoring) queueIPInfo(tag string) {
	m.ipInfoMu.Lock()
	permission := m.ipInfoContext
	m.ipInfoMu.Unlock()
	if permission == nil || permission.Err() != nil {
		return
	}
	state := m.outbounds[tag]
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.ipPending || (!state.ipRefresh && state.history.IpInfo != nil) {
		return
	}
	select {
	case m.ipInfoQueue <- ipInfoTask{tag, state.ipVersion, permission}:
		state.ipPending = true
	default: // Metadata is optional; never block latency publication on its queue.
	}
}

func (m *OutboundMonitoring) ipInfoWorkerLoop() {
	defer m.workerWG.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case task := <-m.ipInfoQueue:
			m.fetchIPInfo(task)
		}
	}
}

func (m *OutboundMonitoring) fetchIPInfo(task ipInfoTask) {
	state := m.outbounds[task.tag]
	defer func() {
		state.mu.Lock()
		state.ipPending = false
		state.mu.Unlock()
	}()
	state.mu.Lock()
	valid := task.version == state.ipVersion && !state.invalid
	state.mu.Unlock()
	if !valid || task.permission.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(task.permission, m.urlTestTimeout)
	defer cancel()
	info, _, err := ipinfo.GetIpInfo(m.logger, ctx, state.outbound)
	if err != nil || ctx.Err() != nil || info == nil {
		return
	}
	m.applyIPInfo(task, ctx, info)
}

func (m *OutboundMonitoring) applyIPInfo(task ipInfoTask, ctx context.Context, info *ipinfo.IpInfo) {
	state := m.outbounds[task.tag]
	state.mu.Lock()
	defer state.mu.Unlock()
	if task.version != state.ipVersion || state.invalid || ctx.Err() != nil || task.permission.Err() != nil {
		return
	}
	state.history.IpInfo = mergeIpInfo(state.history.IpInfo, info)
	state.ipRefresh = false
	// An IP provider's response time is not a latency probe. Never overwrite
	// Delay/Time here or change node selection based on a different endpoint.
	snapshot := state.history
	m.history.StoreURLTestHistory(task.tag, &snapshot)
	m.cacheDirty.Store(true)
	m.emitGroupEvent(state.groupTags)
}
