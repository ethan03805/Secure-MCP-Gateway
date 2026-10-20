//go:build windows

package winsandbox

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Filtering Platform egress filters (FR-21.14, SR-4.5-3). The
// Gateway keeps its own persistent provider and sublayer. For each
// backend AppContainer SID it adds, at the ALE connect and ALE
// receive/accept layers for IPv4 and IPv6, a block filter matching the
// SID (a hard block that a permit in another sublayer cannot override),
// and at the IPv4 connect layer a higher-weight permit for TCP to the
// Egress Broker's loopback port. The AppContainer's loopback exemption,
// without which the broker port is unreachable, is added and removed with
// the filters; it covers every loopback port, and the block filter is what
// limits it to the broker port.

var (
	modfwpuclnt                  = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0          = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0    = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0   = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0    = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0         = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0         = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0           = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterCreateEnum     = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0          = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnum    = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0          = modfwpuclnt.NewProc("FwpmFreeMemory0")

	modfirewallapi                         = windows.NewLazySystemDLL("FirewallAPI.dll")
	procNetworkIsolationGetAppContainerCfg = modfirewallapi.NewProc("NetworkIsolationGetAppContainerConfig")
	procNetworkIsolationSetAppContainerCfg = modfirewallapi.NewProc("NetworkIsolationSetAppContainerConfig")
)

// WFP error codes.
const (
	fwpEAlreadyExists = 0x80320009
	fwpENotFound      = 0x80320003 // FWP_E_FILTER_NOT_FOUND
	fwpEProviderNF    = 0x80320005
	fwpESubLayerNF    = 0x80320007
)

const (
	rpcCAuthnWinNT = 10

	fwpmProviderFlagPersistent = 0x1
	fwpmSublayerFlagPersistent = 0x1
	fwpmFilterFlagPersistent   = 0x1
	fwpmFilterFlagClearAction  = 0x8 // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: a hard block

	fwpActionBlock  = 0x1001 // FWP_ACTION_BLOCK
	fwpActionPermit = 0x1002 // FWP_ACTION_PERMIT

	fwpEmpty  = 0
	fwpUint8  = 1
	fwpUint16 = 2
	fwpUint32 = 3
	fwpSID    = 13

	fwpMatchEqual = 0
)

// The Gateway's provider and sublayer.
var (
	ProviderKey = windows.GUID{Data1: 0x5c3a1f60, Data2: 0x8d2b, Data3: 0x4e57, Data4: [8]byte{0x9a, 0x61, 0x53, 0x4d, 0x43, 0x50, 0x47, 0x57}}
	SublayerKey = windows.GUID{Data1: 0x5c3a1f61, Data2: 0x8d2b, Data3: 0x4e57, Data4: [8]byte{0x9a, 0x61, 0x53, 0x4d, 0x43, 0x50, 0x47, 0x57}}
)

// Layers and conditions (fwpmu.h).
var (
	layerConnectV4 = guid(0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82)
	layerConnectV6 = guid(0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4)
	layerAcceptV4  = guid(0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50)
	layerAcceptV6  = guid(0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f)

	condPackageID     = guid(0x71bc78fa, 0xf17c, 0x4997, 0xa6, 0x02, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c)
	condRemoteAddress = guid(0xb235ae9a, 0x1d64, 0x49b8, 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45)
	condRemotePort    = guid(0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b)
	condProtocol      = guid(0x3971ef2b, 0x623e, 0x4f9a, 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7)

	filterLayers = []windows.GUID{layerConnectV4, layerConnectV6, layerAcceptV4, layerAcceptV6}
)

func guid(d1 uint32, d2, d3 uint16, d4 ...byte) windows.GUID {
	g := windows.GUID{Data1: d1, Data2: d2, Data3: d3}
	copy(g.Data4[:], d4)
	return g
}

type fwpmDisplayData struct {
	Name        *uint16
	Description *uint16
}

type fwpByteBlob struct {
	Size uint32
	Data *byte
}

type fwpmProvider struct {
	ProviderKey  windows.GUID
	DisplayData  fwpmDisplayData
	Flags        uint32
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

type fwpmSublayer struct {
	SubLayerKey  windows.GUID
	DisplayData  fwpmDisplayData
	Flags        uint32
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob
	Weight       uint16
}

// fwpValue is FWP_VALUE0 and FWP_CONDITION_VALUE0: a type and an 8-byte
// union.
type fwpValue struct {
	Type  uint32
	Value uintptr
}

type fwpmFilterCondition struct {
	FieldKey  windows.GUID
	MatchType uint32
	Value     fwpValue
}

type fwpmAction struct {
	Type uint32
	Key  windows.GUID
}

type fwpmFilter struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              fwpValue
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition
	Action              fwpmAction
	ProviderContextKey  [2]uint64 // union with rawContext
	Reserved            *windows.GUID
	FilterID            uint64
	EffectiveWeight     fwpValue
}

type fwpmFilterEnumTemplate struct {
	ProviderKey             *windows.GUID
	LayerKey                windows.GUID
	EnumType                uint32
	Flags                   uint32
	ProviderContextTemplate uintptr
	NumFilterConditions     uint32
	FilterCondition         uintptr
	ActionMask              uint32
	CalloutKey              *windows.GUID
}

// Engine is an open session to the Windows Filtering Platform. Opening it
// and changing filters needs an administrator, which in the machine mode is
// the elevated enable step (FR-21.14).
type Engine struct {
	h windows.Handle
}

// OpenEngine opens the local filter engine.
func OpenEngine() (*Engine, error) {
	var h windows.Handle
	if r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&h))); r != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0: %w", hresult(r))
	}
	return &Engine{h: h}, nil
}

// Close closes the session.
func (e *Engine) Close() error {
	if e.h == 0 {
		return nil
	}
	r, _, _ := procFwpmEngineClose0.Call(uintptr(e.h))
	e.h = 0
	if r != 0 {
		return hresult(r)
	}
	return nil
}

func hresult(r uintptr) error { return fmt.Errorf("error 0x%08X", uint32(r)) }

func (e *Engine) tx(f func() error) error {
	if r, _, _ := procFwpmTransactionBegin0.Call(uintptr(e.h), 0); r != 0 {
		return fmt.Errorf("FwpmTransactionBegin0: %w", hresult(r))
	}
	if err := f(); err != nil {
		_, _, _ = procFwpmTransactionAbort0.Call(uintptr(e.h))
		return err
	}
	if r, _, _ := procFwpmTransactionCommit0.Call(uintptr(e.h)); r != 0 {
		return fmt.Errorf("FwpmTransactionCommit0: %w", hresult(r))
	}
	return nil
}

func u16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// ensureProvider adds the Gateway's persistent provider and sublayer when
// they do not exist.
func (e *Engine) ensureProvider() error {
	pk := ProviderKey
	prov := fwpmProvider{ProviderKey: pk, Flags: fwpmProviderFlagPersistent,
		DisplayData: fwpmDisplayData{Name: u16("Secure MCP Gateway"), Description: u16("Egress filters of the Gateway's backend AppContainers")}}
	if r, _, _ := procFwpmProviderAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&prov)), 0); r != 0 && uint32(r) != fwpEAlreadyExists {
		return fmt.Errorf("FwpmProviderAdd0: %w", hresult(r))
	}
	sl := fwpmSublayer{SubLayerKey: SublayerKey, Flags: fwpmSublayerFlagPersistent, ProviderKey: &pk, Weight: 0x7fff,
		DisplayData: fwpmDisplayData{Name: u16("Secure MCP Gateway backends"), Description: u16("Blocks backend AppContainers except the Egress Broker port")}}
	r, _, _ := procFwpmSubLayerAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&sl)), 0)
	runtime.KeepAlive(prov)
	if r != 0 && uint32(r) != fwpEAlreadyExists {
		return fmt.Errorf("FwpmSubLayerAdd0: %w", hresult(r))
	}
	return nil
}

// filterKey derives a stable filter key from the SID and the filter's role,
// so the filters of a SID can be found and removed without state.
func filterKey(sid *windows.SID, role string) windows.GUID {
	h := sha256.Sum256([]byte("smcp-wfp/" + sid.String() + "/" + role))
	g := windows.GUID{Data1: binary.LittleEndian.Uint32(h[0:4]), Data2: binary.LittleEndian.Uint16(h[4:6]), Data3: binary.LittleEndian.Uint16(h[6:8])&0x0fff | 0x5000}
	copy(g.Data4[:], h[8:16])
	g.Data4[0] = g.Data4[0]&0x3f | 0x80
	return g
}

// filterRoles are the filters of one SID: a block per layer and the broker
// permit.
var filterRoles = []string{"block-connect-v4", "block-connect-v6", "block-accept-v4", "block-accept-v6", "permit-broker-v4"}

// AddBackendFilters installs the filters of one backend AppContainer SID:
// every connection of the SID is blocked except TCP to 127.0.0.1 on
// brokerPort (SR-4.5-3), and the SID gets the loopback exemption that
// lets that one connection leave the AppContainer (FR-21.14). It replaces
// filters an earlier call added for the SID.
func (e *Engine) AddBackendFilters(sid *windows.SID, brokerPort uint16) error {
	if brokerPort == 0 {
		return errors.New("winsandbox: no broker port")
	}
	if err := e.ensureProvider(); err != nil {
		return err
	}
	if err := e.tx(func() error {
		if err := e.deleteFilters(sid); err != nil {
			return err
		}
		for i, layer := range filterLayers {
			if err := e.addFilter(sid, filterRoles[i], layer, fwpActionBlock, fwpmFilterFlagPersistent|fwpmFilterFlagClearAction, 0, nil); err != nil {
				return err
			}
		}
		return e.addFilter(sid, "permit-broker-v4", layerConnectV4, fwpActionPermit, fwpmFilterFlagPersistent, 15, []fwpmFilterCondition{
			{FieldKey: condProtocol, MatchType: fwpMatchEqual, Value: fwpValue{Type: fwpUint8, Value: 6}},
			{FieldKey: condRemoteAddress, MatchType: fwpMatchEqual, Value: fwpValue{Type: fwpUint32, Value: 0x7f000001}},
			{FieldKey: condRemotePort, MatchType: fwpMatchEqual, Value: fwpValue{Type: fwpUint16, Value: uintptr(brokerPort)}},
		})
	}); err != nil {
		return err
	}
	return setLoopbackExemption(sid, true)
}

func (e *Engine) addFilter(sid *windows.SID, role string, layer windows.GUID, action, flags uint32, weight uint8, extra []fwpmFilterCondition) error {
	pk := ProviderKey
	conds := append([]fwpmFilterCondition{{FieldKey: condPackageID, MatchType: fwpMatchEqual,
		Value: fwpValue{Type: fwpSID, Value: uintptr(unsafe.Pointer(sid))}}}, extra...)
	f := fwpmFilter{
		FilterKey:           filterKey(sid, role),
		DisplayData:         fwpmDisplayData{Name: u16("Secure MCP Gateway " + role), Description: u16(sid.String())},
		Flags:               flags,
		ProviderKey:         &pk,
		LayerKey:            layer,
		SubLayerKey:         SublayerKey,
		Weight:              fwpValue{Type: fwpUint8, Value: uintptr(weight)},
		NumFilterConditions: uint32(len(conds)),
		FilterCondition:     &conds[0],
		Action:              fwpmAction{Type: action},
	}
	var id uint64
	r, _, _ := procFwpmFilterAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(conds)
	runtime.KeepAlive(sid)
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0 %s: %w", role, hresult(r))
	}
	return nil
}

func (e *Engine) deleteFilters(sid *windows.SID) error {
	for _, role := range filterRoles {
		k := filterKey(sid, role)
		if r, _, _ := procFwpmFilterDeleteByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k))); r != 0 && uint32(r) != fwpENotFound {
			return fmt.Errorf("FwpmFilterDeleteByKey0 %s: %w", role, hresult(r))
		}
	}
	return nil
}

// RemoveBackendFilters removes the filters and the loopback exemption of
// one SID (disable, FR-21.14).
func (e *Engine) RemoveBackendFilters(sid *windows.SID) error {
	if err := e.tx(func() error { return e.deleteFilters(sid) }); err != nil {
		return err
	}
	return setLoopbackExemption(sid, false)
}

// Filter is one filter of the Gateway's provider.
type Filter struct {
	Key    windows.GUID
	Name   string
	Layer  windows.GUID
	Action uint32
}

// Filters lists the filters of the Gateway's provider on the layers it
// uses.
func (e *Engine) Filters() ([]Filter, error) {
	var out []Filter
	for _, layer := range filterLayers {
		pk := ProviderKey
		tmpl := fwpmFilterEnumTemplate{ProviderKey: &pk, LayerKey: layer, ActionMask: 0xffffffff}
		var eh windows.Handle
		if r, _, _ := procFwpmFilterCreateEnum.Call(uintptr(e.h), uintptr(unsafe.Pointer(&tmpl)), uintptr(unsafe.Pointer(&eh))); r != 0 {
			return nil, fmt.Errorf("FwpmFilterCreateEnumHandle0: %w", hresult(r))
		}
		for {
			var entries **fwpmFilter
			var n uint32
			r, _, _ := procFwpmFilterEnum0.Call(uintptr(e.h), uintptr(eh), 64, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n)))
			if r != 0 {
				_, _, _ = procFwpmFilterDestroyEnum.Call(uintptr(e.h), uintptr(eh))
				return nil, fmt.Errorf("FwpmFilterEnum0: %w", hresult(r))
			}
			if n > 0 {
				for _, f := range unsafe.Slice(entries, n) {
					out = append(out, Filter{Key: f.FilterKey, Name: windows.UTF16PtrToString(f.DisplayData.Name), Layer: f.LayerKey, Action: f.Action.Type})
				}
			}
			if entries != nil {
				_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
			}
			if n < 64 {
				break
			}
		}
		_, _, _ = procFwpmFilterDestroyEnum.Call(uintptr(e.h), uintptr(eh))
	}
	return out, nil
}

// Uninstall removes every filter of the Gateway's provider, its sublayer
// and the provider, and the loopback exemptions of the given SIDs
// (smcpctl uninstall, SR-4.5-3).
func (e *Engine) Uninstall(sids []*windows.SID) error {
	fs, err := e.Filters()
	if err != nil {
		return err
	}
	if err := e.tx(func() error {
		for _, f := range fs {
			k := f.Key
			if r, _, _ := procFwpmFilterDeleteByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k))); r != 0 && uint32(r) != fwpENotFound {
				return fmt.Errorf("FwpmFilterDeleteByKey0: %w", hresult(r))
			}
		}
		sk := SublayerKey
		if r, _, _ := procFwpmSubLayerDeleteByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&sk))); r != 0 && uint32(r) != fwpESubLayerNF {
			return fmt.Errorf("FwpmSubLayerDeleteByKey0: %w", hresult(r))
		}
		pk := ProviderKey
		if r, _, _ := procFwpmProviderDeleteByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&pk))); r != 0 && uint32(r) != fwpEProviderNF {
			return fmt.Errorf("FwpmProviderDeleteByKey0: %w", hresult(r))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, s := range sids {
		if err := setLoopbackExemption(s, false); err != nil {
			return err
		}
	}
	return nil
}

// LoopbackExempt reports whether the SID has the loopback exemption.
func LoopbackExempt(sid *windows.SID) (bool, error) {
	list, err := loopbackExemptions()
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.Equals(sid) {
			return true, nil
		}
	}
	return false, nil
}

func loopbackExemptions() ([]*windows.SID, error) {
	var n uint32
	var arr *windows.SIDAndAttributes
	if r, _, _ := procNetworkIsolationGetAppContainerCfg.Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&arr))); r != 0 {
		return nil, fmt.Errorf("NetworkIsolationGetAppContainerConfig: %w", hresult(r))
	}
	var out []*windows.SID
	if n > 0 && arr != nil {
		for _, sa := range unsafe.Slice(arr, n) {
			c, err := sa.Sid.Copy()
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	// The array is allocated by FirewallAPI with no documented free
	// routine; it is small and read at enable and disable only.
	return out, nil
}

// setLoopbackExemption adds or removes the SID from the AppContainer
// loopback exemption list, keeping the other entries.
func setLoopbackExemption(sid *windows.SID, on bool) error {
	cur, err := loopbackExemptions()
	if err != nil {
		return err
	}
	var next []windows.SIDAndAttributes
	found := false
	for _, s := range cur {
		if s.Equals(sid) {
			found = true
			if !on {
				continue
			}
		}
		next = append(next, windows.SIDAndAttributes{Sid: s})
	}
	if on == found {
		return nil
	}
	if on {
		next = append(next, windows.SIDAndAttributes{Sid: sid})
	}
	var p *windows.SIDAndAttributes
	if len(next) > 0 {
		p = &next[0]
	}
	if r, _, _ := procNetworkIsolationSetAppContainerCfg.Call(uintptr(len(next)), uintptr(unsafe.Pointer(p))); r != 0 {
		return fmt.Errorf("NetworkIsolationSetAppContainerConfig: %w", hresult(r))
	}
	runtime.KeepAlive(next)
	return nil
}

var _ = fwpEmpty
