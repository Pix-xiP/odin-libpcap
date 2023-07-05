package odin_libpcap

import _c "core:c"

VLAN_TAG_LEN :: 4

vlan_tag :: struct {
	vlan_tpid: _c.uint16_t, // ETH_P_8021Q
	vlan_tci:  _c.uint16_t, // VLAN TCI
}
