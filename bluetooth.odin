package odin_libpcap

import _c "core:c"

// Header prepended libpcap to each bluetooth frame fields as in network byte order
pcap_bluetooth_h4_header :: struct {
	direction: _c.uint32_t, // if first bit set, direction is incoming
}

// Header prepended libpcap to each bluetooth frame fields as in network byte order
pcap_bluetooth_linux_monitor_header :: struct {
	adapter_id: _c.uint16_t,
	opcode:     _c.uint16_t,
}
