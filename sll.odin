package odin_libpcap

import _c "core:c"

SLL_HDR_LEN :: 16 // Total hdr len 
SLL_ADDRLEN :: 8 // len of addr field 

// DLT_Linux_ssl fake link-layer hdr
ssl_header :: struct {
	ssl_pkttype:  _c.uint16_t, // pkt type 
	ssl_hatype:   _c.uint16_t, // link-layer addr type 
	ssl_halen:    _c.uint16_t, // link-layer addr len 
	ssl_addr:     [SLL_ADDRLEN]_c.uint8_t, // link-layer addr
	ssl_protocol: _c.uint16_t, // protocol
}

// DLT_LINUR_SSL2 fake link-layer hdr 
SLL2_HDR_LEN :: 20
ssl2_header :: struct {
	sll2_protocol:     _c.uint16_t, //protocol 
	sll2_reserved_mbz: _c.uint16_t, // reserved - must be zero 
	sll2_if_index:     _c.uint32_t, // 1-based interface index 
	sll2_hatype:       _c.uint16_t, // link-layer address type 
	sll2_pkttype:      _c.uint8_t, // packet type 
	sll2_halen:        _c.uint8_t, // link-layer address length 
	sll2_addr:         [SLL_ADDRLEN]_c.uint8_t, // link-layer address 
}

LINUX_SSL :: enum _c.int {
	HOST      = 0,
	BROADCAST = 1,
	MULTICAST = 2,
	OTHERHOST = 3,
	OUTGOING  = 4,
}

LINUX_SLL_P_802_3 :: 0x0001 //  Novell 802.3 frames without 802.2 LLC header */
LINUX_SLL_P_802_2 :: 0x0004 //  802.2 frames (not D/I/X Ethernet) */
LINUX_SLL_P_CAN :: 0x000C //  CAN frames, with SocketCAN pseudo-headers */
LINUX_SLL_P_CANFD :: 0x000D //  CAN FD frames, with SocketCAN pseudo-headers */
