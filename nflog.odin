package odin_libpcap

import _c "core:c"

nflog_hdr_t :: struct {
	nflog_family:  _c.uint8_t, // address family
	nflog_version: _c.uint8_t, // lib_version
	nflog_rid:     _c.uint16_t, // res ID
}

nflog_tlv_t :: struct {
	tlv_length: _c.uint16_t, // tlv length
	tlv_type:   _c.uint16_t, // tlv type 
	// Value Follows this!
}

nflog_packet_hdr_t :: struct {
	hw_addrlen: _c.uint16_t, // Address Length 
	pad:        _c.uint16_t, // padding to 32-bit boundary
	hw_addr:    [8]_c.uint8_t, // address, up to 8 bytes
}

nflog_timestamp_t :: struct {
	sec:  _c.uint64_t,
	usec: _c.uint64_t,
}

NFULA :: enum _c.int {
	PACKET_HDR         = 1, // nflog_packet_hdr_t 
	MARK               = 2, // packet mark from skbuff 
	TIMESTAMP          = 3, // nflog_timestamp_t for skbuff's time stamp 
	IFINDEX_INDEV      = 4, // ifindex of device on which packet received (possibly bridge group) 
	IFINDEX_OUTDEV     = 5, // ifindex of device on which packet transmitted (possibly bridge group) 
	IFINDEX_PHYSINDEV  = 6, // ifindex of physical device on which packet received (not bridge group) 
	IFINDEX_PHYSOUTDEV = 7, // ifindex of physical device on which packet transmitted (not bridge group) 
	HWADDR             = 8, // nflog_hwaddr_t for hardware address 
	PAYLOAD            = 9, // packet payload 
	PREFIX             = 10, // text string - null-terminated, count includes NUL 
	UID                = 11, // UID owning socket on which packet was sent/received 
	SEQ                = 12, // sequence number of packets on this NFLOG socket 
	SEQ_GLOBAL         = 13, // sequence number of packets on all NFLOG sockets 
	GID                = 14, // GID owning socket on which packet was sent/received 
	HWTYPE             = 15, // ARPHRD_ type of skbuff's device 
	HWHEADER           = 16, // skbuff's MAC-layer header 
	HWLEN              = 17, // length of skbuff's MAC-layer header 
}
