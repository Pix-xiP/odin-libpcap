package odin_libpcap

import _c "core:c"

// SocketCAN header, as per libpcap doc/networking/can.txt 

pcap_can_socketcan_hdr :: struct {
	can_id:         _c.uint32_t,
	payload_length: _c.uint8_t,
	fd_flags:       _c.uint8_t,
	reserved1:      _c.uint8_t,
	reserved2:      _c.uint8_t,
}

// Bits in fd_flags:
CANFD_BRS :: 0x01 // bit rate switch (second bitrate for payload data)
CANFD_ESI :: 0x02 // error state indicator of the transmitting node 
CANFD_FDF :: 0x04 // mark CAN FD for dual use of CAN format
