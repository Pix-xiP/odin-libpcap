package odin_libpcap

import _c "core:c"

// Transfer modes
URB_TRANSFER_IN :: 0x80
URB_ISOCHRONOUS :: 0x0
URB_INTERRUPT :: 0x1
URB_CONTROL :: 0x2
URB_BULK :: 0x3

// Possible event types
URB_SUBMIT :: 'S'
URB_COMPLETE :: 'C'
URB_ERROR :: 'E'

pcap_usb_setup :: struct {
	bm_request_type: _c.uint8_t,
	b_request:       _c.uint8_t,
	w_value:         _c.uint16_t,
	w_index:         _c.uint16_t,
	w_lengthY:       _c.uint16_t,
}

// Infomration from URB for Isochronous transfers
iso_rec :: struct {
	error_count: _c.int32_t,
	numdesc:     _c.int32_t,
}

// Header prepended by linux kernel to each event
// appears at the front of each packet in DLT_USB_LINUX captures
pcap_usb_header :: struct {
	id:              _c.uint64_t,
	event_type:      _c.uint8_t,
	transfer_type:   _c.uint8_t,
	endpoint_number: _c.uint8_t,
	device_address:  _c.uint8_t,
	bus_id:          _c.uint16_t,
	setup_flag:      _c.char, // If !=0 urb setuphead ir not present
	data_flag:       _c.char, // If !=0 urb data is not present
	ts_sec:          _c.int64_t,
	ts_usec:         _c.int32_t,
	status:          _c.int32_t,
	urb_len:         _c.uint32_t,
	data_len:        _c.uint32_t, // amount of urb data really here
	setup:           ^pcap_usb_setup,
}

// Header prepended by linux kernel ot each event
// iso_src information and fields starting with interval are 
// zero'd out padding.
usb_hdr_s :: union {
	pcap_usb_setup,
	iso_rec,
}

pcap_usb_header_mapped :: struct {
	id:              _c.uint64_t,
	event_type:      _c.uint8_t,
	transfer_type:   _c.uint8_t,
	endpoint_number: _c.uint8_t,
	device_address:  _c.uint8_t,
	bus_id:          _c.uint16_t,
	setup_flag:      _c.char, // if !=0 urb setup hdr is not present
	data_flag:       _c.char, // if !=0 urb data is not present
	s:               usb_hdr_s,
	interval:        _c.int32_t, // for interupt & Isochronous events
	start_frame:     _c.int32_t, // for isochronus events
	xfer_flags:      _c.uint32_t, // copy of urbs xfer flags
	ndesc:           _c.uint32_t, // number of isochronus descriptors
}

// Isochronous descriptors; for isochronus transfers there might be 
// one or more of these at the beginning of the packet data. The 
// number of descriptors is given by the "ndesc" field in the header;
// as indicated - in older kernels that don't put descriptors at the
// beginning of the packet. field is zerod out, so that field can be 
// trusted even in captures from older kernels.
usb_isodesc :: struct {
	status: _c.int32_t,
	offset: _c.uint32_t,
	len:    _c.uint32_t,
	pad:    [4]_c.uint8_t,
}
