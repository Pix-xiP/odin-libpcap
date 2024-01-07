package odin_libpcap

import _c "core:c"
import "core:c/libc"
import "core:os"

when ODIN_OS == .Windows {
	//TODO: Actually get windows VM to test.
	// WinPcap, NPcap are the options here.
	foreign import libpcap "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import libpcap "system:pcap"
}
when ODIN_OS == .Darwin {
	foreign import libpcap "system:pcap"
}

#assert(size_of(b32) == size_of(_c.int)) // To Use later maybe for wrappers!

// Removing the PCAP prefix as the odin package should prefix everything to make it easier
// at least on the things that make sense to lose.

ERRBUF_SIZE :: 256

pcap_t :: pcap
dumper_t :: dumper
pcap_if_t :: pcap_if
addr_t :: addr
handler :: #type proc(user: [^]byte, hdr: ^pkthdr, pkt: [^]byte)

// PCAP Structure Layout for Library
file_header :: struct {
	magic:         bpf_u_int32,
	version_major: _c.ushort,
	version_minor: _c.ushort,
	thiszone:      _c.int, // 0'd 
	sigfigs:       bpf_u_int32, // 0'd ' 
	snaplen:       bpf_u_int32, // max len saved portion of each pkt
	linktype:      bpf_u_int32, // data link type (LINKTYPE_*)
}

// TODO: LT_LINKTYPE macros to.. procs?

direction_t :: enum _c.int {
	INOUT = 0,
	IN,
	OUT,
}

option_name :: enum _c.int {
	TSTAMP_PRECISION = 1,
	IO_READ_PLUGIN   = 2,
	IO_WRITE_PLUGIN  = 3,
}

pcap :: struct {} // "C.incomplete_type" - opaque data type.. #JustCThings

dumper :: struct {} // "C.incomplete_type" - Believe its just a FILE * under the hood?

// Interface List Item
pcap_if :: struct {
	next:        ^pcap_if,
	name:        cstring,
	description: cstring,
	addresses:   ^addr,
	flags:       bpf_u_int32, // PCAP_IF_  ::interface flags
}

// PCAP_IF FLAG CONSTANTS
IF_LOOPBACK :: 0x00000001 // interface is loopback 
IF_UP :: 0x00000002 // interface is up 
IF_RUNNING :: 0x00000004 // interface is running 
IF_WIRELESS :: 0x00000008 // interface is wireless (*NOT* necessarily Wi-Fi!) 
IF_CONNECTION_STATUS :: 0x00000030 // connection status: 
IF_CONNECTION_STATUS_UNKNOWN :: 0x00000000 // unknown 
IF_CONNECTION_STATUS_CONNECTED :: 0x00000010 // connected 
IF_CONNECTION_STATUS_DISCONNECTED :: 0x00000020 // disconnected 
IF_CONNECTION_STATUS_NOT_APPLICABLE :: 0x00000030 // not applicable 

// Representation of an interface address
addr :: struct {
	next:      ^addr,
	addr:      ^os.SOCKADDR,
	netmask:   ^os.SOCKADDR,
	broadaddr: ^os.SOCKADDR,
	dstaddr:   ^os.SOCKADDR,
}

OKAY :: 1

ERRORS :: enum _c.int {
	GENERIC                 = -1, // generic error code 
	BREAK                   = -2, // loop terminated by pcap_breakloop 
	NOT_ACTIVATED           = -3, // the capture needs to be activated 
	ACTIVATED               = -4, // the operation can't be performed on already activated captures 
	NO_SUCH_DEVICE          = -5, // no such device exists 
	RFMON_NOTSUP            = -6, // this device doesn't support rfmon (monitor) mode 
	NOT_RFMON               = -7, // operation supported only in monitor mode 
	PERM_DENIED             = -8, // no permission to open the device 
	IFACE_NOT_UP            = -9, // interface isn't up 
	CANTSET_TSTAMP_TYPE     = -10, // this device doesn't support setting the time stamp type 
	PROMISC_PERM_DENIED     = -11, // you don't have permission to capture in promiscuous mode 
	TSTAMP_PRECISION_NOTSUP = -12, // the requested time stamp precision is not supported 
}

// Warning codes for PCAP API 
// Warnings are positive so as not to clash with errors...
// PCAP_WARNING :: 1 // Generic warning code 
// PCAP_WARNING_PROMISC_NOTSUP :: 2 // device doesn't support promisc mode 
// PCAP_WARNING_TSTAMP_TYPE_NOTSUP :: 3 // timestype type is not supported
WARNING :: enum _c.int {
	GENERIC            = 1,
	PROMISC_NOTSUP     = 2,
	TSTAMP_TYPE_NOTSUP = 3,
}

// Value to pass to pcap_compile() as the netmask if you don't 
// know what the netmask it!
NETMASK_UNKNOWN :: 0xFFFFFFFF

// Initialisation Options:
// On UNIX systems local character encoding is assumed to be UTF-8
// On Windows, local character encoding is the local ansi code page. 

CHAR_ENC_LOCAL: u32 : 0x00000000 // strings are in the local character encoding 
CHAR_ENC_UTF_8: u32 : 0x00000001 // strings are in UTF-8
MMAP_32BIT: u32 : 0x00000002 // map packet buffers with 32-bit addresses

timeval :: struct {
	tv_sec:  _c.long,
	tv_usec: _c.long,
}

pkthdr :: struct {
	ts:     timeval,
	caplen: bpf_u_int32,
	len:    bpf_u_int32,
}

when ODIN_OS == .Windows {
	stat :: struct {
		ps_recv:    _c.uint32_t,
		ps_drop:    _c.uint32_t,
		ps_ifdrop:  _c.uint32_t,
		ps_capt:    _c.uint32_t,
		ps_sent:    _c.uint32_t,
		ps_netdrop: _c.uint32_t,
	}
	// MSDOS stat_ex
	stat_ex :: struct {
		rx_packets:          _c.ulong, // total packets received
		tx_packets:          _c.ulong, // total packets transmitted    
		rx_bytes:            _c.ulong, // total bytes received         
		tx_bytes:            _c.ulong, // total bytes transmitted      
		rx_errors:           _c.ulong, // bad packets received         
		tx_errors:           _c.ulong, // packet transmit problems     
		rx_dropped:          _c.ulong, // no space in Rx buffers       
		tx_dropped:          _c.ulong, // no space available for Tx    
		multicast:           _c.ulong, // multicast packets received   
		collisions:          _c.ulong,

		// detailed rx_errors: 
		rx_length_errors:    _c.ulong,
		rx_over_errors:      _c.ulong, // receiver ring buff overflow  
		rx_crc_errors:       _c.ulong, // recv'd pkt with crc error    
		rx_frame_errors:     _c.ulong, // recv'd frame alignment error 
		rx_fifo_errors:      _c.ulong, // recv'r fifo overrun          
		rx_missed_errors:    _c.ulong, // recv'r missed packet         

		// detailed tx_errors 
		tx_aborted_errors:   _c.ulong,
		tx_carrier_errors:   _c.ulong,
		tx_fifo_errors:      _c.ulong,
		tx_heartbeat_errors: _c.ulong,
		tx_window_errors:    _c.ulong,
	}
} else {
	stat :: struct {
		ps_recv:   _c.uint32_t,
		ps_drop:   _c.uint32_t,
		ps_ifdrop: _c.uint32_t,
	}
}

rmtauth :: struct {
	type:     _c.int,
	username: cstring,
	password: cstring,
}

samp :: struct {
	method: _c.int,
	value:  _c.int,
}

options :: struct {} // "C.incomplete_type" 

@(default_calling_convention = "c", link_prefix = "pcap_")
foreign libpcap {
	init :: proc(opts: _c.uint, errbuf: [^]byte) -> _c.int ---

	@(deprecated = "'lokupdev' is deprecated. Use 'findalldevs' instead")
	lookupdev :: proc(errbuf: [^]byte) -> cstring ---

	lookupnet :: proc(device: cstring, netp: ^bpf_u_int32, maskp: ^bpf_u_int32, errbuf: [^]byte) -> _c.int ---

	create :: proc(source: cstring, errbuf: [^]byte) -> ^pcap_t ---

	set_snaplen :: proc(p: ^pcap_t, snaplen: _c.int) -> _c.int ---

	set_promisc :: proc(p: ^pcap_t, promisc: _c.int) -> _c.int ---

	can_set_rfmon :: proc(p: ^pcap_t) -> _c.int ---

	set_rfmon :: proc(p: ^pcap_t, rfmon: _c.int) -> _c.int ---

	set_timeout :: proc(p: ^pcap_t, to_ms: _c.int) -> _c.int ---

	set_tstamp_type :: proc(p: ^pcap_t, tstamp_type: _c.int) -> _c.int ---

	set_immediate_mode :: proc(p: ^pcap_t, immediate_mode: _c.int) -> _c.int ---

	set_buffer_size :: proc(p: ^pcap_t, buffer_size: _c.int) -> _c.int ---

	set_tstamp_precision :: proc(p: ^pcap_t, tstamp_precision: _c.int) -> _c.int ---

	get_tstamp_precision :: proc(p: ^pcap_t) -> _c.int ---

	activate :: proc(p: ^pcap_t) -> _c.int ---

	list_tstamp_types :: proc(p: ^pcap_t, tstamp_typesp: ^^_c.int) -> _c.int ---

	free_tstamp_types :: proc(tstamp_types: ^_c.int) ---

	tstamp_type_name_to_val :: proc(name: cstring) -> _c.int ---

	tstamp_type_val_to_name :: proc(tstamp_type: _c.int) -> cstring ---

	tstamp_type_val_to_description :: proc(tstamp_type: _c.int) -> cstring ---

	open_live :: proc(device: cstring, snaplen: _c.int, promisc: b32, to_ms: _c.int, errbuf: [^]byte) -> ^pcap_t ---

	open_dead :: proc(linktype: _c.int, snaplen: _c.int) -> ^pcap_t ---

	open_dead_with_tstamp_precision :: proc(linktype: _c.int, snaplen: _c.int, precision: _c.uint32_t) -> ^pcap_t ---

	open_offline_with_tstamp_precision :: proc(savefile: cstring, precision: _c.uint32_t, errbuf: [^]byte) -> ^pcap_t ---

	open_offline :: proc(savefile: cstring, errbuf: [^]byte) -> ^pcap_t ---

	fopen_offline_with_tstamp_precision :: proc(fp: ^libc.FILE, precision: _c.uint32_t, errbuf: [^]byte) -> ^pcap_t ---

	fopen_offline :: proc(fp: ^libc.FILE, errbuf: [^]byte) -> ^pcap_t ---

	close :: proc(p: ^pcap_t) ---

	loop :: proc(p: ^pcap_t, count: _c.int, callback: handler, user: [^]byte) -> _c.int ---

	dispatch :: proc(p: ^pcap_t, count: _c.int, callback: handler, user: [^]byte) -> _c.int ---

	next :: proc(p: ^pcap_t, pkt_hdr: ^pkthdr) -> ^[^]byte ---

	next_ex :: proc(p: ^pcap_t, pkt_hdr: ^^pkthdr, pkt_data: ^[^]byte) -> _c.int ---

	breakloop :: proc(p: ^pcap_t) ---

	stats :: proc(p: ^pcap_t, ps: ^stat) -> _c.int ---

	setfilter :: proc(p: ^pcap_t, fp: ^bpf_program) -> _c.int ---

	setdirection :: proc(p: ^pcap_t, direction: direction_t) -> _c.int ---

	getnonblock :: proc(p: ^pcap_t, errbuf: [^]byte) -> _c.int ---

	setnonblock :: proc(p: ^pcap_t, nonblock: _c.int, errbuf: [^]byte) -> _c.int ---
	// NOTE: rawptr might actually need to be [^]byte same as sendpacket
	inject :: proc(p: ^pcap_t, buf: rawptr, size: _c.size_t) -> _c.int ---

	sendpacket :: proc(p: ^pcap_t, buf: [^]byte, size: _c.int) -> _c.int ---

	statustostr :: proc(error: _c.int) -> cstring ---

	strerror :: proc(error: _c.int) -> cstring ---

	geterr :: proc(p: ^pcap_t) -> cstring ---

	perror :: proc(p: ^pcap_t, prefix: cstring) ---

	compile :: proc(p: ^pcap_t, fp: ^bpf_program, str: cstring, optimize: _c.int, netmask: bpf_u_int32) -> _c.int ---
	//  // Deprecated completely
	// compile_nopcap :: proc(: _c.int, unamed1: _c.int, unamed2: ^bpf_program, unamed3: cstring, unamed4: _c.int, unamed5: bpf_u_int32) -> _c.int ---

	freecode :: proc(ptr: ^bpf_program) ---

	offline_filter :: proc(fp: ^bpf_program, hdr: ^pkthdr, pkg: [^]byte) -> _c.int ---

	datalink :: proc(p: ^pcap_t) -> _c.int ---

	datalink_ext :: proc(p: ^pcap_t) -> _c.int ---

	list_datalinks :: proc(p: ^pcap_t, dtlist_buf: ^^_c.int) -> _c.int ---

	set_datalink :: proc(p: ^pcap_t, datalink: _c.int) -> _c.int ---

	free_datalinks :: proc(dlt_list: ^_c.int) ---

	datalink_name_to_val :: proc(name: cstring) -> _c.int ---

	datalink_val_to_name :: proc(value: _c.int) -> cstring ---

	datalink_val_to_description :: proc(value: _c.int) -> cstring ---

	datalink_val_to_description_or_dlt :: proc(value: _c.int) -> cstring ---

	snapshot :: proc(p: ^pcap_t) -> _c.int ---

	is_swapped :: proc(p: ^pcap_t) -> _c.int ---

	major_version :: proc(p: ^pcap_t) -> _c.int ---

	minor_version :: proc(p: ^pcap_t) -> _c.int ---

	bufsize :: proc(p: ^pcap_t) -> _c.int ---

	file :: proc(p: ^pcap_t) -> ^libc.FILE ---

	fileno :: proc(p: ^pcap_t) -> _c.int ---

	dump_open :: proc(p: ^pcap_t, fname: cstring) -> ^dumper_t ---

	dump_fopen :: proc(p: ^pcap_t, fp: ^libc.FILE) -> ^dumper_t ---

	dump_open_append :: proc(p: ^pcap_t, fname: cstring) -> ^dumper_t ---

	dump_file :: proc(p: ^dumper_t) -> ^libc.FILE ---

	dump_ftell :: proc(p: ^dumper_t) -> _c.long ---

	dump_ftell64 :: proc(p: ^dumper_t) -> i64 ---

	dump_flush :: proc(p: ^dumper_t) -> _c.int ---

	dump_close :: proc(p: ^dumper_t) ---

	dump :: proc(user: [^]byte, hdr: ^pkthdr, sp: [^]byte) ---

	// findalldevs :: proc(alldevs_ptr: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---
	findalldevs :: proc(alldevs_ptr: ^^pcap_if_t, errbuf: [^]byte) -> ERRORS ---

	freealldevs :: proc(alldevs: ^pcap_if_t) ---

	lib_version :: proc() -> cstring ---

	get_selectable_fd :: proc(p: ^pcap_t) -> _c.int ---

	get_required_select_timeout :: proc(p: ^pcap_t) -> ^timeval ---

	open :: proc(source: cstring, snaplen: _c.int, flags: _c.int, read_timeout: _c.int, auth: ^rmtauth, errbuf: [^]byte) -> ^pcap_t ---

	createsrcstr :: proc(source: cstring, type: _c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	parsesrcstr :: proc(source: cstring, type: ^_c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	findalldevs_ex :: proc(source: cstring, auth: ^rmtauth, alldevs: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---

	setsampling :: proc(p: ^pcap_t) -> ^samp ---

	//	remoteact_accept :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^rmtauth, errbuf: [^]byte) -> SOCKET ---
	//	
	//	remoteact_accept_ex :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^rmtauth, uses_ssl: _c.int, errbuf: [^]byte) -> SOCKET ---

	remoteact_list :: proc(hostlist: cstring, sep: _c.char, size: _c.int, errbuf: [^]byte) -> _c.int ---

	remoteact_close :: proc(host: cstring, errbuf: [^]byte) -> _c.int ---

	remoteact_cleanup :: proc() ---

	alloc_option :: proc() -> ^options ---

	free_option :: proc(po: ^options) ---

	set_option_string :: proc(po: ^options, pon: option_name, value: cstring) -> _c.int ---

	set_option_int :: proc(po: ^options, pon: option_name, value: _c.int) -> _c.int ---

	get_option_string :: proc(po: ^options, pon: option_name) -> cstring ---

	get_option_int :: proc(po: ^options, pon: option_name) -> _c.int ---
}
