package odin_libpcap

import "core:os"
import _c "core:c"
import "core:c/libc"

// TODO: Add a when for each system - Linux, Windows etc.
when ODIN_OS == .Windows {
	// WinPcap, NPcap are the options here.
	foreign import libpcap "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import libpcap "libpcap" // TODO: Put on a linux VM and check if .a needed
}
when ODIN_OS == .Darwin {
	// HACK: Ran into issues with it finding the dylib, so moved it into the folder..
	foreign import libpcap "system:libpcap.A.dylib"
}

#assert(size_of(b32) == size_of(_c.int)) // To Use later maybe for wrappers!

PCAP_ERRBUF_SIZE :: 256

pcap_t :: pcap
pcap_dumper_t :: pcap_dumper
pcap_if_t :: pcap_if
pcap_addr_t :: pcap_addr
pcap_handler :: #type proc(user: [^]byte, hdr: ^pcap_pkthdr, pkt: [^]byte)

// PCAP Structure Layout for Library
pcap_file_header :: struct {
	magic:         bpf_u_int32,
	version_major: _c.ushort,
	version_minor: _c.ushort,
	thiszone:      _c.int, // 0'd 
	sigfigs:       bpf_u_int32, // 0'd ' 
	snaplen:       bpf_u_int32, // max len saved portion of each pkt
	linktype:      bpf_u_int32, // data link type (LINKTYPE_*)
}

// TODO: LT_LINKTYPE macros to.. procs?

pcap_direction_t :: enum i32 {
	PCAP_D_INOUT = 0,
	PCAP_D_IN,
	PCAP_D_OUT,
}

pcap_option_name :: enum i32 {
	PON_TSTAMP_PRECISION = 1,
	PON_IO_READ_PLUGIN   = 2,
	PON_IO_WRITE_PLUGIN  = 3,
}

pcap :: struct {} // "C.incomplete_type" - opaque data type.. #JustCThings

pcap_dumper :: struct {} // "C.incomplete_type" - Believe its just a FILE * under the hood?

// Interface List Item
pcap_if :: struct {
	next:        ^pcap_if,
	name:        cstring,
	description: cstring,
	addresses:   ^pcap_addr,
	flags:       bpf_u_int32, // PCAP_IF_  ::interface flags
}

// PCAP_IF FLAG CONSTANTS
PCAP_IF_LOOPBACK :: 0x00000001 // interface is loopback 
PCAP_IF_UP :: 0x00000002 // interface is up 
PCAP_IF_RUNNING :: 0x00000004 // interface is running 
PCAP_IF_WIRELESS :: 0x00000008 // interface is wireless (*NOT* necessarily Wi-Fi!) 
PCAP_IF_CONNECTION_STATUS :: 0x00000030 // connection status: 
PCAP_IF_CONNECTION_STATUS_UNKNOWN :: 0x00000000 // unknown 
PCAP_IF_CONNECTION_STATUS_CONNECTED :: 0x00000010 // connected 
PCAP_IF_CONNECTION_STATUS_DISCONNECTED :: 0x00000020 // disconnected 
PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE :: 0x00000030 // not applicable 

// Representation of an interface address
pcap_addr :: struct {
	next:      ^pcap_addr,
	addr:      ^os.SOCKADDR,
	netmask:   ^os.SOCKADDR,
	broadaddr: ^os.SOCKADDR,
	dstaddr:   ^os.SOCKADDR,
}

// Error codes for PCAP API 
// All negative cause #C things, success or fail on calls.
// check if return < 0 
PCAP_ERROR :: -1 // generic error code 
PCAP_ERROR_BREAK :: -2 // loop terminated by pcap_breakloop 
PCAP_ERROR_NOT_ACTIVATED :: -3 // the capture needs to be activated 
PCAP_ERROR_ACTIVATED :: -4 // the operation can't be performed on already activated captures 
PCAP_ERROR_NO_SUCH_DEVICE :: -5 // no such device exists 
PCAP_ERROR_RFMON_NOTSUP :: -6 // this device doesn't support rfmon (monitor) mode 
PCAP_ERROR_NOT_RFMON :: -7 // operation supported only in monitor mode 
PCAP_ERROR_PERM_DENIED :: -8 // no permission to open the device 
PCAP_ERROR_IFACE_NOT_UP :: -9 // interface isn't up 
PCAP_ERROR_CANTSET_TSTAMP_TYPE :: -10 // this device doesn't support setting the time stamp type 
PCAP_ERROR_PROMISC_PERM_DENIED :: -11 // you don't have permission to capture in promiscuous mode 
PCAP_ERROR_TSTAMP_PRECISION_NOTSUP :: -12 // the requested time stamp precision is not supported 

PCAP_ERRORS :: enum {
	GENERIC_ERROR           = -1, // generic error code 
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
PCAP_WARNING :: 1 // Generic warning code 
PCAP_WARNING_PROMISC_NOTSUP :: 2 // device doesn't support promisc mode 
PCAP_WARNING_TSTAMP_TYPE_NOTSUP :: 3 // timestype type is not supported

WARNING :: enum {
	GENERIC_WARNING    = 1,
	PROMISC_NOTSUP     = 2,
	TSTAMP_TYPE_NOTSUP = 3,
}

// Value to pass to pcap_compile() as the netmask if you don't 
// know what the netmask it!
PCAP_NETMASK_UNKNOWN :: 0xFFFFFFFF

// Initialisation Options:
// On UNIX systems local character encoding is assumed to be UTF-8
// On Windows, local character encoding is the local ansi code page. 

PCAP_CHAR_ENC_LOCAL: u32 : 0x00000000 // strings are in the local character encoding 
PCAP_CHAR_ENC_UTF_8: u32 : 0x00000001 // strings are in UTF-8
PCAP_MMAP_32BIT: u32 : 0x00000002 // map packet buffers with 32-bit addresses

timeval :: struct {
	tv_sec:  _c.long,
	tv_usec: _c.long,
}

pcap_pkthdr :: struct {
	ts:     timeval,
	caplen: bpf_u_int32,
	len:    bpf_u_int32,
}

when ODIN_OS == .Windows {
	pcap_stat :: struct {
		ps_recv:    _c.uint32_t,
		ps_drop:    _c.uint32_t,
		ps_ifdrop:  _c.uint32_t,
		ps_capt:    _c.uint32_t,
		ps_sent:    _c.uint32_t,
		ps_netdrop: _c.uint32_t,
	}
	// MSDOS pcap_stat_ex
	pcap_stat_ex :: struct {
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
	pcap_stat :: struct {
		ps_recv:   _c.uint32_t,
		ps_drop:   _c.uint32_t,
		ps_ifdrop: _c.uint32_t,
	}
}

pcap_rmtauth :: struct {
	type:     _c.int,
	username: cstring,
	password: cstring,
}

pcap_samp :: struct {
	method: _c.int,
	value:  _c.int,
}

pcap_options :: struct {} // "C.incomplete_type" 

@(default_calling_convention = "c", link_prefix = "pcap_")
foreign libpcap {
	init :: proc(opts: _c.uint, errbuf: [^]byte) -> _c.int ---

	// DEPRECATED use findalldevs instead
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

	loop :: proc(p: ^pcap_t, count: _c.int, callback: pcap_handler, user: [^]byte) -> _c.int ---

	dispatch :: proc(p: ^pcap_t, count: _c.int, callback: pcap_handler, user: [^]byte) -> _c.int ---

	next :: proc(p: ^pcap_t, pkt_hdr: ^pcap_pkthdr) -> ^[^]byte ---

	next_ex :: proc(p: ^pcap_t, pkt_hdr: ^^pcap_pkthdr, pkt_data: ^[^]byte) -> _c.int ---

	breakloop :: proc(p: ^pcap_t) ---

	stats :: proc(p: ^pcap_t, ps: ^pcap_stat) -> _c.int ---

	setfilter :: proc(p: ^pcap_t, fp: ^bpf_program) -> _c.int ---

	setdirection :: proc(p: ^pcap_t, direction: pcap_direction_t) -> _c.int ---

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

	offline_filter :: proc(fp: ^bpf_program, hdr: ^pcap_pkthdr, pkg: [^]byte) -> _c.int ---

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

	dump_open :: proc(p: ^pcap_t, fname: cstring) -> ^pcap_dumper_t ---

	dump_fopen :: proc(p: ^pcap_t, fp: ^libc.FILE) -> ^pcap_dumper_t ---

	dump_open_append :: proc(p: ^pcap_t, fname: cstring) -> ^pcap_dumper_t ---

	dump_file :: proc(p: ^pcap_dumper_t) -> ^libc.FILE ---

	dump_ftell :: proc(p: ^pcap_dumper_t) -> _c.long ---

	dump_ftell64 :: proc(p: ^pcap_dumper_t) -> i64 ---

	dump_flush :: proc(p: ^pcap_dumper_t) -> _c.int ---

	dump_close :: proc(p: ^pcap_dumper_t) ---

	dump :: proc(user: [^]byte, hdr: ^pcap_pkthdr, sp: [^]byte) ---

	findalldevs :: proc(alldevs_ptr: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---

	freealldevs :: proc(alldevs: ^pcap_if_t) ---

	lib_version :: proc() -> cstring ---

	get_selectable_fd :: proc(p: ^pcap_t) -> _c.int ---

	get_required_select_timeout :: proc(p: ^pcap_t) -> ^timeval ---

	open :: proc(source: cstring, snaplen: _c.int, flags: _c.int, read_timeout: _c.int, auth: ^pcap_rmtauth, errbuf: [^]byte) -> ^pcap_t ---

	createsrcstr :: proc(source: cstring, type: _c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	parsesrcstr :: proc(source: cstring, type: ^_c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	findalldevs_ex :: proc(source: cstring, auth: ^pcap_rmtauth, alldevs: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---

	setsampling :: proc(p: ^pcap_t) -> ^pcap_samp ---

	//	remoteact_accept :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^pcap_rmtauth, errbuf: [^]byte) -> SOCKET ---
	//	
	//	remoteact_accept_ex :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^pcap_rmtauth, uses_ssl: _c.int, errbuf: [^]byte) -> SOCKET ---

	remoteact_list :: proc(hostlist: cstring, sep: _c.char, size: _c.int, errbuf: [^]byte) -> _c.int ---

	remoteact_close :: proc(host: cstring, errbuf: [^]byte) -> _c.int ---

	remoteact_cleanup :: proc() ---

	alloc_option :: proc() -> ^pcap_options ---

	free_option :: proc(po: ^pcap_options) ---

	set_option_string :: proc(po: ^pcap_options, pon: pcap_option_name, value: cstring) -> _c.int ---

	set_option_int :: proc(po: ^pcap_options, pon: pcap_option_name, value: _c.int) -> _c.int ---

	get_option_string :: proc(po: ^pcap_options, pon: pcap_option_name) -> cstring ---

	get_option_int :: proc(po: ^pcap_options, pon: pcap_option_name) -> _c.int ---
}

// TODO: Move to its own file, might as well one to one the entire library
@(default_calling_convention = "c")
foreign _ {
	@(link_name = "bpf_filter")
	bpf_filter :: proc(pc: ^bpf_insn, pkt: [^]byte, wirelen: _c.uint32_t, buflen: _c.uint32_t) -> _c.uint32_t ---

	@(link_name = "bpf_validate")
	bpf_validate :: proc(fcode: ^bpf_insn, flen: _c.int) -> _c.int ---

	@(link_name = "bpf_image")
	bpf_image :: proc(pc: ^bpf_insn, arg: _c.int) -> cstring ---

	@(link_name = "bpf_dump")
	bpf_dump :: proc(p: ^bpf_program, arg: _c.int) ---
}