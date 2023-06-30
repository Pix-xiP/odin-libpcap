package odin_libpcap

// TODO: Add a when for each system - Linux, Windows etc.
when ODIN_OS == .Windows {
	foreign import libpcap "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import libpcap "libpcap" // TODO: Put on a linux VM and check if .a needed
}
when ODIN_OS == .Darwin {
	// HACK: Ran into issues with it finding the dylib, so moved it into the folder..
	foreign import libpcap "system:libpcap.A.dylib"
}

import _c "core:c"
import "core:c/libc"

#assert(size_of(b32) == size_of(_c.int)) // To Use later maybe for wrappers!

PCAP_ERRBUF_SIZE :: 256

bpf_int32 :: _c.int32_t
bpf_u_int32 :: _c.uint32_t
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

pcap :: struct {} // Opaque Structure... How to handle... TODO:

pcap_dumper :: struct {} // TODO: Define PCAP DUMPER

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
	addr:      ^sockaddr,
	netmask:   ^sockaddr,
	broadaddr: ^sockaddr,
	dstaddr:   ^sockaddr,
}

// Error codes for PCAP API 
// All negative cause #C things, success or fail on calls.
// check if return < 0 
// TODO: Turn this into an Enum or Error

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

// Warning codes for PCAP API 
// Warnings are positive so as not to clash with errors...
// TODO: Enum this 
PCAP_WARNING :: 1 // Generic warning code 
PCAP_WARNING_PROMISC_NOTSUP :: 2 // device doesn't support promisc mode 
PCAP_WARNING_TSTAMP_TYPE_NOTSUP :: 3 // timestype type is not supported

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

pcap_stat :: struct {
	ps_recv:   _c.uint32_t,
	ps_drop:   _c.uint32_t,
	ps_ifdrop: _c.uint32_t,
}

// TODO: When Windows:
// pcap_stat :: struct {
//  ps_capt: _c.uint32_t,
//  ps_sent: _c.uint32_t,
//  ps_netdrop: _c.uint32_t,
// }

// TODO: MSDOS - PCAP_STATS_EX

sockaddr :: struct {}

pcap_rmtauth :: struct {
	type:     _c.int,
	username: cstring,
	password: cstring,
}

pcap_samp :: struct {
	method: _c.int,
	value:  _c.int,
}

// TODO: Check.
bpf_insn :: struct {
	code: _c.ushort,
	jt:   _c.uchar,
	jf:   _c.uchar,
	k:    bpf_u_int32,
}

bpf_program :: struct {
	bf_len:   _c.uint32_t,
	bf_insns: ^bpf_insn,
}

pcap_options :: struct {} // TODO: Track down a definition for this..

@(default_calling_convention = "c")
foreign libpcap {

	@(link_name = "pcap_init")
	pcap_init :: proc(opts: _c.uint, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_lookupdev") // DEPRECATED use pcap_findalldevs instead
	pcap_lookupdev :: proc(errbuf: [^]byte) -> cstring ---

	@(link_name = "pcap_lookupnet")
	pcap_lookupnet :: proc(device: cstring, netp: ^bpf_u_int32, maskp: ^bpf_u_int32, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_create")
	pcap_create :: proc(source: cstring, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_set_snaplen")
	pcap_set_snaplen :: proc(p: ^pcap_t, snaplen: _c.int) -> _c.int ---

	@(link_name = "pcap_set_promisc")
	pcap_set_promisc :: proc(p: ^pcap_t, promisc: _c.int) -> _c.int ---

	@(link_name = "pcap_can_set_rfmon")
	pcap_can_set_rfmon :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_set_rfmon")
	pcap_set_rfmon :: proc(p: ^pcap_t, rfmon: _c.int) -> _c.int ---

	@(link_name = "pcap_set_timeout")
	pcap_set_timeout :: proc(p: ^pcap_t, to_ms: _c.int) -> _c.int ---

	@(link_name = "pcap_set_tstamp_type")
	pcap_set_tstamp_type :: proc(p: ^pcap_t, tstamp_type: _c.int) -> _c.int ---

	@(link_name = "pcap_set_immediate_mode")
	pcap_set_immediate_mode :: proc(p: ^pcap_t, immediate_mode: _c.int) -> _c.int ---

	@(link_name = "pcap_set_buffer_size")
	pcap_set_buffer_size :: proc(p: ^pcap_t, buffer_size: _c.int) -> _c.int ---

	@(link_name = "pcap_set_tstamp_precision")
	pcap_set_tstamp_precision :: proc(p: ^pcap_t, tstamp_precision: _c.int) -> _c.int ---

	@(link_name = "pcap_get_tstamp_precision")
	pcap_get_tstamp_precision :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_activate")
	pcap_activate :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_list_tstamp_types")
	pcap_list_tstamp_types :: proc(p: ^pcap_t, tstamp_typesp: ^^_c.int) -> _c.int ---

	@(link_name = "pcap_free_tstamp_types")
	pcap_free_tstamp_types :: proc(tstamp_types: ^_c.int) ---

	@(link_name = "pcap_tstamp_type_name_to_val")
	pcap_tstamp_type_name_to_val :: proc(name: cstring) -> _c.int ---

	@(link_name = "pcap_tstamp_type_val_to_name")
	pcap_tstamp_type_val_to_name :: proc(tstamp_type: _c.int) -> cstring ---

	@(link_name = "pcap_tstamp_type_val_to_description")
	pcap_tstamp_type_val_to_description :: proc(tstamp_type: _c.int) -> cstring ---

	@(link_name = "pcap_open_live")
	pcap_open_live :: proc(device: cstring, snaplen: _c.int, promisc: b32, to_ms: _c.int, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_open_dead")
	pcap_open_dead :: proc(linktype: _c.int, snaplen: _c.int) -> ^pcap_t ---

	@(link_name = "pcap_open_dead_with_tstamp_precision")
	pcap_open_dead_with_tstamp_precision :: proc(linktype: _c.int, snaplen: _c.int, precision: _c.uint32_t) -> ^pcap_t ---

	@(link_name = "pcap_open_offline_with_tstamp_precision")
	pcap_open_offline_with_tstamp_precision :: proc(savefile: cstring, precision: _c.uint32_t, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_open_offline")
	pcap_open_offline :: proc(savefile: cstring, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_fopen_offline_with_tstamp_precision")
	pcap_fopen_offline_with_tstamp_precision :: proc(fp: ^libc.FILE, precision: _c.uint32_t, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_fopen_offline")
	pcap_fopen_offline :: proc(fp: ^libc.FILE, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_close")
	pcap_close :: proc(p: ^pcap_t) ---

	@(link_name = "pcap_loop")
	pcap_loop :: proc(p: ^pcap_t, count: _c.int, callback: pcap_handler, user: [^]byte) -> _c.int ---

	@(link_name = "pcap_dispatch")
	pcap_dispatch :: proc(p: ^pcap_t, count: _c.int, callback: pcap_handler, user: [^]byte) -> _c.int ---

	@(link_name = "pcap_next")
	pcap_next :: proc(p: ^pcap_t, pkt_hdr: ^pcap_pkthdr) -> ^[^]byte ---

	@(link_name = "pcap_next_ex")
	pcap_next_ex :: proc(p: ^pcap_t, pkt_hdr: ^^pcap_pkthdr, pkt_data: ^[^]byte) -> _c.int ---

	@(link_name = "pcap_breakloop")
	pcap_breakloop :: proc(p: ^pcap_t) ---

	@(link_name = "pcap_stats")
	pcap_stats :: proc(p: ^pcap_t, ps: ^pcap_stat) -> _c.int ---

	@(link_name = "pcap_setfilter")
	pcap_setfilter :: proc(p: ^pcap_t, fp: ^bpf_program) -> _c.int ---

	@(link_name = "pcap_setdirection")
	pcap_setdirection :: proc(p: ^pcap_t, direction: pcap_direction_t) -> _c.int ---

	@(link_name = "pcap_getnonblock")
	pcap_getnonblock :: proc(p: ^pcap_t, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_setnonblock")
	pcap_setnonblock :: proc(p: ^pcap_t, nonblock: _c.int, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_inject") // NOTE: rawptr might actually need to be [^]byte same as pcap_sendpacket
	pcap_inject :: proc(p: ^pcap_t, buf: rawptr, size: _c.size_t) -> _c.int ---

	@(link_name = "pcap_sendpacket")
	pcap_sendpacket :: proc(p: ^pcap_t, buf: [^]byte, size: _c.int) -> _c.int ---

	@(link_name = "pcap_statustostr")
	pcap_statustostr :: proc(error: _c.int) -> cstring ---

	@(link_name = "pcap_strerror")
	pcap_strerror :: proc(error: _c.int) -> cstring ---

	@(link_name = "pcap_geterr")
	pcap_geterr :: proc(p: ^pcap_t) -> cstring ---

	@(link_name = "pcap_perror")
	pcap_perror :: proc(p: ^pcap_t, prefix: cstring) ---

	@(link_name = "pcap_compile")
	pcap_compile :: proc(p: ^pcap_t, fp: ^bpf_program, str: cstring, optimize: _c.int, netmask: bpf_u_int32) -> _c.int ---

	// @(link_name = "pcap_compile_nopcap") // Deprecated completely
	// pcap_compile_nopcap :: proc(: _c.int, unamed1: _c.int, unamed2: ^bpf_program, unamed3: cstring, unamed4: _c.int, unamed5: bpf_u_int32) -> _c.int ---

	@(link_name = "pcap_freecode")
	pcap_freecode :: proc(ptr: ^bpf_program) ---

	@(link_name = "pcap_offline_filter")
	pcap_offline_filter :: proc(fp: ^bpf_program, hdr: ^pcap_pkthdr, pkg: [^]byte) -> _c.int ---

	@(link_name = "pcap_datalink")
	pcap_datalink :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_datalink_ext")
	pcap_datalink_ext :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_list_datalinks")
	pcap_list_datalinks :: proc(p: ^pcap_t, dtlist_buf: ^^_c.int) -> _c.int ---

	@(link_name = "pcap_set_datalink")
	pcap_set_datalink :: proc(p: ^pcap_t, datalink: _c.int) -> _c.int ---

	@(link_name = "pcap_free_datalinks")
	pcap_free_datalinks :: proc(dlt_list: ^_c.int) ---

	@(link_name = "pcap_datalink_name_to_val")
	pcap_datalink_name_to_val :: proc(name: cstring) -> _c.int ---

	@(link_name = "pcap_datalink_val_to_name")
	pcap_datalink_val_to_name :: proc(value: _c.int) -> cstring ---

	@(link_name = "pcap_datalink_val_to_description")
	pcap_datalink_val_to_description :: proc(value: _c.int) -> cstring ---

	@(link_name = "pcap_datalink_val_to_description_or_dlt")
	pcap_datalink_val_to_description_or_dlt :: proc(value: _c.int) -> cstring ---

	@(link_name = "pcap_snapshot")
	pcap_snapshot :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_is_swapped")
	pcap_is_swapped :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_major_version")
	pcap_major_version :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_minor_version")
	pcap_minor_version :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_bufsize")
	pcap_bufsize :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_file")
	pcap_file :: proc(p: ^pcap_t) -> ^libc.FILE ---

	@(link_name = "pcap_fileno")
	pcap_fileno :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_dump_open")
	pcap_dump_open :: proc(p: ^pcap_t, fname: cstring) -> ^pcap_dumper_t ---

	@(link_name = "pcap_dump_fopen")
	pcap_dump_fopen :: proc(p: ^pcap_t, fp: ^libc.FILE) -> ^pcap_dumper_t ---

	@(link_name = "pcap_dump_open_append")
	pcap_dump_open_append :: proc(p: ^pcap_t, fname: cstring) -> ^pcap_dumper_t ---

	@(link_name = "pcap_dump_file")
	pcap_dump_file :: proc(p: ^pcap_dumper_t) -> ^libc.FILE ---

	@(link_name = "pcap_dump_ftell")
	pcap_dump_ftell :: proc(p: ^pcap_dumper_t) -> _c.long ---

	@(link_name = "pcap_dump_ftell64")
	pcap_dump_ftell64 :: proc(p: ^pcap_dumper_t) -> i64 ---

	@(link_name = "pcap_dump_flush")
	pcap_dump_flush :: proc(p: ^pcap_dumper_t) -> _c.int ---

	@(link_name = "pcap_dump_close")
	pcap_dump_close :: proc(p: ^pcap_dumper_t) ---

	@(link_name = "pcap_dump")
	pcap_dump :: proc(user: [^]byte, hdr: ^pcap_pkthdr, sp: [^]byte) ---

	@(link_name = "pcap_findalldevs")
	pcap_findalldevs :: proc(alldevs_ptr: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_freealldevs")
	pcap_freealldevs :: proc(alldevs: ^pcap_if_t) ---

	@(link_name = "pcap_lib_version")
	pcap_lib_version :: proc() -> cstring ---

	@(link_name = "pcap_get_selectable_fd")
	pcap_get_selectable_fd :: proc(p: ^pcap_t) -> _c.int ---

	@(link_name = "pcap_get_required_select_timeout")
	pcap_get_required_select_timeout :: proc(p: ^pcap_t) -> ^timeval ---

	@(link_name = "pcap_open")
	pcap_open :: proc(source: cstring, snaplen: _c.int, flags: _c.int, read_timeout: _c.int, auth: ^pcap_rmtauth, errbuf: [^]byte) -> ^pcap_t ---

	@(link_name = "pcap_createsrcstr")
	pcap_createsrcstr :: proc(source: cstring, type: _c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_parsesrcstr")
	pcap_parsesrcstr :: proc(source: cstring, type: ^_c.int, host: cstring, port: cstring, name: cstring, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_findalldevs_ex")
	pcap_findalldevs_ex :: proc(source: cstring, auth: ^pcap_rmtauth, alldevs: ^^pcap_if_t, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_setsampling")
	pcap_setsampling :: proc(p: ^pcap_t) -> ^pcap_samp ---

	//	@(link_name = "pcap_remoteact_accept")
	//	pcap_remoteact_accept :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^pcap_rmtauth, errbuf: [^]byte) -> SOCKET ---
	//
	//	@(link_name = "pcap_remoteact_accept_ex")
	//	pcap_remoteact_accept_ex :: proc(address: cstring, port: cstring, hostlist: cstring, connectinghost: cstring, auth: ^pcap_rmtauth, uses_ssl: _c.int, errbuf: [^]byte) -> SOCKET ---

	@(link_name = "pcap_remoteact_list")
	pcap_remoteact_list :: proc(hostlist: cstring, sep: _c.char, size: _c.int, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_remoteact_close")
	pcap_remoteact_close :: proc(host: cstring, errbuf: [^]byte) -> _c.int ---

	@(link_name = "pcap_remoteact_cleanup")
	pcap_remoteact_cleanup :: proc() ---

	@(link_name = "pcap_alloc_option")
	pcap_alloc_option :: proc() -> ^pcap_options ---

	@(link_name = "pcap_free_option")
	pcap_free_option :: proc(po: ^pcap_options) ---

	@(link_name = "pcap_set_option_string")
	pcap_set_option_string :: proc(po: ^pcap_options, pon: pcap_option_name, value: cstring) -> _c.int ---

	@(link_name = "pcap_set_option_int")
	pcap_set_option_int :: proc(po: ^pcap_options, pon: pcap_option_name, value: _c.int) -> _c.int ---

	@(link_name = "pcap_get_option_string")
	pcap_get_option_string :: proc(po: ^pcap_options, pon: pcap_option_name) -> cstring ---

	@(link_name = "pcap_get_option_int")
	pcap_get_option_int :: proc(po: ^pcap_options, pon: pcap_option_name) -> _c.int ---

	@(link_name = "bpf_filter")
	bpf_filter :: proc(pc: ^bpf_insn, pkt: [^]byte, wirelen: _c.uint32_t, buflen: _c.uint32_t) -> _c.uint32_t ---

	@(link_name = "bpf_validate")
	bpf_validate :: proc(fcode: ^bpf_insn, flen: _c.int) -> _c.int ---

	@(link_name = "bpf_image")
	bpf_image :: proc(pc: ^bpf_insn, arg: _c.int) -> cstring ---

	@(link_name = "bpf_dump")
	bpf_dump :: proc(p: ^bpf_program, arg: _c.int) ---
}
