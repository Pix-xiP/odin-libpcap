package odin_libpcap

import _c "core:c"
import "core:c/libc"
import "core:os"

when ODIN_OS == .Windows {
	// WinPcap, NPcap are the options here.
	foreign import namedb "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import namedb "system:pcap"
}
when ODIN_OS == .Darwin {
	foreign import namedb "system:pcap"
}

pcap_etherent :: struct {
	addr: [6]_c.uchar,
	name: [122]_c.char,
}
// TODO: Check for this in Core?
addrinfo :: struct {
	ai_flags:     _c.int, //AI_PASSIVE, AI_CANONNAME 
	ai_family:    _c.int, // PF_xxx
	ai_socktype:  _c.int, // SOCK_xxx 
	ai_protocol:  _c.int, // 0 or IPPROTO_xxx for IPv4 and IPv6
	ai_addrlen:   _c.size_t, // length of ai_addr 
	ai_canonname: cstring, // TODO: CHECK // canonical name for hostname 
	ai_addr:      ^os.SOCKADDR, // binary address 
	ai_next:      ^addrinfo, // next structure in linked list
}

PROTO_UNDF :: -1

@(default_calling_convention = "c", link_prefix = "pcap_")
foreign namedb {
	next_ethernet :: proc(f: ^libc.FILE) -> pcap_etherent ---

	ether_hostton :: proc(name: cstring) -> ^_c.uchar ---

	ether_aton :: proc(s: cstring) -> ^_c.uchar ---

	@(deprecated = "'pcap_nametoaddr' is deprecated. Use 'nametoaddrinfo' instead")
	nametoaddr :: proc(name: cstring) -> ^^bpf_u_int32 ---

	nametoaddrinfo :: proc(name: cstring) -> addrinfo ---

	nametonetaddr :: proc(name: cstring) -> _c.uint32_t ---

	nametoport :: proc(name: cstring, port: ^_c.int, proto: ^_c.int) -> _c.int ---

	nametoportrange :: proc(name: cstring, portmin: ^_c.int, portmax: ^_c.int, proto: ^_c.int) -> _c.int ---

	nametoproto :: proc(name: cstring) -> _c.int ---

	nametoeproto :: proc(name: cstring) -> _c.int ---

	nametollc :: proc(name: cstring) -> _c.int ---
}
