package odin_libpcap

import _c "core:c"
import "core:c/libc"

when ODIN_OS == .Windows {
	// WinPcap, NPcap are the options here.
	foreign import namedb "system:npcap" // 99% sure this is wrong, but placeholder
}
when ODIN_OS == .Linux {
	foreign import namedb "libpcap" // TODO: Put on a linux VM and check if .a needed
}
when ODIN_OS == .Darwin {
	// HACK: Ran into issues with it finding the dylib, so moved it into the folder..
	foreign import namedb "system:libpcap.A.dylib"
}

pcap_etherent :: struct {
	addr: [6]_c.uchar,
	name: [122]_c.char,
}

PROTO_UNDF :: -1

@(default_calling_convention = "c", link_prefix = "pcap_")
foreign namedb {
	next_ethernet :: proc(f: ^libc.FILE) -> pcap_etherent ---

	// TODO: Finish bindings.
	// u_char *pcap_ether_hostton(const char*);
	// u_char *pcap_ether_aton(const char *);
	// 
	// // DEPRECATED
	// bpf_u_int32 **pcap_nametoaddr(const char *);
	// 
	// struct addrinfo *pcap_nametoaddrinfo(const char *);
	// bpf_u_int32 pcap_nametonetaddr(const char *);
	// 
	// int	pcap_nametoport(const char *, int *, int *);
	// int	pcap_nametoportrange(const char *, int *, int *, int *);
	// int	pcap_nametoproto(const char *);
	// int	pcap_nametoeproto(const char *);
	// int	pcap_nametollc(const char *);

}
