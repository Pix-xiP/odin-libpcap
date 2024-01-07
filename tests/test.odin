package libpcap_tests

// Will require sudo / root / admin privs in most cases to connect to an interface
import pcap "../"
import "core:fmt"
import "core:net"
import "core:os"
import ss "core:strings"
import _t "core:testing"

@(test)
basic_find_devs :: proc(t: ^_t.T) {
	errbuf: [pcap.ERRBUF_SIZE]byte
	interfaces: ^pcap.pcap_if_t

	err := pcap.findalldevs(&interfaces, &errbuf[0])
	if err == pcap.ERRORS.GENERIC {
		fmt.println("Error while finding all devs: ", ss.string_from_ptr(&errbuf[0], len(errbuf)))
		panic("findalldevs failed")
	}
	for i := interfaces; i != nil; i = i.next {
		fmt.printf("Interface: %s - ", i.name)
		for a := i.addresses; a != nil; a = a.next {
			if cast(int)a.addr.sa_family == os.AF_INET {
				sock_in := cast(^os.sockaddr_in)a.addr
				ip4 := net.IP4_Address(transmute([4]u8)sock_in.sin_addr.s_addr)
				fmt.printf(ntoa(ip4))
			}
		}
		if (i.flags & pcap.IF_UP == pcap.IF_UP) {
			fmt.printf(" - is UP")
		} else {
			fmt.printf(" - is DOWN")
		}
		fmt.printf("\n")
	}


	pcap.freealldevs(interfaces)
}

// Will need sudo privs on linux to access the interfaces for opening.
@(test)
basic_capture :: proc(t: ^_t.T) {
	errbuf: [pcap.ERRBUF_SIZE]byte
	interfaces: ^pcap.pcap_if_t
	header: ^pcap.pkthdr
	packet: [^]byte


	err := pcap.findalldevs(&interfaces, &errbuf[0])
	if err == pcap.ERRORS.GENERIC {
		fmt.println("Error while finding all devs: ", ss.string_from_ptr(&errbuf[0], len(errbuf)))
	}

	name: cstring = nil
	for i := interfaces; i != nil; i = i.next {
		for a := i.addresses; a != nil; a = a.next {
			if ss.compare(string(i.name), "eno1") == 0 {
				name = i.name
			}
		}
	}

	handler := pcap.open_live(name, 512, true, 1000, &errbuf[0])
	if handler == nil {
		fmt.println("Handler returned nil, you probably don't have permission to open.")
		fmt.println(string(errbuf[:]))
	}

	for i := 0; i < 5; i += 1 {
		err := pcap.next_ex(handler, &header, &packet)
		if err == pcap.OKAY {
			fmt.println("TS: ", header.ts)
			fmt.println("Cap Len: ", header.caplen)
			fmt.println("Len: ", header.len)
			plen: u32 = 64 // only the first 64 for testing purposes.
			if header.caplen < plen do plen = header.caplen

			for j: u32 = 0; j < plen; j += 1 {
				if (j + 1) % 16 == 0 && j != 0 {
					fmt.printf("%02X \n", packet[j])
				} else if (j + 1) % 8 == 0 && j != 0 {
					fmt.printf("%02X  ", packet[j])
				} else {
					fmt.printf("%02X ", packet[j])
				}
			}
			fmt.println()
		}
	}

	pcap.freealldevs(interfaces)
	pcap.close(handler)
}

// @(test)
// bpf_compile_trial :: proc(t: ^_t.T) {
// 	errbuf: [pcap.ERRBUF_SIZE]byte
// 	interfaces: ^pcap.pcap_if_t
//
// 	err := pcap.findalldevs(&interfaces, &errbuf[0])
//
// }

ntoa_raw :: proc(in_addr: u32, allocator := context.allocator, loc := #caller_location) -> string {
	arr := transmute([4]u8)in_addr
	addr := fmt.aprintf("%d.%d.%d.%d", arr[0], arr[1], arr[2], arr[3])
	return addr
}

ntoa_ip4 :: proc(
	in_addr: net.IP4_Address,
	allocator := context.allocator,
	loc := #caller_location,
) -> string {
	addr := fmt.aprintf("%d.%d.%d.%d", in_addr[0], in_addr[1], in_addr[2], in_addr[3])
	return addr
}

ntoa_ip6 :: proc(
	in_addr: net.IP6_Address,
	allocator := context.allocator,
	loc := #caller_location,
) {
	unreachable()

}

ntoa :: proc {
	ntoa_ip6,
	ntoa_ip4,
	ntoa_raw,
}

main :: proc() {

}
