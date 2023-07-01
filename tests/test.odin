package libpcap_tests

// Will require sudo / root / admin privs in most cases to connect to an interface
import pcap "../"
import "core:fmt"
import "core:strings"
import _t "core:testing"

@(test)
basic_find_devs :: proc(t: ^_t.T) {
	errbuf: [pcap.PCAP_ERRBUF_SIZE]byte
	interfaces: ^pcap.pcap_if_t

	err := pcap.findalldevs(&interfaces, &errbuf[0])
	if err == pcap.PCAP_ERROR {
		fmt.println(
			"Error while finding all devs: ",
			strings.string_from_ptr(&errbuf[0], len(errbuf)),
		)
		panic("findalldevs failed")
	}
	iface := interfaces
	fmt.println("Printing interfaces")
	for (iface != nil) {
		fmt.printf("Interface: %s ", iface.name)
		if iface.flags & pcap.PCAP_IF_UP == pcap.PCAP_IF_UP {
			fmt.printf("is UP\n")
		} else {
			fmt.printf("is DOWN\n")
		}
		iface = iface.next
	}

	pcap.freealldevs(interfaces)
}

@(test)
basic_capture :: proc(t: ^_t.T) {
	errbuf: [pcap.PCAP_ERRBUF_SIZE]byte
	interfaces: ^pcap.pcap_if_t
	header: ^pcap.pcap_pkthdr
	packet: [^]byte


	err := pcap.findalldevs(&interfaces, &errbuf[0])
	if err == pcap.PCAP_ERROR {
		fmt.println(
			"Error while finding all devs: ",
			strings.string_from_ptr(&errbuf[0], len(errbuf)),
		)
	}

	handler := pcap.open_live(interfaces.name, 512, true, 1000, &errbuf[0])

	PCAP_OKAY :: 1
	for i := 0; i < 5; i += 1 {
		err := pcap.next_ex(handler, &header, &packet)
		if err == PCAP_OKAY {
			fmt.println("TS: ", header.ts)
			fmt.println("Cap Len: ", header.caplen)
			fmt.println("Len: ", header.len)
			plen: u32 = 64
			if header.caplen < plen do plen = header.caplen
			for j: u32 = 0; j < plen; j += 1 {
				if (j % 16 == 0 && j != 0) {
					fmt.printf("%2X \n", packet[j])
				} else if (j % 8 == 0 && j != 0) {
					fmt.printf("%2X  ", packet[j])
				} else {
					fmt.printf("%2X ", packet[j])
				}
			}
			fmt.println()
		}
	}

	pcap.freealldevs(interfaces)
	pcap.close(handler)
}
