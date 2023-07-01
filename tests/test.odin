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
