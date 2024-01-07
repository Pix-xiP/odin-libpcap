# Odin Libpcap!
----

General bindings for using the libpcap library on Linux, Mac and theoretically NPcap on Windows (untested)

Everything should be converted from the standard libpcap headers. Not everything has been completely tested, happy to fix errors as they pop up!

## Converted Files:
-----
- [x] bluetooth.odin 
- [x] bpf.odin
- [x] can_socketcan.odin 
- [x] dlt.odin
- [x] ipnet.odin 
- [x] namedb.odin
- [x] nflog.odin
- [x] pcap.odin
- [x] sll.odin 
- [x] usb.odin
- [x] vlan.odin

Tests inside tests/... will be expanded upon to clear everything as I get time..

## Notes:

I have not added the function attrs to each to show which func is available where - I don't plan to but if someone wants to go through and add decorators etc, I'm happy to merge
