module github.com/x86taka/xdp-etherip

go 1.21

require (
	github.com/cilium/ebpf v0.16.0
	github.com/google/go-cmp v0.6.0
	github.com/google/gopacket v1.1.19
	github.com/pkg/errors v0.9.1
	github.com/urfave/cli v1.22.14
	github.com/vishvananda/netlink v1.1.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/exp v0.0.0-20240119083558-1b970713d09a // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/x86taka/gopacket v0.0.0-20231210055638-74b4deb65353
