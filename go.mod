module github.com/takehaya/goxdp-template

go 1.21

require (
	github.com/cilium/ebpf v0.12.3
	github.com/google/go-cmp v0.5.9
	github.com/google/gopacket v1.1.19
	github.com/pkg/errors v0.9.1
	github.com/urfave/cli v1.22.5
	github.com/vishvananda/netlink v1.1.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.14.1-0.20231108175955-e4099bfacb8c // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/x86taka/gopacket v0.0.0-20231210055638-74b4deb65353
