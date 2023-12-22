package coreelf_test

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
)

var payload = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func generateIPv4TCPInput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolTCP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
		SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
	}
	tcph := &layers.TCP{
		Seq:     0x00000000,
		SYN:     true,
		Ack:     0x00000000,
		SrcPort: 1234,
		DstPort: 80,
		Options: []layers.TCPOption{
			//TCP MSS Option (1460)
			{
				OptionType:   0x02,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4},
			},
			{
				OptionType:   0x04,
				OptionLength: 2,
			},
			{
				OptionType:   0x08,
				OptionLength: 10,
				OptionData:   []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			},
			{
				OptionType:   0x01,
				OptionLength: 1,
			},
			{
				OptionType:   0x01,
				OptionLength: 1,
			},
		},
	}
	tcph.SetNetworkLayerForChecksum(iph)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		iph,
		tcph,
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func generateIPv4TCPOutput(t *testing.T) []byte {

	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()

	ip6h := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolEtherIP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("fe80::2"),
	}
	eiph := &layers.EtherIP{
		Version:  3,
		Reserved: 0,
	}
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolTCP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
		SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
	}
	tcph := &layers.TCP{
		Seq:     0x00000000,
		SYN:     true,
		Ack:     0x00000000,
		SrcPort: 1234,
		DstPort: 80,
		Options: []layers.TCPOption{
			//TCP MSS Option (1460 => 1404)
			{
				OptionType:   0x02,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0x7c},
			},
			{
				OptionType:   0x04,
				OptionLength: 2,
			},
			{
				OptionType:   0x08,
				OptionLength: 10,
				OptionData:   []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			},
			{
				OptionType:   0x01,
				OptionLength: 1,
			},
			{
				OptionType:   0x01,
				OptionLength: 1,
			},
		},
	}

	tcph.SetNetworkLayerForChecksum(iph)
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x60, 0xb9, 0xe6, 0x20, 0xfb}, SrcMAC: []byte{0xbe, 0xfd, 0x30, 0xae, 0x56, 0xb9}, EthernetType: layers.EthernetTypeIPv6},
		ip6h, eiph,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		iph,
		tcph,
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

type XdpMd struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

func ebpfTestRun(input []byte, prog *ebpf.Program, xdpctx XdpMd) (uint32, []byte, error) {
	xdpOut := XdpMd{}
	var output []byte
	if len(input) > 0 {
		output = make([]byte, len(input)+256+2)
	}
	opts := ebpf.RunOptions{
		Data:       input,
		DataOut:    output,
		Context:    xdpctx,
		ContextOut: &xdpOut,
	}
	ret, err := prog.Run(&opts)
	if err != nil {
		return ret, nil, fmt.Errorf("test program: %w", err)
	}
	return ret, opts.DataOut, nil
}

func TestXDPProg(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs, err := coreelf.ReadCollection()
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%+v\n", verr)
		} else {
			t.Fatal(err)
		}
	}
	defer objs.Close()

	input := generateIPv4TCPInput(t)
	xdpmd := XdpMd{
		Data:           0,
		DataEnd:        uint32(len(input)),
		IngressIfindex: 3,
	}

	ret, got, err := ebpfTestRun(input, objs.XdpProg, xdpmd)
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_REDIRECT
	if ret != 4 {
		t.Errorf("got %d want %d", ret, 4)
	}

	// check output
	want := generateIPv4TCPOutput(t)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Logf("input: %x", input)
		t.Logf("output: %x", got)
		t.Logf("wantoutput: %x", want)
		t.Errorf("output mismatch (-want +got):\n%s", diff)
	}
}
