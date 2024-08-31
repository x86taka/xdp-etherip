# XDP-EtherIP

Implementation of EtherIP with XDP

Supported Features

- [x] Ether over IPv6
- [x] TCP MSS Clamping

## Build

In modern Linux systems, `bpf_helper_defs.h` is expected to be built. By running the following script, it will fetch the necessary kernel code. Please ensure you use the script according to your kernel version.

```shell
./gen_bpf_helper.sh
```

Install development packages

```shell
sudo apt install clang llvm libelf-dev build-essential linux-headers-$(uname -r) linux-libc-dev libbpf-dev gcc-multilib clang-format
```

Let's build Go & eBPF

```shell
make
```

## Run

```shell
./bin/xdp-etherip

# Use options
./bin/xdp-etherip --device eth2 --device eth3
```

## Test

```shell
make test
```
