#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

// vlan header
struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

// tcp options
struct tcpopt {
  __u8 kind;
  __u8 len;
};

// EtherIP header
struct etherip_hdr {
  __u8 etherip_ver;
  __u8 etherip_pad;
};

#endif  // XDP_PROG_H
