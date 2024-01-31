#include "xdp_prog.h"

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

static __always_inline void update_checksum(uint16_t *csum, uint16_t old_val,
                                            uint16_t new_val) {
  uint32_t new_csum_value;
  uint32_t new_csum_comp;
  uint32_t undo;

  undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
  new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
  new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  *csum = (uint16_t)~new_csum_comp;
}

static __always_inline int update_tcp_mss(void *data, void *data_end,
                                          int new_mss_int) {
  struct tcphdr *old_tcp_header;
  old_tcp_header = data;
  if (data + sizeof(struct tcphdr) > data_end) {
    return 1;
  }
  // if SYN
  if (old_tcp_header->syn == 1) {
    data += sizeof(struct tcphdr);
  }
  struct tcpopt *old_tcp_options;
  old_tcp_options = data;
  if (data + sizeof(struct tcpopt) > data_end) {
    return 1;
  }
  // if MSS
  if (old_tcp_options->kind == 2 && old_tcp_options->len == 4) {
    data += sizeof(struct tcpopt);
    uint16_t *old_mss;
    old_mss = data;
    if (data + sizeof(uint16_t) > data_end) {
      return 1;
    }
    uint16_t old_mss_value = *old_mss;
    // if old mss > new mss
    if (ntohs(*old_mss) > new_mss_int) {
      // set new mss
      uint16_t new_mss = htons(new_mss_int);
      __builtin_memcpy(old_mss, &new_mss, sizeof(uint16_t));
      // recalc checksum
      update_checksum(&old_tcp_header->check, old_mss_value, new_mss);
    }
  }
  return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *cpy_ether_header;
  struct ethhdr *ether_header;
  struct ipv6hdr *ip6_header;
  ether_header = data;

  if (data + sizeof(*ether_header) > data_end) {
    return XDP_ABORTED;
  }
  /*

  Decap !!

  */

  uint16_t h_proto = ether_header->h_proto;

  if (h_proto == htons(ETH_P_IPV6)) {  // Is IPv6 Packet

    data += sizeof(*ether_header);
    ip6_header = data;
    if (data + sizeof(*ip6_header) + 2 > data_end) {
      return XDP_ABORTED;
    }
    // Is EtherIP Packet
    if (ip6_header->nexthdr == 97) {
      data += sizeof(*ip6_header) + 2;
      if (data + sizeof(*ip6_header) + 2 > data_end) {
        return XDP_ABORTED;
      }
      struct ethhdr *etherip_ether_header;
      etherip_ether_header = data;

      bpf_xdp_adjust_head(ctx, sizeof(*ether_header) + sizeof(*ip6_header) + 2);
      bpf_redirect(3, 0);
      return XDP_REDIRECT;
    }
  }

  /*

  Encap !!!

  */

  if (ctx->ingress_ifindex == 3) {
    data += sizeof(*ether_header);

    uint16_t length = sizeof(ether_header);

    //  add EtherIP over ipv6 Header
    struct ethhdr *output_ethernet_header;
    struct ipv6hdr *etherip_tunnel_ip6_header;
    struct in6_addr etherip_tunnel_ip6_saddr;
    struct in6_addr etherip_tunnel_ip6_daddr;

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct ethhdr) -
                                     (int)sizeof(struct ipv6hdr) -
                                     (int)sizeof(struct etherip_hdr))) {
      return XDP_ABORTED;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // New Ethernet Header

    if (data + sizeof(struct ethhdr) > data_end) {
      return XDP_ABORTED;
    }

    output_ethernet_header = data;
    // set Mac Addresses
    uint8_t dmac[6] = {0x00, 0x60, 0xb9, 0xe6, 0x20, 0xfb};
    uint8_t smac[6] = {0xbe, 0xfd, 0x30, 0xae, 0x56, 0xb9};
    output_ethernet_header->h_proto = htons(ETH_P_IPV6);
    __builtin_memcpy(output_ethernet_header->h_dest, dmac, sizeof(dmac));
    __builtin_memcpy(output_ethernet_header->h_source, smac, sizeof(smac));

    // IPv6 Header
    data += sizeof(struct ethhdr);
    if (data + sizeof(struct ipv6hdr) > data_end) {
      return XDP_ABORTED;
    }

    etherip_tunnel_ip6_header = data;
    etherip_tunnel_ip6_header->version = 6;
    etherip_tunnel_ip6_header->priority = 0;
    etherip_tunnel_ip6_header->nexthdr = 97;
    etherip_tunnel_ip6_header->hop_limit = 64;
    uint8_t saddr[16] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    __builtin_memcpy(etherip_tunnel_ip6_saddr.s6_addr, saddr, sizeof(saddr));
    etherip_tunnel_ip6_header->saddr = etherip_tunnel_ip6_saddr;
    uint8_t daddr[16] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    __builtin_memcpy(etherip_tunnel_ip6_daddr.s6_addr, daddr, sizeof(daddr));
    etherip_tunnel_ip6_header->daddr = etherip_tunnel_ip6_daddr;

    // EtherIP Header
    data += sizeof(struct ipv6hdr);

    struct etherip_hdr *etherip_header;
    etherip_header = data;
    if (data + sizeof(struct etherip_hdr) > data_end) {
      return XDP_ABORTED;
    }
    etherip_header->etherip_ver = 0x30;
    etherip_header->etherip_pad = 0x00;

    etherip_tunnel_ip6_header->payload_len = htons(data_end - data);

    data += sizeof(struct etherip_hdr);
    struct ethhdr *old_ether_header;
    old_ether_header = data;
    if (data + sizeof(struct ethhdr) > data_end) {
      return XDP_ABORTED;
    }

    /*

     TCP adjust MSS

    */

    // if IPv4
    if (old_ether_header->h_proto == htons(ETH_P_IP)) {
      data += sizeof(struct ethhdr);
      struct iphdr *old_ip_header;
      old_ip_header = data;
      if (data + sizeof(struct iphdr) > data_end) {
        return XDP_ABORTED;
      }

      // if TCP
      if (old_ip_header->protocol == 6) {
        data += sizeof(struct iphdr);
        if (update_tcp_mss(data, data_end, 1404)) {
          return XDP_ABORTED;
        }
      }
    }
    // if IPv6
    if (old_ether_header->h_proto == htons(ETH_P_IPV6)) {
      data += sizeof(struct ethhdr);
      struct ipv6hdr *old_ip6_header;
      old_ip6_header = data;
      if (data + sizeof(struct ipv6hdr) > data_end) {
        return XDP_ABORTED;
      }
      // if TCP
      if (old_ip6_header->nexthdr == 6) {
        data += sizeof(struct ipv6hdr);
        if (update_tcp_mss(data, data_end, 1384) == 1) {
          return XDP_ABORTED;
        }
      }
    }
    bpf_redirect(2, 0);
    return XDP_REDIRECT;
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
