#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdatomic.h>
#include <arpa/inet.h>

#include <linux/bpf.h>
#include "../libbpf/src/bpf_helpers.h"

#define MAX_TCP_OPTIONS 10

struct tcpopt
{
  __u8 kind;
  __u8 len;
};

struct etherip_hdr
{
  __u8 etherip_ver;
  __u8 etherip_pad;
};

struct vlan_hdr
{
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

static __always_inline void update_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
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
SEC("xdp")
int program(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *cpy_ether_header;
  struct ethhdr *ether_header;
  struct ipv6hdr *ip6_header;
  ether_header = data;

  if (data + sizeof(*ether_header) > data_end)
  {
    return XDP_ABORTED;
  }
  /*

  Decap !!

  */

  uint16_t h_proto = ether_header->h_proto;

  if (h_proto == htons(ETH_P_IPV6))
  { // Is IPv6 Packet

    data += sizeof(*ether_header);
    ip6_header = data;
    if (data + sizeof(*ip6_header) + 2 > data_end)
    {
      return XDP_ABORTED;
    }
    // Is EtherIP Packet
    if (ip6_header->nexthdr == 97)
    {
      data += sizeof(*ip6_header) + 2;
      if (data + sizeof(*ip6_header) + 2 > data_end)
      {
        return XDP_ABORTED;
      }
      struct ethhdr *etherip_ether_header;
      etherip_ether_header = data;

      bpf_xdp_adjust_head(ctx, sizeof(*ether_header) + sizeof(*ip6_header) + 2);
      bpf_redirect(3, 0);
      return XDP_REDIRECT;
      // return XDP_TX;
    }
  }

  /*

  Encap !!!

  */

  // Check ifindex
  // if (ether_header->h_proto == htons(ETH_P_8021Q))
  if (ctx->ingress_ifindex == 3)
  {
    // Encap if vlan header available

    data += sizeof(*ether_header);
    /*
    struct vlan_hdr *vlan_header;
    vlan_header = data;
    if (data + sizeof(*vlan_header) > data_end)
    {
      return XDP_ABORTED;
    }
    */

    uint16_t length = sizeof(ether_header);

    //  add EtherIP over ipv6 Header
    struct ethhdr *output_ethernet_header;
    struct ipv6hdr *etherip_tunnel_ip6_header;
    struct in6_addr etherip_tunnel_ip6_saddr;
    struct in6_addr etherip_tunnel_ip6_daddr;

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct ethhdr) - (int)sizeof(struct ipv6hdr) - (int)sizeof(struct etherip_hdr)))
    {
      return XDP_ABORTED;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // New Ethernet Header

    if (data + sizeof(struct ethhdr) > data_end)
    {
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
    if (data + sizeof(struct ipv6hdr) > data_end)
    {
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
    if (data + sizeof(struct etherip_hdr) > data_end)
    {
      return XDP_ABORTED;
    }
    etherip_header->etherip_ver = 0x30;
    etherip_header->etherip_pad = 0x00;

    etherip_tunnel_ip6_header->payload_len = htons(data_end - data);

    data += sizeof(struct etherip_hdr);
    struct ethhdr *old_ether_header;
    old_ether_header = data;
    if (data + sizeof(struct ethhdr) > data_end)
    {
      return XDP_ABORTED;
    }

    /*

     TCP adjust MSS

    */

    // if IPv4
    if (old_ether_header->h_proto == htons(ETH_P_IP))
    {
      data += sizeof(struct ethhdr);
      struct iphdr *old_ip_header;
      old_ip_header = data;
      if (data + sizeof(struct iphdr) > data_end)
      {
        return XDP_ABORTED;
      }

      // if TCP
      if (old_ip_header->protocol == 6)
      {
        data += sizeof(struct iphdr);
        struct tcphdr *old_tcp_header;
        old_tcp_header = data;
        if (data + sizeof(struct tcphdr) > data_end)
        {
          return XDP_ABORTED;
        }
        // if SYN
        if (old_tcp_header->syn == 1)
        {
          data += sizeof(struct tcphdr);
          struct tcpopt *old_tcp_options;
          old_tcp_options = data;
          if (data + sizeof(struct tcpopt) > data_end)
          {
            return XDP_ABORTED;
          }
          // if MSS
          if (old_tcp_options->kind == 2 && old_tcp_options->len == 4)
          {
            data += sizeof(struct tcpopt);
            uint16_t *old_mss;
            old_mss = data;
            if (data + sizeof(uint16_t) > data_end)
            {
              return XDP_ABORTED;
            }
            uint16_t old_mss_value = *old_mss;
            // if MSS > 1404
            if (ntohs(*old_mss) > 1404)
            {
              // set MSS 1404
              uint16_t new_mss = htons(1404);
              __builtin_memcpy(old_mss, &new_mss, sizeof(uint16_t));
              // recalc checksum

              update_checksum(&old_tcp_header->check, old_mss_value, htons(1404));
            }
          }
        }
      }
    }
    // if IPv6
    if (old_ether_header->h_proto == htons(ETH_P_IPV6))
    {
      data += sizeof(struct ethhdr);
      struct ipv6hdr *old_ip6_header;
      old_ip6_header = data;
      if (data + sizeof(struct ipv6hdr) > data_end)
      {
        return XDP_ABORTED;
      }
      // if TCP
      if (old_ip6_header->nexthdr == 6)
      {
        data += sizeof(struct ipv6hdr);
        struct tcphdr *old_tcp_header;
        old_tcp_header = data;
        if (data + sizeof(struct tcphdr) + 4 > data_end)
        {
          return XDP_ABORTED;
        }
        // if SYN
        if (old_tcp_header->syn == 1)

        {
          data += sizeof(struct tcphdr);
          struct tcpopt *old_tcp_options;
          old_tcp_options = data;
          if (data + sizeof(struct tcpopt) > data_end)
          {
            return XDP_ABORTED;
          }
          // if MSS
          if (old_tcp_options->kind == 2 && old_tcp_options->len == 4)
          {
            data += sizeof(struct tcpopt);
            uint16_t *old_mss;
            old_mss = data;
            if (data + sizeof(uint16_t) > data_end)
            {
              return XDP_ABORTED;
            }
            uint16_t old_mss_value = *old_mss;
            // if MSS > 1404
            if (ntohs(*old_mss) > 1404)
            {
              // set MSS 1404
              uint16_t new_mss = htons(1404);
              __builtin_memcpy(old_mss, &new_mss, sizeof(uint16_t));
              // recalc checksum
              update_checksum(&old_tcp_header->check, old_mss_value, htons(1404));
            }
          }
        }
      }
    }

    bpf_redirect(2, 0);
    return XDP_REDIRECT;
    // return XDP_TX;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";