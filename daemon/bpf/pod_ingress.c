// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "maps.h"

#define ETH_P_IP 0x0800
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

static __always_inline int load_l4_info(struct __sk_buff *skb,
                                        const struct iphdr *iph,
                                        __u16 *src_port, __u16 *dst_port,
                                        __u32 *l4_off, __u32 *check_off,
                                        bool *skip_l4_csum) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return TC_ACT_SHOT;

  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return TC_ACT_OK;

  *l4_off = sizeof(struct ethhdr) + ihl * 4;
  *skip_l4_csum = false;

  if (iph->protocol == IPPROTO_TCP) {
    struct {
      __be16 source;
      __be16 dest;
    } ports;
    if (bpf_skb_load_bytes(skb, *l4_off, &ports, sizeof(ports)) < 0)
      return TC_ACT_SHOT;

    *src_port = bpf_ntohs(ports.source);
    *dst_port = bpf_ntohs(ports.dest);
    *check_off = *l4_off + __builtin_offsetof(struct tcphdr, check);
    return TC_ACT_OK;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr udp = {};
    if (bpf_skb_load_bytes(skb, *l4_off, &udp, sizeof(udp)) < 0)
      return TC_ACT_SHOT;

    *src_port = bpf_ntohs(udp.source);
    *dst_port = bpf_ntohs(udp.dest);
    *check_off = *l4_off + __builtin_offsetof(struct udphdr, check);
    *skip_l4_csum = udp.check == 0;
    return TC_ACT_OK;
  }

  return TC_ACT_OK;
}

static __always_inline int rewrite_service_nat(struct __sk_buff *skb,
                                               __u32 l4_off,
                                               bool rewrite_src,
                                               __u32 check_off,
                                               bool skip_l4_csum,
                                               __u32 old_addr_host,
                                               __u32 new_addr_host,
                                               __u16 old_port_host,
                                               __u16 new_port_host) {
  if (old_addr_host != new_addr_host) {
    __be32 old_addr = bpf_htonl(old_addr_host);
    __be32 new_addr = bpf_htonl(new_addr_host);

    if (bpf_l3_csum_replace(skb,
                            sizeof(struct ethhdr) +
                                __builtin_offsetof(struct iphdr, check),
                            old_addr, new_addr, sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;

    if (!skip_l4_csum &&
        bpf_l4_csum_replace(skb, check_off, old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;
  }

  if (old_port_host != new_port_host && !skip_l4_csum &&
      bpf_l4_csum_replace(skb, check_off, bpf_htons(old_port_host),
                          bpf_htons(new_port_host), sizeof(__be16)) < 0)
    return TC_ACT_SHOT;

  if (old_addr_host != new_addr_host) {
    __be32 new_addr = bpf_htonl(new_addr_host);
    __u32 addr_off = sizeof(struct ethhdr) +
                     __builtin_offsetof(struct iphdr, daddr);
    if (rewrite_src)
      addr_off = sizeof(struct ethhdr) +
                 __builtin_offsetof(struct iphdr, saddr);

    if (bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0) < 0)
      return TC_ACT_SHOT;
  }

  if (old_port_host != new_port_host) {
    __be16 new_port = bpf_htons(new_port_host);
    __u32 port_off = l4_off + sizeof(__be16);
    if (rewrite_src)
      port_off = l4_off;

    if (bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0) < 0)
      return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

static __always_inline int maybe_reverse_service_dnat(struct __sk_buff *skb) {
  struct iphdr iph = {};
  if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph, sizeof(iph)) < 0)
    return TC_ACT_SHOT;

  if (iph.protocol != IPPROTO_TCP && iph.protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u32 l4_off = 0;
  __u32 check_off = 0;
  bool skip_l4_csum = false;
  int l4_ret = load_l4_info(skb, &iph, &src_port, &dst_port, &l4_off,
                            &check_off, &skip_l4_csum);
  if (l4_ret != TC_ACT_OK)
    return l4_ret;

  struct service_ct_key key = {
      .proto = iph.protocol,
      .src_addr = bpf_ntohl(iph.saddr),
      .src_port = src_port,
      .dst_addr = bpf_ntohl(iph.daddr),
      .dst_port = dst_port,
  };
  const struct service_ct_val *val =
      bpf_map_lookup_elem(&service_ct_map, &key);
  if (!val)
    return TC_ACT_OK;

  return rewrite_service_nat(skb, l4_off, true, check_off, skip_l4_csum,
                             key.src_addr, val->service_addr, key.src_port,
                             val->service_port);
}

static __always_inline int maybe_track_hub_reply(struct __sk_buff *skb) {
  struct ifindex_subnet_key ifkey = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *ifval =
      bpf_map_lookup_elem(&ifindex_subnet, &ifkey);
  if (!ifval || ifval->subnet_id == 1)
    return TC_ACT_OK;

  struct subnet_key default_key = {
      .subnet_id = 1,
  };
  const struct subnet_val *default_subnet =
      bpf_map_lookup_elem(&subnet_map, &default_key);
  if (!default_subnet)
    return TC_ACT_OK;

  struct iphdr iph = {};
  if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph, sizeof(iph)) < 0)
    return TC_ACT_SHOT;

  if (iph.protocol != IPPROTO_TCP && iph.protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  __u32 src_addr = bpf_ntohl(iph.saddr);
  if ((src_addr & default_subnet->mask) !=
      (default_subnet->gw_addr & default_subnet->mask))
    return TC_ACT_OK;

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u32 l4_off = 0;
  __u32 check_off = 0;
  bool skip_l4_csum = false;
  int l4_ret = load_l4_info(skb, &iph, &src_port, &dst_port, &l4_off,
                            &check_off, &skip_l4_csum);
  if (l4_ret != TC_ACT_OK)
    return l4_ret;

  struct service_ct_key reply_key = {
      .proto = iph.protocol,
      .src_addr = bpf_ntohl(iph.daddr),
      .src_port = dst_port,
      .dst_addr = src_addr,
      .dst_port = src_port,
  };
  __u8 allow = 1;
  if (bpf_map_update_elem(&hub_reply_ct_map, &reply_key, &allow, BPF_ANY) < 0)
    return TC_ACT_SHOT;

  return TC_ACT_OK;
}

SEC("tc")
int tc_pod_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  int hub_ret = maybe_track_hub_reply(skb);
  if (hub_ret != TC_ACT_OK)
    return hub_ret;

  return maybe_reverse_service_dnat(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
