// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "maps.h"

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define IP_OFFSET 0x1FFF

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct arp_payload {
  __u8 sha[ETH_ALEN];
  __be32 spa;
  __u8 tha[ETH_ALEN];
  __be32 tpa;
} __attribute__((packed));

static __always_inline int update_l4_csum(struct __sk_buff *skb,
                                          struct iphdr *iph, void *data_end,
                                          __be32 old_addr, __be32 new_addr) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return TC_ACT_SHOT;

  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return TC_ACT_OK;

  __u32 l4_off = sizeof(struct ethhdr) + ihl * 4;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)iph + ihl * 4;
    if ((void *)(tcp + 1) > data_end)
      return TC_ACT_SHOT;

    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct tcphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;

    return TC_ACT_OK;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)iph + ihl * 4;
    if ((void *)(udp + 1) > data_end)
      return TC_ACT_SHOT;

    if (udp->check == 0)
      return TC_ACT_OK;

    if (bpf_l4_csum_replace(skb,
                            l4_off + __builtin_offsetof(struct udphdr, check),
                            old_addr, new_addr,
                            BPF_F_PSEUDO_HDR | sizeof(new_addr)) < 0)
      return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

static __always_inline int load_l4_info(struct __sk_buff *skb,
                                        const struct iphdr *iph,
                                        __u16 *src_port, __u16 *dst_port,
                                        __u32 *l4_off, __u32 *check_off,
                                        bool *skip_csum) {
  __u32 ihl = iph->ihl;
  if (ihl < 5)
    return TC_ACT_SHOT;

  if ((bpf_ntohs(iph->frag_off) & IP_OFFSET) != 0)
    return TC_ACT_OK;

  *l4_off = sizeof(struct ethhdr) + ihl * 4;
  *skip_csum = false;

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
    *skip_csum = udp.check == 0;
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

static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 subnet_id);

static __always_inline __u32 service_flow_hash(struct __sk_buff *skb,
                                               const struct iphdr *iph,
                                               __u16 src_port,
                                               __u16 dst_port) {
  __u32 hash = bpf_get_hash_recalc(skb);
  if (hash != 0)
    return hash;

  hash = bpf_ntohl(iph->saddr);
  hash ^= bpf_ntohl(iph->daddr) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
  hash ^= ((__u32)src_port << 16) | dst_port;
  hash ^= ((__u32)iph->protocol << 24);
  hash ^= hash >> 16;
  hash *= 0x7feb352d;
  hash ^= hash >> 15;

  return hash;
}

static __always_inline int maybe_service_dnat(struct __sk_buff *skb,
                                              const struct subnet_val *subnet) {
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

  __u32 tid = subnet->table_id;
  void *service_inner_map = bpf_map_lookup_elem(&service_map, &tid);
  if (!service_inner_map)
    return TC_ACT_OK;

  struct service_key service_key = {
      .addr = bpf_ntohl(iph.daddr),
      .port = dst_port,
      .proto = iph.protocol,
  };
  const struct service_val *service_meta =
      bpf_map_lookup_elem(service_inner_map, &service_key);
  if (!service_meta || service_meta->backend_count == 0)
    return TC_ACT_OK;

  void *service_backend_inner_map =
      bpf_map_lookup_elem(&service_backend_map, &tid);
  if (!service_backend_inner_map)
    return TC_ACT_SHOT;

  __u32 flow_hash = service_flow_hash(skb, &iph, src_port, dst_port);
  struct service_backend_key backend_key = {
      .addr = service_key.addr,
      .port = service_key.port,
      .proto = service_key.proto,
      .slot = flow_hash % service_meta->backend_count,
  };
  const struct service_backend_val *backend =
      bpf_map_lookup_elem(service_backend_inner_map, &backend_key);
  if (!backend)
    return TC_ACT_SHOT;

  struct service_ct_key ct_key = {
      .proto = iph.protocol,
      .src_addr = backend->backend_addr,
      .src_port = backend->backend_port,
      .dst_addr = bpf_ntohl(iph.saddr),
      .dst_port = src_port,
  };
  struct service_ct_val ct_val = {
      .service_addr = service_key.addr,
      .service_port = service_key.port,
  };
  if (bpf_map_update_elem(&service_ct_map, &ct_key, &ct_val, BPF_ANY) < 0)
    return TC_ACT_SHOT;

  return rewrite_service_nat(skb, l4_off, false, check_off, skip_l4_csum,
                             service_key.addr, backend->backend_addr,
                             service_key.port, backend->backend_port);
}

static __always_inline int maybe_forward_hub_reply(struct __sk_buff *skb,
                                                   struct ethhdr *eth,
                                                   struct iphdr *iph) {
  struct subnet_key default_key = {
      .subnet_id = 1,
  };
  const struct subnet_val *default_subnet =
      bpf_map_lookup_elem(&subnet_map, &default_key);
  if (!default_subnet)
    return TC_ACT_SHOT;

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u32 l4_off = 0;
  __u32 check_off = 0;
  bool skip_l4_csum = false;
  int l4_ret = load_l4_info(skb, iph, &src_port, &dst_port, &l4_off,
                            &check_off, &skip_l4_csum);
  if (l4_ret != TC_ACT_OK)
    return l4_ret;

  struct service_ct_key reply_key = {
      .proto = iph->protocol,
      .src_addr = bpf_ntohl(iph->saddr),
      .src_port = src_port,
      .dst_addr = bpf_ntohl(iph->daddr),
      .dst_port = dst_port,
  };
  const __u8 *allow = bpf_map_lookup_elem(&hub_reply_ct_map, &reply_key);
  if (!allow)
    return TC_ACT_SHOT;

  struct arp_table_key ak = {
      .subnet_id = 1,
      .ipaddr = reply_key.dst_addr,
  };
  const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
  if (!av)
    return TC_ACT_SHOT;

  __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, default_subnet->gw_mac, ETH_ALEN);

  return forward_l2(skb, eth, 1);
}

static __always_inline int handle_snat(struct __sk_buff *skb,
                                       struct ethhdr *eth, struct iphdr *iph,
                                       const struct fib_val *fv) {
  void *data;
  void *data_end;

  struct ifindex_subnet_key isk = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *isv =
      bpf_map_lookup_elem(&ifindex_subnet, &isk);
  if (!isv)
    return TC_ACT_SHOT;

  struct nat_inside nk = {
      .subnet_id = isv->subnet_id,
      .addr = bpf_ntohl(iph->saddr),
  };
  const struct nat_outside *nv = bpf_map_lookup_elem(&nat_snat_map, &nk);
  if (!nv)
    return TC_ACT_SHOT;

  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __builtin_memcpy(dst_mac, fv->dmac, ETH_ALEN);
  __builtin_memcpy(src_mac, fv->smac, ETH_ALEN);

  __be32 old_addr = iph->saddr;
  __be32 new_addr = bpf_htonl(nv->addr);

  if (bpf_l3_csum_replace(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, check),
                          old_addr, new_addr, sizeof(new_addr)) < 0)
    return TC_ACT_SHOT;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  int csum_ret = update_l4_csum(skb, iph, data_end, old_addr, new_addr);
  if (csum_ret != TC_ACT_OK)
    return csum_ret;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb,
                          sizeof(struct ethhdr) +
                              __builtin_offsetof(struct iphdr, saddr),
                          &new_addr, sizeof(new_addr), 0) < 0)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_dest),
                          dst_mac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  if (bpf_skb_store_bytes(skb, __builtin_offsetof(struct ethhdr, h_source),
                          src_mac, ETH_ALEN, 0) < 0)
    return TC_ACT_SHOT;

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  return bpf_redirect(fv->oif, 0);
}

static __always_inline int handle_arp(struct __sk_buff *skb, void *data_end,
                                      struct ethhdr *eth, __u32 subnet_id,
                                      const struct subnet_val *subnet) {
  struct arphdr *arp = (void *)(eth + 1);
  if ((void *)(arp + 1) > data_end)
    return TC_ACT_SHOT;

  if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER))
    return TC_ACT_SHOT;
  if (arp->ar_pro != bpf_htons(ETH_P_IP))
    return TC_ACT_SHOT;
  if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
    return TC_ACT_SHOT;
  if (arp->ar_op != bpf_htons(ARPOP_REQUEST))
    return TC_ACT_SHOT;

  struct arp_payload *payload = (void *)(arp + 1);
  if ((void *)(payload + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 tpa = bpf_ntohl(payload->tpa);
  __u32 gw_addr = subnet->gw_addr;
  __u32 mask = subnet->mask;

  if ((tpa & mask) != (gw_addr & mask))
    return TC_ACT_SHOT;

  __u8 responder_mac[ETH_ALEN];
  if (subnet_id == 1) {
    __builtin_memcpy(responder_mac, subnet->gw_mac, ETH_ALEN);
  } else {
    if (tpa == gw_addr) {
      __builtin_memcpy(responder_mac, subnet->gw_mac, ETH_ALEN);
    } else {
      struct arp_table_key ak = {
          .subnet_id = subnet_id,
          .ipaddr = tpa,
      };
      const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
      if (!av)
        return TC_ACT_SHOT;
      __builtin_memcpy(responder_mac, av->mac, ETH_ALEN);
    }
  }

  __u8 requester_mac[ETH_ALEN];
  __builtin_memcpy(requester_mac, eth->h_source, ETH_ALEN);
  __be32 requester_ip = payload->spa;
  __be32 target_ip = payload->tpa;

  __builtin_memcpy(eth->h_dest, requester_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, responder_mac, ETH_ALEN);

  arp->ar_op = bpf_htons(ARPOP_REPLY);
  __builtin_memcpy(payload->tha, requester_mac, ETH_ALEN);
  payload->tpa = requester_ip;
  __builtin_memcpy(payload->sha, responder_mac, ETH_ALEN);
  payload->spa = target_ip;

  return bpf_redirect(skb->ifindex, 0);
}

static __always_inline int forward_l2(struct __sk_buff *skb, struct ethhdr *eth,
                                      __u32 subnet_id) {
  struct fdb_key fk = {};
  fk.subnet_id = subnet_id;
  __builtin_memcpy(fk.mac, eth->h_dest, ETH_ALEN);
  const struct fdb_val *fv = bpf_map_lookup_elem(&fdb, &fk);
  if (!fv)
    return TC_ACT_SHOT;

  if (fv->ifindex != 0)
    return bpf_redirect(fv->ifindex, 0);

  __u32 vx_key = 0;
  const __u32 *vx_if = bpf_map_lookup_elem(&vxlan_ifindex, &vx_key);
  if (!vx_if)
    return TC_ACT_SHOT;

  struct bpf_tunnel_key tkey = {};
  tkey.remote_ipv4 = fv->vtep_ip;
  tkey.tunnel_id = subnet_id;
  tkey.tunnel_ttl = 64;
  tkey.tunnel_tos = 0;

  if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0)
    return TC_ACT_SHOT;

  return bpf_redirect(*vx_if, 0);
}

static __always_inline int handle_l3(struct __sk_buff *skb, struct ethhdr *eth,
                                     const struct subnet_val *subnet) {
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  int service_ret = maybe_service_dnat(skb, subnet);
  if (service_ret != TC_ACT_OK)
    return service_ret;

  void *data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_SHOT;

  __u32 dst_be = iph->daddr; // keep network order for LPM trie

  __u32 tid = subnet->table_id;
  void *fib_inner_map = bpf_map_lookup_elem(&fib_map, &tid);
  if (!fib_inner_map)
    return TC_ACT_SHOT;

  struct fib_key fkey = {
      .prefixlen = 32,
      .dst = dst_be,
  };
  const struct fib_val *fv = bpf_map_lookup_elem(fib_inner_map, &fkey);
  if (!fv)
    return maybe_forward_hub_reply(skb, eth, iph);

  if (fv->type == FIB_ROUTE_TYPE_CONNECTED) {
    struct arp_table_key ak = {
        .subnet_id = fv->subnet_id,
        .ipaddr = bpf_ntohl(dst_be),
    };
    const struct arp_table_val *av = bpf_map_lookup_elem(&arp_table, &ak);
    if (!av)
      return TC_ACT_SHOT;

    __builtin_memcpy(eth->h_dest, av->mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_ENDPOINT) {
    __builtin_memcpy(eth->h_dest, fv->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fv->smac, ETH_ALEN);

    return forward_l2(skb, eth, fv->subnet_id);
  }

  if (fv->type == FIB_ROUTE_TYPE_INTERNET_GATEWAY)
    return handle_snat(skb, eth, iph, fv);

  return TC_ACT_SHOT;
}

static __always_inline int handle_l2(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;

  struct ifindex_subnet_key key = {
      .ifindex = skb->ifindex,
  };
  const struct ifindex_subnet_val *val =
      bpf_map_lookup_elem(&ifindex_subnet, &key);
  if (!val)
    return TC_ACT_SHOT;

  struct subnet_key skey = {
      .subnet_id = val->subnet_id,
  };
  const struct subnet_val *subnet = bpf_map_lookup_elem(&subnet_map, &skey);
  if (!subnet)
    return TC_ACT_SHOT;

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto == ETH_P_ARP)
    return handle_arp(skb, data_end, eth, val->subnet_id, subnet);

  bool is_gw = true;
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    if (eth->h_dest[i] != subnet->gw_mac[i]) {
      is_gw = false;
      break;
    }
  }

  if (val->subnet_id == 1) {
    if (is_gw) {
      int l3_ret = handle_l3(skb, eth, subnet);
      if (l3_ret != TC_ACT_SHOT)
        return l3_ret;
    }

    __u32 host_key = 0;
    const struct host_iface_val *host =
        bpf_map_lookup_elem(&host_iface, &host_key);
    if (!host)
      return TC_ACT_SHOT;
    return bpf_redirect(host->ifindex, 0);
  }

  if (is_gw)
    return handle_l3(skb, eth, subnet);

  return forward_l2(skb, eth, val->subnet_id);
}

SEC("tc")
int tc_pod_egress(struct __sk_buff *skb) { return handle_l2(skb); }

char __license[] SEC("license") = "Dual MIT/GPL";
