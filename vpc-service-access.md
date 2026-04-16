# VPC Service Access PoC

## このブランチの目的

このブランチは、Juneau の VPC 分離を保ったまま Kubernetes Service 到達性を拡張するための PoC である。

解決したい課題は次の 3 つ。

- 同一 VPC 内の Pod から `ClusterIP` Service を引けるようにする
- `default` VPC 上の共用 Ingress controller から tenant VPC 配下の Pod を公開できるようにする
- tenant VPC からは、`default` VPC のうち明示的に公開した Service にだけ到達できるようにする

要するに、このブランチで実装したのは **VPC スコープ付き Service アクセス** である。

## 実装した機能

### 1. 同一 VPC 内の ClusterIP 解決

Pod から `ClusterIP` 宛ての TCP/UDP パケットが出たとき、`pod_egress` で Service lookup を行い、backend Pod IP/Port に DNAT する。

- `service_map`
  - key: `(clusterIP, servicePort, protocol)`
  - value: `backend_count`
- `service_backend_map`
  - key: `(clusterIP, servicePort, protocol, slot)`
  - value: `(backendIP, backendPort)`
- `pod_ingress`
  - `service_ct_map` を使って reverse DNAT を行う

backend は 1 つ固定ではなく、flow hash で複数 backend に分散する。

### 2. `default -> tenant` の Pod IP 到達性

`default` VPC の Pod は、従来のように常に host 側へ逃がすのではなく、まず FIB lookup を試す。

- tenant subnet にヒットしたら eBPF でそのまま転送する
- ヒットしなければ従来どおり host 側に fallback する

これにより、`default` VPC 上の Ingress controller から tenant backend Pod IP に直接接続できる。

### 3. tenant から公開 Service へのアクセス

`default` VPC の Service に `juneau.loutres.me/public: "true"` を付けた場合だけ、tenant VPC からその `ClusterIP` を引ける。

そのために次を実装した。

- daemon が `Service` / `EndpointSlice` / `NetworkEndpoint` / `Subnet` / `RouteTable` を見て table ごとの Service map を構築する
- controller が tenant `RouteTable` に `public` Service backend Pod IP の `/32` route を載せる

これにより tenant 側は、

- `public` な Service の `ClusterIP` には到達できる
- 未公開の `default` VPC Service や Pod IP には到達できない

### 4. hub initiated flow の返り道

`default -> tenant` の direct Pod IP 通信については、tenant 側 `pod_ingress` で `hub_reply_ct_map` を記録する。

これにより、Ingress のように `default` VPC 側から開始した通信の返りが tenant 側で通常 route miss しても、返送を継続できる。

## 現在動作するもの

このブランチで確認できている動作は次のとおり。

- 同一 VPC 内の `ClusterIP` Service に到達できる
- tenant から `public` な `default` VPC Service に到達できる
- CoreDNS を `public` にすると tenant から DNS 解決できる
- `default` VPC 上の Ingress controller から tenant backend Pod IP に到達できる
- tenant 間 direct 通信は成立しない
- tenant から未公開の `default` VPC Service / Pod IP には到達できない
- `public` な Service が複数 backend を持つ場合、別 flow で backend が分散する

## 重要な実装前提

この PoC では、Service の所属 VPC は namespace では決めていない。

実際には次のように決めている。

- `EndpointSlice` の backend IP を引く
- その IP に対応する `NetworkEndpoint` を引く
- その `Subnet.Spec.Vpc` を Service の owner VPC とみなす

そのため、

- 1 Service が複数 VPC の backend を持つ構成はサポートしない
- backend の実在位置が Service の可視性を決める

## Kubernetes 標準 Service と異なる点

この実装は Kubernetes の `ClusterIP` に近い挙動を出すが、既存の Service 実装と同一ではない。

- 対応するのは `ClusterIP` の TCP/UDP のみ
- `NodePort`、`LoadBalancer`、`ExternalIPs`、`ExternalName`、SCTP は未対応
- `ClusterIP=None` の headless Service は対象外
- backend 選択は kube-proxy と同じアルゴリズムではない
  - endpoint を安定ソートし、flow hash で slot を選ぶ
- `sessionAffinity: ClientIP`、`InternalTrafficPolicy`、topology aware routing などは未対応
- reverse DNAT は Juneau 独自の `service_ct_map` / `pod_ingress` 実装である
- tenant から `default` VPC Service を見せる条件は Kubernetes 標準機能ではなく `juneau.loutres.me/public` annotation である

## この PoC の意味

このブランチで確認したかったのは、Cilium のような全面的 kube-proxy replacement を作らなくても、Juneau の VPC 分離モデルに必要な範囲だけ eBPF datapath を拡張すれば次が成立する、という点である。

- VPC 分離を保つ
- shared ingress を成立させる
- shared service を `public` 制御付きで tenant に見せる

つまり、この PoC は **Juneau 向けの VPC スコープ付き Service datapath が成立することの確認** である。
