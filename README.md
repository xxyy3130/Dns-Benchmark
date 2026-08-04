# DNS Benchmark

**Description:** An asynchronous DNS resolver benchmark that measures query reliability, latency, concurrency throughput, and resolver cleanliness across a resolver list stored in `resolvers.json`.

**Resolver scope:** The built-in resolver list focuses on mainland China and Hong Kong, including public, ISP, enterprise, education-network, and authoritative DNS services.

## Features

- Runs multiple resolvers in parallel to reduce total benchmark time.
- Loads the mainland-China and Hong Kong IPv4/IPv6 resolver list from a standalone JSON file.
- Probes both A and AAAA records before deciding that a resolver is unreachable.
- Measures ordinary query success rate, median latency, and P95 latency.
- Tests configurable concurrency levels, including 64 and 128 by default.
- Checks NXDOMAIN behavior, sensitive domains, DNSSEC, and TCP fallback.
- Writes a tab-separated TXT ranking and optionally a full JSON report.

## Requirements

- Python 3.9 or newer
- Network access to DNS servers on port 53
- Working IPv6 connectivity to test IPv6 resolver endpoints; without an IPv6 route, those entries are reported as `SKIP`
- Optional HTTPS access for DNS-over-HTTPS reference queries

The script uses only Python standard-library modules.

## Resolver Labels

Mainland resolver names include an English network label when their current longest-prefix BGP origin belongs to one of the supported network classes:

- `[Telecom]`: China Telecom
- `[Unicom]`: China Unicom
- `[Mobile]`: China Mobile
- `[Tietong]`: China Tietong; reserved for independently announced Tietong networks
- `[Education]`: CERNET or an education-network address
- `[Tencent]`: Tencent DNSPod IPv6 public DNS
- `[Alibaba]`: Alibaba AliDNS IPv6 public DNS
- `[Baidu]`: Baidu IPv6 public DNS
- `[Public]`: Other nationwide public IPv6 DNS services

Branded IPv4 public DNS and IDC services using their own Alibaba, Tencent, Volcengine, Baidu, CNNIC-SDNS, or 114DNS networks remain untagged. Every built-in IPv6 resolver has an explicit English label. The built-in addresses were checked on 2026-08-04; `202.141.162.123` is labelled `Telecom` because its current longest-prefix route is announced by China Telecom rather than CERNET. `Auth-CN-1` through `Auth-CN-16`, covering `203.119.*`, `202.112.0.44`, and the listed `125.208.*` addresses, are explicitly labelled `Education`. No current built-in resolver matched an independently announced Tietong network.

## Built-in IPv6 Resolvers

| Label | Name | Address |
| --- | --- | --- |
| `[Education]` | Tsinghua-TUNA666-v6 | `2001:da8::666` |
| `[Tencent]` | DNSPod-v6-1 | `2402:4e00::` |
| `[Tencent]` | DNSPod-v6-2 | `2402:4e00:1::` |
| `[Alibaba]` | AliDNS-v6-1 | `2400:3200::1` |
| `[Alibaba]` | AliDNS-v6-2 | `2400:3200:baba::1` |
| `[Baidu]` | BaiduDNS-v6 | `2400:da00::6666` |
| `[Public]` | China-IPv6-DNS-1 | `240c::6666` |
| `[Public]` | China-IPv6-DNS-2 | `240c::6644` |
| `[Education]` | CSTNET-v6 | `2001:cc0::1` |
| `[Telecom]` | CT-China-v6-P1 | `240e:4c:4008::1` |
| `[Telecom]` | CT-China-v6-B1 | `240e:4c:4808::1` |
| `[Unicom]` | CU-China-v6-P1 | `2408:8899::8` |
| `[Unicom]` | CU-China-v6-B1 | `2408:8888::8` |
| `[Mobile]` | CM-China-v6-P1 | `2409:8088::a` |
| `[Mobile]` | CM-China-v6-B1 | `2409:8088::b` |
| `[Telecom]` | CT-Anhui-v6-B1 | `240e:46:4888::4888` |

IPv6 entries run the same ordinary A-record benchmark over IPv6 transport. Before the full benchmark, reachability is checked with both A and AAAA queries against two domains. The queried A-record performance remains directly comparable with IPv4 resolvers, while the resolver connection itself uses IPv6.

The Telecom, Unicom, and Mobile IPv6 entries are carrier recursive resolvers rather than unrestricted public DNS services. They may time out or return `REFUSED` outside the matching carrier or service region; this is a server access policy rather than an IPv6 transport failure.

At startup, the script asks the operating system to select an IPv6 source address without sending a packet. If no route is available, it prints a warning and immediately skips IPv6 entries instead of waiting through repeated timeouts. Use `--force-ipv6` only when policy routing makes this automatic check inaccurate.

## DNS Records

`resolvers.json` contains the DNS records used by the benchmark.

## Test Domains

The ordinary latency and concurrency set contains 21 domains. In addition to the existing general-purpose sites, it includes:

- `sunlogin.oray.com`: Sunlogin Remote Control
- `parsec.app`: Parsec
- `todesk.com`: ToDesk Remote Desktop

## Quick Start

Run the default benchmark:

```bash
py dns_benchmark.py --output dns_benchmark.txt
```

The default settings are:

- Three ordinary-query repeats per domain
- Four ordinary latency queries in flight per resolver
- 192 requests for each concurrency level
- 64 and 128 concurrent requests
- 32 resolvers tested at the same time
- A 1.5-second DNS query timeout
- A 3-second DNS-over-HTTPS reference timeout

## Usage

```text
py dns_benchmark.py [options]
```

### Parameters

| Parameter | Default | Description |
| --- | ---: | --- |
| `--repeats N` | `3` | Number of ordinary latency repeats per domain. There are 21 ordinary test domains, so the total is `21 * N` queries per resolver. |
| `--requests N` | `192` | Number of requests sent for each concurrency level. |
| `--concurrency-levels LIST` | `64,128` | Comma-separated concurrency levels, for example `32,64,128`. |
| `--parallel-resolvers N` | `32` | Maximum number of DNS resolvers tested at the same time. Increase carefully because it creates more network traffic. |
| `--latency-workers N` | `4` | Low-concurrency workers used for ordinary latency samples. Use `1` for strictly sequential sampling; higher values reduce the impact of repeated timeouts. |
| `--timeout SECONDS` | `1.5` | Timeout for individual UDP DNS queries. |
| `--doh-timeout SECONDS` | `3.0` | Timeout for each DNS-over-HTTPS reference query. DoH collection runs in the background alongside resolver tests. |
| `--force-ipv6` | Disabled | Test IPv6 resolvers even when the operating system cannot automatically select an IPv6 route. Useful with unusual policy-routing setups. |
| `--resolvers PATH` | `resolvers.json` | Resolver JSON file. The default is the file beside `dns_benchmark.py`. |
| `--output PATH` | Required | Path of the tab-separated TXT ranking report. |
| `--json-output PATH` | None | Optional path for complete JSON data, including per-query samples and integrity details. |

## Examples

Run the default 64/128 benchmark and save both report formats:

```bash
py dns_benchmark.py --output dns_benchmark.txt --json-output dns_benchmark.json
```

Use more latency samples and test three concurrency levels:

```bash
py dns_benchmark.py --repeats 5 --requests 256 --concurrency-levels 32,64,128 --parallel-resolvers 16 --timeout 2 --output results.txt
```

Use faster ordinary latency sampling and a shorter DoH reference timeout:

```bash
py dns_benchmark.py --latency-workers 8 --doh-timeout 2 --output results.txt
```

Use strictly sequential ordinary latency sampling for the lowest per-resolver test load:

```bash
py dns_benchmark.py --latency-workers 1 --output results.txt
```

## Output

The TXT report is grouped in this order:

1. Completed resolvers with `Clean > 10%`
2. Completed resolvers with `Clean <= 10%`
3. Skipped resolvers

Within each completed group, results are sorted by:

1. Ordinary query success rate, descending
2. DNS median latency, ascending
3. DNS P95 latency, ascending
4. Cleanliness score, descending
5. 64-way successful QPS, descending
6. 128-way performance, descending

The main table uses fixed-width fields separated by tab characters. Open it with a monospace font and a consistent tab-stop setting for the best alignment.

The latency columns measure DNS UDP request/response time over the resolver's IPv4 or IPv6 transport. They are not ICMP ping RTT values: DNS caching, resolver processing, and protocol handling can make DNS latency lower or higher than `ping`.

The table includes:

- `Success`: ordinary query success rate
- `DNSMed(ms)`: median latency of successful ordinary DNS queries
- `P95(ms)`: 95th-percentile latency
- `Clean`: weighted resolver cleanliness score based on randomized NXDOMAIN checks, randomized sensitive-subdomain pollution probes, sensitive-domain results, known-answer checks, DNSSEC behavior, and DNS-over-TCP support. Exact IP mismatches are treated as inconclusive because CDN and geographic answers can differ. Unavailable DoH-baseline weights are excluded, and per-domain verdicts are included in the optional JSON report.
- `QPS@64`: successful queries per second at 64-way concurrency
- `128 OK`: success rate at 128-way concurrency
- `QPS@128`: successful queries per second at 128-way concurrency
