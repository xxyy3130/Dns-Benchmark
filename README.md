# Dns-Benchmark
An asynchronous DNS resolver benchmark that measures query reliability, latency, concurrency throughput, and resolver cleanliness across a large built-in resolver list.

## Features

- Runs multiple resolvers in parallel to reduce total benchmark time.
- Measures ordinary query success rate, median latency, and P95 latency.
- Tests configurable concurrency levels, including 64 and 128 by default.
- Checks NXDOMAIN behavior, sensitive domains, DNSSEC, and TCP fallback.
- Writes a tab-separated TXT ranking and optionally a full JSON report.

## Requirements

- Python 3.9 or newer
- Network access to DNS servers on port 53
- Optional HTTPS access for DNS-over-HTTPS reference queries

The script uses only Python standard-library modules.

## Quick Start

Run the default benchmark:

```bash
py dns_benchmark.py --output dns_benchmark.txt
```

The default settings are:

- Three ordinary-query repeats per domain
- 192 requests for each concurrency level
- 64 and 128 concurrent requests
- 32 resolvers tested at the same time
- A 1.5-second DNS query timeout

## Usage

```text
py dns_benchmark.py [options]
```

### Parameters

| Parameter | Default | Description |
| --- | ---: | --- |
| `--repeats N` | `3` | Number of ordinary latency repeats per domain. There are 16 ordinary test domains, so the total is `16 * N` queries per resolver. |
| `--requests N` | `192` | Number of requests sent for each concurrency level. |
| `--concurrency-levels LIST` | `64,128` | Comma-separated concurrency levels, for example `32,64,128`. |
| `--parallel-resolvers N` | `32` | Maximum number of DNS resolvers tested at the same time. Increase carefully because it creates more network traffic. |
| `--timeout SECONDS` | `1.5` | Timeout for individual UDP DNS queries. |
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

## Output

The TXT report is sorted by:

1. Ordinary query success rate, descending
2. Median latency, ascending
3. P95 latency, ascending
4. 64-way successful QPS, descending
5. 128-way performance, descending
6. Cleanliness score, descending

The main table uses fixed-width fields separated by tab characters. Open it with a monospace font and a consistent tab-stop setting for the best alignment.

The table includes:

- `Success`: ordinary query success rate
- `Median(ms)`: median latency of successful ordinary queries
- `P95(ms)`: 95th-percentile latency
- `QPS@64`: successful queries per second at 64-way concurrency
- `128 OK`: success rate at 128-way concurrency
- `QPS@128`: successful queries per second at 128-way concurrency
- `Clean`: weighted resolver cleanliness score
