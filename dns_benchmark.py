import argparse
import asyncio
import functools
import ipaddress
import json
import random
import socket
import statistics
import struct
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_RESOLVERS_PATH = Path(__file__).with_name("resolvers.json")
RESOLVERS = {}


def load_resolvers(path):
    resolver_path = Path(path)
    with resolver_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if data.get("schema_version") != 1:
        raise ValueError("resolver JSON schema_version must be 1")
    entries = data.get("resolvers")
    if not isinstance(entries, list) or not entries:
        raise ValueError("resolver JSON must contain a non-empty resolvers list")

    resolvers = {}
    addresses = {}
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise ValueError(f"resolver entry {index} must be an object")
        name = entry.get("name")
        server = entry.get("server")
        label = entry.get("label")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"resolver entry {index} has an invalid name")
        if not isinstance(server, str):
            raise ValueError(f"resolver entry {index} has an invalid server")
        if label is not None and (not isinstance(label, str) or not label.strip()):
            raise ValueError(f"resolver entry {index} has an invalid label")

        try:
            address = ipaddress.ip_address(server)
        except ValueError as exc:
            raise ValueError(f"resolver entry {index} has an invalid IP address: {server}") from exc

        display_name = f"[{label.strip()}] {name.strip()}" if label else name.strip()
        normalized = address.compressed
        if display_name in resolvers:
            raise ValueError(f"duplicate resolver name: {display_name}")
        if normalized in addresses:
            raise ValueError(
                f"duplicate resolver address {normalized}: {addresses[normalized]} and {display_name}"
            )
        resolvers[display_name] = normalized
        addresses[normalized] = display_name

    return resolvers


def _socket_family(server):
    return socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET


def _socket_address(server, port):
    """Return the native address tuple required by a low-level UDP socket."""
    if _socket_family(server) == socket.AF_INET6:
        return server, port, 0, 0
    return server, port


def _asyncio_address(server, port):
    """asyncio resolves flowinfo/scopeid itself and requires a host/port pair."""
    return server, port


def _same_ip(left, right):
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _has_ipv6_route():
    """Ask the OS to select a source address without sending network traffic."""
    candidate = next(
        (server for server in RESOLVERS.values() if _socket_family(server) == socket.AF_INET6),
        None,
    )
    if candidate is None:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(_socket_address(candidate, 53))
            return not ipaddress.ip_address(sock.getsockname()[0]).is_unspecified
    except OSError:
        return False

DOMAINS = [
    "baidu.com", "qq.com", "taobao.com", "jd.com", "bilibili.com",
    "douyin.com", "weibo.com", "zhihu.com", "gov.cn", "12306.cn",
    "microsoft.com", "github.com", "apple.com", "cloudflare.com",
    "wikipedia.org", "openai.com", "store.steampowered.com", "www.amap.com",
    "sunlogin.oray.com", "parsec.app", "todesk.com",
]

SENSITIVE_DOMAINS = [
    "www.google.com", "www.youtube.com", "www.facebook.com", "twitter.com",
    "telegram.org", "www.wikipedia.org", "github.com", "openai.com",
    "www.instagram.com", "www.reddit.com", "www.tiktok.com", "discord.com",
]

POLLUTION_PROBE_ROOTS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "wikipedia.org", "telegram.org",
]

KNOWN_ANSWER_DOMAINS = {
    "one.one.one.one": {"1.0.0.1", "1.1.1.1"},
    "dns.google": {"8.8.4.4", "8.8.8.8"},
}

TRUSTED_DOH_LABELS = {"CloudflareDoH", "GoogleDoH"}


def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * p
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    fraction = index - low
    return ordered[low] * (1 - fraction) + ordered[high] * fraction


def encode_name(name):
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label.encode("idna"))]) + label.encode("idna") for label in labels) + b"\x00"


def make_query(name, dnssec=False, qtype="A"):
    query_types = {"A": 1, "AAAA": 28}
    try:
        query_type = query_types[qtype.upper()]
    except (AttributeError, KeyError):
        raise ValueError(f"unsupported DNS query type: {qtype}") from None
    query_id = random.randrange(0, 65536)
    additional = 1 if dnssec else 0
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, additional)
    packet += encode_name(name) + struct.pack("!HH", query_type, 1)
    if dnssec:
        packet += b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return query_id, packet


def skip_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def parse_response(packet, expected_id):
    if len(packet) < 12:
        raise ValueError("short DNS response")
    query_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    if query_id != expected_id:
        raise ValueError("mismatched DNS transaction ID")
    offset = 12
    for _ in range(qd):
        offset = skip_name(packet, offset) + 4
    answers = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            offset = skip_name(packet, offset)
            if offset + 10 > len(packet):
                raise ValueError("truncated resource record")
            rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata = packet[offset:offset + rdlength]
            offset += rdlength
            value = None
            if rrtype == 1 and rdlength == 4:
                value = socket.inet_ntop(socket.AF_INET, rdata)
            elif rrtype == 28 and rdlength == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            if section == "answer" and value:
                answers.append(value)
    return {
        "rcode": flags & 0xF,
        "answers": sorted(set(answers)),
        "answer_count": an,
        "flags": {
            "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
            "rd": bool(flags & 0x0100), "ra": bool(flags & 0x0080),
            "ad": bool(flags & 0x0020), "cd": bool(flags & 0x0010),
        },
    }


def dns_query(server, name, timeout=1.5, tcp=False, dnssec=False, qtype="A"):
    query_id, packet = make_query(name, dnssec=dnssec, qtype=qtype)
    started = time.perf_counter()
    try:
        if tcp:
            with socket.create_connection((server, 53), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                length_data = recv_exact(sock, 2)
                response = recv_exact(sock, struct.unpack("!H", length_data)[0])
        else:
            with socket.socket(_socket_family(server), socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, _socket_address(server, 53))
                response, peer = sock.recvfrom(4096)
                if not _same_ip(peer[0], server):
                    raise ValueError("response came from unexpected server")
        elapsed_ms = (time.perf_counter() - started) * 1000
        parsed = parse_response(response, query_id)
        parsed.update({"ok": True, "latency_ms": elapsed_ms, "error": None})
        return parsed
    except Exception as exc:
        return {
            "ok": False, "latency_ms": (time.perf_counter() - started) * 1000,
            "rcode": None, "answers": [], "answer_count": 0,
            "flags": {}, "error": f"{type(exc).__name__}: {exc}",
        }


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("TCP DNS connection closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def doh_json(endpoint, name, timeout=3):
    url = endpoint + "?" + urllib.parse.urlencode({"name": name, "type": "A"})
    request = urllib.request.Request(url, headers={"accept": "application/dns-json", "user-agent": "dns-benchmark/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.load(response)
    answers = sorted({item["data"] for item in body.get("Answer", []) if item.get("type") == 1})
    return {"status": body.get("Status"), "answers": answers}


def summarize_queries(samples):
    good = [sample for sample in samples if sample["ok"]]
    times = [sample["latency_ms"] for sample in good]
    return {
        "requests": len(samples), "success": len(good),
        "success_pct": round(100 * len(good) / len(samples), 2) if samples else 0,
        "median_ms": round(statistics.median(times), 3) if times else None,
        "mean_ms": round(statistics.mean(times), 3) if times else None,
        "p95_ms": round(percentile(times, 0.95), 3) if times else None,
        "max_ms": round(max(times), 3) if times else None,
        "rcodes": dict(Counter(str(sample["rcode"]) for sample in good)),
        "errors": dict(Counter(sample["error"] for sample in samples if not sample["ok"])),
    }


def failed_sample(started, exc):
    return {
        "ok": False, "latency_ms": (time.perf_counter() - started) * 1000,
        "rcode": None, "answers": [], "answer_count": 0, "flags": {},
        "error": f"{type(exc).__name__}: {exc}",
    }


class _DnsDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, client):
        self.client = client

    def connection_made(self, transport):
        self.client.transport = transport

    def datagram_received(self, data, address):
        self.client.receive(data, address)

    def error_received(self, exc):
        self.client.receive_error(exc)


class AsyncDnsClient:
    """One connected UDP socket per resolver, shared by all its async queries."""

    def __init__(self, server, timeout):
        self.server = server
        self.timeout = timeout
        self.family = _socket_family(server)
        self.remote_addr = _asyncio_address(server, 53)
        self.transport = None
        self.pending = {}
        self.fallback = False

    async def start(self):
        loop = asyncio.get_running_loop()
        try:
            await loop.create_datagram_endpoint(
                lambda: _DnsDatagramProtocol(self),
                remote_addr=self.remote_addr, family=self.family,
            )
        except NotImplementedError:
            self.fallback = True

    def receive(self, data, address):
        if len(data) < 2 or (address and not _same_ip(address[0], self.server)):
            return
        query_id = struct.unpack("!H", data[:2])[0]
        future = self.pending.get(query_id)
        if future is not None and not future.done():
            future.set_result(data)

    def receive_error(self, exc):
        for future in tuple(self.pending.values()):
            if not future.done():
                future.set_exception(exc)

    async def query(self, name, dnssec=False, qtype="A"):
        started = time.perf_counter()
        try:
            if self.fallback:
                loop = asyncio.get_running_loop()
                query = functools.partial(
                    dns_query, self.server, name, self.timeout, False, dnssec, qtype
                )
                return await loop.run_in_executor(None, query)
            loop = asyncio.get_running_loop()
            for _ in range(8):
                query_id, packet = make_query(name, dnssec=dnssec, qtype=qtype)
                if query_id not in self.pending:
                    break
            else:
                raise RuntimeError("too many pending DNS transaction IDs")
            future = loop.create_future()
            self.pending[query_id] = future
            if self.transport is None:
                raise ConnectionError("DNS UDP transport is not ready")
            self.transport.sendto(packet)
            response = await asyncio.wait_for(future, timeout=self.timeout)
            parsed = parse_response(response, query_id)
            parsed.update({"ok": True, "latency_ms": (time.perf_counter() - started) * 1000, "error": None})
            return parsed
        except Exception as exc:
            return failed_sample(started, exc)
        finally:
            self.pending.pop(locals().get("query_id"), None)

    def close(self):
        for future in tuple(self.pending.values()):
            if not future.done():
                future.cancel()
        self.pending.clear()
        if self.transport is not None:
            self.transport.close()
            self.transport = None


async def async_tcp_query(server, name, timeout=1.5, dnssec=False):
    started = time.perf_counter()
    writer = None
    try:
        query_id, packet = make_query(name, dnssec=dnssec)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 53), timeout=timeout)
        writer.write(struct.pack("!H", len(packet)) + packet)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        length_data = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        response = await asyncio.wait_for(reader.readexactly(struct.unpack("!H", length_data)[0]), timeout=timeout)
        parsed = parse_response(response, query_id)
        parsed.update({"ok": True, "latency_ms": (time.perf_counter() - started) * 1000, "error": None})
        return parsed
    except Exception as exc:
        return failed_sample(started, exc)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_latency_async(client, repeats, workers):
    ordered = DOMAINS * repeats
    random.shuffle(ordered)
    gate = asyncio.Semaphore(workers)

    async def one(domain):
        async with gate:
            result = await client.query(domain)
            result["domain"] = domain
            return result

    samples = await asyncio.gather(*(one(domain) for domain in ordered))
    return summarize_queries(samples), samples


async def run_concurrency_async(client, workers, requests):
    selected = [DOMAINS[index % len(DOMAINS)] for index in range(requests)]
    random.shuffle(selected)
    gate = asyncio.Semaphore(workers)

    async def one(name):
        async with gate:
            return await client.query(name)

    started = time.perf_counter()
    samples = await asyncio.gather(*(one(name) for name in selected))
    elapsed = max(time.perf_counter() - started, 1e-9)
    summary = summarize_queries(samples)
    summary.update({
        "workers": workers, "wall_seconds": round(elapsed, 3),
        "successful_qps": round(summary["success"] / elapsed, 2),
    })
    return summary


async def run_integrity_async(client, server, token):
    nonexistent = [f"{token}-{index}.invalid" for index in range(3)] + [
        f"{token}-{index}.example.com" for index in range(3)
    ]
    pollution_probes = build_pollution_probe_domains(token)
    nx_values, sensitive_values, probe_values, known_values, valid_dnssec, bogus_dnssec, tcp = await asyncio.gather(
        asyncio.gather(*(client.query(name) for name in nonexistent)),
        asyncio.gather(*(client.query(name, dnssec=True) for name in SENSITIVE_DOMAINS)),
        asyncio.gather(*(client.query(name) for name in pollution_probes)),
        asyncio.gather(*(client.query(name) for name in KNOWN_ANSWER_DOMAINS)),
        client.query("cloudflare.com", dnssec=True),
        client.query("dnssec-failed.org", dnssec=True),
        async_tcp_query(server, "baidu.com"),
    )
    nx_results = dict(zip(nonexistent, nx_values))
    sensitive = dict(zip(SENSITIVE_DOMAINS, sensitive_values))
    nxdomain_clean = sum(
        1 for result in nx_results.values()
        if result["ok"] and result["rcode"] == 3 and not result["answers"]
    )
    return {
        "nxdomain_clean": nxdomain_clean,
        "nxdomain_total": len(nx_results),
        "nxdomain_results": nx_results,
        "sensitive_results": sensitive,
        "pollution_probe_results": dict(zip(pollution_probes, probe_values)),
        "known_answer_results": dict(zip(KNOWN_ANSWER_DOMAINS, known_values)),
        "dnssec_valid": valid_dnssec,
        "dnssec_bogus": bogus_dnssec,
        "tcp_query": tcp,
    }


def _reference_answers(doh_references, domain):
    answers = set()
    for item in doh_references.get(domain, {}).values():
        answers.update(item.get("answers", []))
    return answers


def build_pollution_probe_domains(token):
    return [
        f"{token}-pollution-{index}.{root}"
        for index, root in enumerate(POLLUTION_PROBE_ROOTS)
    ]


def _successful_references(doh_references, domain, labels=None):
    references = []
    for label, item in doh_references.get(domain, {}).items():
        if labels is not None and label not in labels:
            continue
        if item.get("status") is not None and not item.get("error"):
            references.append(item)
    return references


def _references_expect_no_address(doh_references, domain):
    trusted = _successful_references(doh_references, domain, TRUSTED_DOH_LABELS)
    references = trusted or _successful_references(doh_references, domain)
    return bool(references) and all(
        item.get("status") in (0, 3) and not item.get("answers")
        for item in references
    )


def _suspicious_addresses(answers):
    suspicious = []
    for answer in answers:
        try:
            address = ipaddress.ip_address(answer)
        except ValueError:
            suspicious.append(answer)
            continue
        if not address.is_global:
            suspicious.append(answer)
    return suspicious


def _reused_unverified_addresses(sensitive_results, doh_references):
    domains_by_address = {}
    for domain, result in sensitive_results.items():
        references = _reference_answers(doh_references, domain)
        for answer in result.get("answers", []):
            if answer not in references:
                domains_by_address.setdefault(answer, set()).add(domain)
    return {
        address: sorted(domains)
        for address, domains in domains_by_address.items()
        if len(domains) >= 3
    }


def calculate_cleanliness(integrity, doh_references):
    total = integrity.get("nxdomain_total", 0)
    nxdomain_pct = integrity.get("nxdomain_clean", 0) / total if total else 0
    sensitive_results = integrity.get("sensitive_results", {})
    reused_addresses = _reused_unverified_addresses(sensitive_results, doh_references)
    sensitive_credit = 0.0
    sensitive_checks = {}
    for domain, result in sensitive_results.items():
        expected = _reference_answers(doh_references, domain)
        answers = set(result.get("answers", []))
        suspicious = _suspicious_addresses(answers)
        reused = sorted(answer for answer in answers if answer in reused_addresses)
        if not result.get("ok"):
            verdict = "query_failed"
            credit = 0.0
        elif result.get("rcode") != 0:
            verdict = f"rcode_{result.get('rcode')}"
            credit = 0.0
        elif not answers:
            verdict = "empty_answer"
            credit = 0.0
        elif suspicious:
            verdict = "non_global_address"
            credit = 0.0
        elif reused:
            verdict = "cross_domain_reuse"
            credit = 0.0
        elif expected and answers.intersection(expected):
            verdict = "reference_match"
            credit = 1.0
        elif expected:
            verdict = "reference_mismatch_unverified"
            credit = 0.5
        else:
            verdict = "plausible_no_reference"
            credit = 0.5
        sensitive_credit += credit
        clean = True if credit == 1.0 else False if credit == 0.0 else None
        sensitive_checks[domain] = {
            "clean": clean,
            "score_credit": credit,
            "verdict": verdict,
            "answers": sorted(answers),
            "reference_answers": sorted(expected),
            "suspicious_answers": suspicious,
            "reused_answers": reused,
        }
    sensitive_pct = sensitive_credit / len(sensitive_results) if sensitive_results else 0

    probe_results = integrity.get("pollution_probe_results", {})
    probe_clean = 0
    probe_evaluated = 0
    probe_checks = {}
    for domain, result in probe_results.items():
        expected_empty = _references_expect_no_address(doh_references, domain)
        answers = set(result.get("answers", []))
        if not expected_empty:
            verdict = "reference_inconclusive"
            clean = None
        elif not result.get("ok"):
            verdict = "query_failed"
            clean = False
        elif answers:
            verdict = "injected_address"
            clean = False
        elif result.get("rcode") in (0, 3):
            verdict = "clean_negative"
            clean = True
        else:
            verdict = f"rcode_{result.get('rcode')}"
            clean = False
        if clean is not None:
            probe_evaluated += 1
            probe_clean += int(clean)
        probe_checks[domain] = {
            "clean": clean,
            "verdict": verdict,
            "answers": sorted(answers),
            "reference_expected_empty": expected_empty,
        }
    probe_pct = probe_clean / probe_evaluated if probe_evaluated else 0

    known_results = integrity.get("known_answer_results", {})
    known_clean = 0
    known_checks = {}
    for domain, expected in KNOWN_ANSWER_DOMAINS.items():
        result = known_results.get(domain, {})
        answers = set(result.get("answers", []))
        clean = bool(result.get("ok") and result.get("rcode") == 0 and answers.intersection(expected))
        known_clean += int(clean)
        known_checks[domain] = {
            "clean": clean,
            "answers": sorted(answers),
            "expected_answers": sorted(expected),
        }
    known_pct = known_clean / len(KNOWN_ANSWER_DOMAINS) if KNOWN_ANSWER_DOMAINS else 0

    valid_result = integrity.get("dnssec_valid", {})
    bogus_result = integrity.get("dnssec_bogus", {})
    valid_dnssec = bool(valid_result.get("ok") and valid_result.get("flags", {}).get("ad"))
    bogus_blocked = bool(bogus_result.get("ok") and bogus_result.get("rcode") in (2, 5))
    tcp_ok = bool(integrity.get("tcp_query", {}).get("ok"))
    components = [
        (0.30, nxdomain_pct, total > 0),
        (0.30, probe_pct, probe_evaluated > 0),
        (0.25, sensitive_pct, bool(sensitive_results)),
        (0.05, known_pct, bool(known_results)),
        (0.05, float(valid_dnssec), True),
        (0.03, float(bogus_blocked), True),
        (0.02, float(tcp_ok), True),
    ]
    active_weight = sum(weight for weight, _, active in components if active)
    weighted_score = sum(weight * value for weight, value, active in components if active)
    score = 100 * weighted_score / active_weight if active_weight else 0
    return {
        "score_pct": round(score, 2),
        "nxdomain_pct": round(100 * nxdomain_pct, 2),
        "pollution_probe_pct": round(100 * probe_pct, 2),
        "pollution_probe_evaluated": probe_evaluated,
        "active_weight_pct": round(100 * active_weight, 2),
        "sensitive_pct": round(100 * sensitive_pct, 2),
        "known_answer_pct": round(100 * known_pct, 2),
        "dnssec_valid": valid_dnssec,
        "dnssec_bogus_blocked": bogus_blocked,
        "tcp_pct": 100 if tcp_ok else 0,
        "suspected_reused_addresses": reused_addresses,
        "sensitive_checks": sensitive_checks,
        "pollution_probe_checks": probe_checks,
        "known_answer_checks": known_checks,
    }


async def collect_doh_references(domains, trusted_only_domains, timeout):
    endpoints = {
        "GoogleDoH": "https://dns.google/resolve",
        "CloudflareDoH": "https://cloudflare-dns.com/dns-query",
        "AliDoH": "https://dns.alidns.com/resolve",
        "DNSPodDoH": "https://doh.pub/resolve",
    }
    trusted_only_domains = set(trusted_only_domains)
    loop = asyncio.get_running_loop()
    jobs = {
        (domain, label): loop.run_in_executor(
            None, functools.partial(doh_json, endpoint, domain, timeout)
        )
        for domain in domains
        for label, endpoint in endpoints.items()
        if domain not in trusted_only_domains or label in TRUSTED_DOH_LABELS
    }
    references = {domain: {} for domain in domains}
    for (domain, label), job in jobs.items():
        try:
            references[domain][label] = await job
        except Exception as exc:
            references[domain][label] = {"error": f"{type(exc).__name__}: {exc}"}
    return references


async def run_resolver_async(label, server, args, token):
    print(f"Testing {label} {server}", flush=True)
    ip_version = ipaddress.ip_address(server).version
    if ip_version == 6 and not args.ipv6_enabled:
        return {
            "server": server,
            "ip_version": ip_version,
            "skip_reason": "no IPv6 route detected; use --force-ipv6 to override",
            "skipped": True,
        }
    client = AsyncDnsClient(server, args.timeout)
    try:
        await client.start()
        reachability_probes = [
            ("baidu.com", "A"),
            ("baidu.com", "AAAA"),
            ("qq.com", "A"),
            ("qq.com", "AAAA"),
        ]
        reachability_samples = await asyncio.gather(*(
            client.query(domain, qtype=qtype)
            for domain, qtype in reachability_probes
        ))
        for sample, (domain, qtype) in zip(reachability_samples, reachability_probes):
            sample.update({"domain": domain, "qtype": qtype})
        reachability = summarize_queries(reachability_samples)
        if not any(item["ok"] for item in reachability_samples):
            return {
                "server": server,
                "ip_version": ip_version,
                "reachability": reachability,
                "reachability_samples": reachability_samples,
                "skip_reason": "no A or AAAA probe received a DNS response",
                "skipped": True,
            }
        latency_summary, latency_samples = await run_latency_async(
            client, args.repeats, args.latency_workers
        )
        integrity = await run_integrity_async(client, server, token)
        concurrency = {}
        for workers in args.concurrency_levels:
            concurrency[str(workers)] = await run_concurrency_async(client, workers, args.requests)
        return {
            "server": server,
            "ip_version": ip_version,
            "reachability": reachability,
            "reachability_samples": reachability_samples,
            "latency": latency_summary, "latency_samples": latency_samples,
            "integrity": integrity, "concurrency": concurrency, "skipped": False,
        }
    except Exception as exc:
        return {
            "server": server,
            "ip_version": ip_version,
            "skip_reason": "transport setup failed",
            "skipped": True,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        client.close()


def parse_concurrency_levels(value):
    levels = sorted({int(item.strip()) for item in value.split(",") if item.strip()})
    if not levels or any(level < 1 for level in levels):
        raise ValueError("--concurrency-levels must contain positive integers")
    return levels


def _number(value, default):
    return default if value is None else value


def rank_resolvers(resolvers, levels):
    level64 = str(64)
    level128 = str(128)

    def key(item):
        _, result = item
        latency = result.get("latency", {})
        concurrency = result.get("concurrency", {})
        clean = result.get("integrity", {}).get("cleanliness", {})
        clean_score = clean.get("score_pct")
        qps64 = concurrency.get(level64, {}).get("successful_qps")
        perf128 = concurrency.get(level128, {}).get("successful_qps")
        if perf128 is None and level128 not in concurrency and levels:
            perf128 = concurrency.get(str(max(levels)), {}).get("successful_qps")
        return (
            bool(result.get("skipped")),
            not result.get("skipped") and clean_score is not None and clean_score <= 10,
            -_number(latency.get("success_pct"), -1),
            _number(latency.get("median_ms"), float("inf")),
            _number(latency.get("p95_ms"), float("inf")),
            -_number(clean_score, -1),
            -_number(qps64, -1),
            -_number(perf128, -1),
        )

    return sorted(resolvers.items(), key=key)


def _metric_text(value, suffix=""):
    return "-" if value is None else f"{value}{suffix}"


async def async_main(args):
    token = f"codex-dns-{int(time.time())}-{random.randrange(100000)}"
    ipv6_route_detected = _has_ipv6_route()
    args.ipv6_enabled = ipv6_route_detected or args.force_ipv6
    pollution_probe_domains = build_pollution_probe_domains(token)
    reference_domains = SENSITIVE_DOMAINS + pollution_probe_domains
    doh_task = asyncio.create_task(
        collect_doh_references(
            reference_domains, pollution_probe_domains, args.doh_timeout
        )
    )
    output = {
        "started_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "method": {
            "latency_repeats": args.repeats, "concurrent_requests": args.requests,
            "concurrency_levels": args.concurrency_levels,
            "parallel_resolvers": args.parallel_resolvers,
            "latency_workers": args.latency_workers,
            "timeout": args.timeout, "doh_timeout": args.doh_timeout,
            "ipv6_route_detected": ipv6_route_detected,
            "force_ipv6": args.force_ipv6,
            "resolver_file": str(args.resolvers),
        },
        "resolvers": {}, "doh_references": {},
    }
    resolver_gate = asyncio.Semaphore(args.parallel_resolvers)
    completed = 0
    total = len(RESOLVERS)
    if not ipv6_route_detected:
        action = "testing anyway because --force-ipv6 is set" if args.force_ipv6 else "IPv6 resolvers will be skipped"
        print(f"Warning: no usable IPv6 route was detected; {action}.", flush=True)
    print(
        f"Starting {total} resolver tests; DoH references are loading in background.",
        flush=True,
    )

    async def one(label, server):
        nonlocal completed
        async with resolver_gate:
            started = time.perf_counter()
            result = await run_resolver_async(label, server, args, token)
            completed += 1
            status = "SKIP" if result.get("skipped") else "DONE"
            elapsed = time.perf_counter() - started
            print(
                f"Completed {label} {server} [{completed}/{total}] "
                f"{status} in {elapsed:.1f}s",
                flush=True,
            )
            return label, result

    results = await asyncio.gather(*(one(label, server) for label, server in RESOLVERS.items()))
    output["resolvers"] = dict(results)
    if not doh_task.done():
        print("Resolver tests finished; waiting for DoH references...", flush=True)
    output["doh_references"] = await doh_task
    for result in output["resolvers"].values():
        integrity = result.get("integrity")
        if integrity is not None:
            integrity["cleanliness"] = calculate_cleanliness(
                integrity, output["doh_references"]
            )
    output["finished_at"] = datetime.now(timezone.utc).astimezone().isoformat()
    write_txt_report(output, args.output, args.concurrency_levels)
    print(f"TXT report saved: {args.output}", flush=True)
    if args.json_output:
        print(f"Writing JSON details: {args.json_output}", flush=True)
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, ensure_ascii=False, indent=2)
        print(f"JSON details saved: {args.json_output}", flush=True)


def _fit_cell(value, width, align="left"):
    text = "-" if value is None else str(value)
    if len(text) > width:
        text = text[:max(1, width - 1)] + "~"
    if align == "right":
        return text.rjust(width)
    if align == "center":
        return text.center(width)
    return text.ljust(width)


def _render_table(headers, rows, widths, alignments):
    def tab_row(values, row_alignments):
        return "\t".join(
            _fit_cell(value, width, align)
            for value, width, align in zip(values, widths, row_alignments)
        )

    lines = [tab_row(headers, ["center"] * len(headers))]
    lines.append("\t".join("-" * width for width in widths))
    for row in rows:
        lines.append(tab_row(row, alignments))
    lines.append("\t".join("-" * width for width in widths))
    return lines


def write_txt_report(output, path, levels):
    """Write a fixed-width report that remains aligned in plain-text viewers."""
    ranked = rank_resolvers(output["resolvers"], levels)
    rows = []
    for rank, (label, result) in enumerate(ranked, 1):
        latency = result.get("latency", {})
        concurrency = result.get("concurrency", {})
        clean = result.get("integrity", {}).get("cleanliness", {})
        level64 = concurrency.get("64", {})
        level128 = concurrency.get("128", {})
        if not level128 and levels:
            level128 = concurrency.get(str(max(levels)), {})
        rows.append([
            rank,
            label,
            result.get("server", "-"),
            _metric_text(latency.get("success_pct"), "%"),
            _metric_text(latency.get("median_ms")),
            _metric_text(latency.get("p95_ms")),
            _metric_text(clean.get("score_pct"), "%"),
            _metric_text(level64.get("successful_qps")),
            _metric_text(level128.get("success_pct"), "%"),
            _metric_text(level128.get("successful_qps")),
            "SKIP" if result.get("skipped") else "DONE",
        ])

    headers = [
        "Rank", "Name", "Resolver", "Success", "DNSMed(ms)", "P95(ms)",
        "Clean", "QPS@64", "128 OK", "QPS@128", "Status",
    ]
    widths = [4, 34, 39, 9, 10, 9, 7, 9, 8, 9, 6]
    alignments = ["right", "left", "left", "right", "right", "right", "right", "right", "right", "right", "center"]
    lines = [
        "DNS Benchmark Report",
        "=" * 30,
        f"Start : {output['started_at']}",
        f"Finish: {output['finished_at']}",
        "Config:",
        f"  Latency repeats={output['method']['latency_repeats']} | Requests/level={output['method']['concurrent_requests']} | Levels={','.join(map(str, levels))}",
        f"  Parallel resolvers={output['method']['parallel_resolvers']} | Latency workers={output['method']['latency_workers']} | Timeout={output['method']['timeout']}s | DoH timeout={output['method']['doh_timeout']}s",
        "Sort  : DONE Clean>10 first, DONE Clean<=10 next, SKIP last; within DONE groups: Success(desc), DNS median(asc), DNS P95(asc), Clean(desc), QPS@64(desc), 128 performance(desc)",
        "",
    ]
    lines.extend(_render_table(headers, rows, widths, alignments))
    lines.extend([
        "",
        "Notes:",
        "  Latency is DNS UDP round-trip time, not ICMP ping RTT; DNS caching and resolver processing can make it differ from ping.",
        "  IPv6 reachability uses A and AAAA probes; ranked latency/concurrency tests remain A-record queries over IPv6 transport.",
        "  IPv6 entries are skipped immediately when no route is detected unless --force-ipv6 is used.",
        "  128 OK = success rate at 128 concurrent requests; QPS columns count successful responses.",
        "  Clean score = NXDOMAIN 30% + pollution probes 30% + sensitive domains 25% + known answers 5% + valid DNSSEC 5% + bogus DNSSEC blocked 3% + TCP 2%.",
        "  Pollution probes use randomized sensitive subdomains and trusted DoH baselines; unavailable baseline weights are excluded.",
        "  Exact IP mismatches alone are inconclusive because CDN and geographic answers can differ; JSON output includes per-domain verdicts.",
    ])
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    global RESOLVERS
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--requests", type=int, default=192)
    parser.add_argument("--concurrency-levels", default="64,128", help="Comma-separated concurrency levels (default: 64,128)")
    parser.add_argument("--parallel-resolvers", type=int, default=32, help="Resolvers tested at the same time")
    parser.add_argument("--latency-workers", type=int, default=4, help="Low-concurrency workers per resolver for ordinary latency samples (default: 4)")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--doh-timeout", type=float, default=3.0, help="Timeout for each DNS-over-HTTPS reference query (default: 3.0)")
    parser.add_argument("--force-ipv6", action="store_true", help="Test IPv6 resolvers even when automatic route detection fails")
    parser.add_argument("--resolvers", type=Path, default=DEFAULT_RESOLVERS_PATH, help="Resolver JSON path (default: resolvers.json beside the script)")
    parser.add_argument("--output", required=True, help="TXT report path")
    parser.add_argument("--json-output", help="Optional full JSON detail path")
    args = parser.parse_args()
    if (args.repeats < 1 or args.requests < 1 or args.parallel_resolvers < 1 or
            args.latency_workers < 1 or args.timeout <= 0 or args.doh_timeout <= 0):
        parser.error("count options must be positive and timeouts must be greater than zero")
    try:
        args.concurrency_levels = parse_concurrency_levels(args.concurrency_levels)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        RESOLVERS = load_resolvers(args.resolvers)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load resolver JSON {args.resolvers}: {exc}")
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
