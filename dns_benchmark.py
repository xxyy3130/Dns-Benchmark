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


RESOLVERS = {
    "AliDNS-1": "223.5.5.5",
    "AliDNS-2": "223.6.6.6",
    "DNSPod-1": "119.29.29.29",
    "Volcengine-IDC-1": "180.184.1.1",
    "Volcengine-IDC-2": "180.184.2.2",
    "Tsinghua-TUNA666": "101.6.6.6",
    "USTC-LUG-1": "202.38.93.153",
    "USTC-LUG-2": "202.141.162.123",
    "HKBN-1": "203.80.96.10",
    "HKBN-2": "203.80.96.9",
    "HKBN-3": "203.186.94.20",
    "HKBN-4": "203.186.94.22",
    "HGC-1": "210.0.128.250",
    "HGC-2": "210.0.128.251",
    "I-CABLE-1": "61.10.0.130",
    "I-CABLE-2": "61.10.1.130",
    "CMHK-1": "203.142.100.18",
    "CMHK-2": "203.142.100.21",
    "BaiduDNS-1": "180.76.76.76",
    "360DNS-1": "101.226.4.6",
    "360DNS-2": "218.30.118.6",
    "114DNS-Standard-1": "114.114.114.114",
    "114DNS-Standard-2": "114.114.115.115",
    "114DNS-Security-1": "114.114.114.119",
    "114DNS-Security-2": "114.114.115.119",
    "114DNS-Family-1": "114.114.114.110",
    "114DNS-Family-2": "114.114.115.110",
    "CNNIC-SDNS-1": "1.2.4.8",
    "CNNIC-SDNS-2": "210.2.4.8",
    "Auth-CN-1": "203.119.25.1",
    "Auth-CN-2": "203.119.26.1",
    "Auth-CN-3": "203.119.27.1",
    "Auth-CN-4": "203.119.28.1",
    "Auth-CN-5": "203.119.29.1",
    "Auth-CN-6": "202.112.0.44",
    "Auth-CN-7": "125.208.32.1",
    "Auth-CN-8": "125.208.33.1",
    "Auth-CN-9": "125.208.34.1",
    "Auth-CN-10": "125.208.35.1",
    "Auth-CN-11": "125.208.36.1",
    "Auth-CN-12": "125.208.40.1",
    "Auth-CN-13": "125.208.41.1",
    "Auth-CN-14": "125.208.42.1",
    "Auth-CN-15": "125.208.43.1",
    "Auth-CN-16": "125.208.44.1",
    "CT-Beijing-P1": "219.141.136.10",
    "CT-Beijing-B1": "219.141.140.10",
    "CT-Shanghai-P1": "202.96.209.133",
    "CT-Shanghai-P2": "202.96.209.5",
    "CT-Shanghai-B1": "116.228.111.118",
    "CT-Shanghai-B2": "180.168.255.118",
    "CT-Tianjin-P1": "219.150.32.132",
    "CT-Tianjin-B1": "219.146.0.132",
    "CT-Chongqing-P1": "61.128.192.68",
    "CT-Chongqing-B1": "61.128.128.68",
    "CT-Anhui-P1": "61.132.163.68",
    "CT-Anhui-P2": "202.102.192.68",
    "CT-Anhui-B1": "202.102.213.68",
    "CT-Fujian-P1": "218.85.152.99",
    "CT-Fujian-B1": "218.85.157.99",
    "CT-Gansu-P1": "202.100.64.68",
    "CT-Gansu-B1": "61.178.0.93",
    "CT-Guangdong-P1": "202.96.128.86",
    "CT-Guangdong-P2": "202.96.134.133",
    "CT-Guangdong-P3": "202.96.154.8",
    "CT-Guangdong-B1": "202.96.128.166",
    "CT-Guangdong-B2": "202.96.128.68",
    "CT-Guangdong-B3": "202.96.154.15",
    "CT-Guangxi-P1": "202.103.225.68",
    "CT-Guangxi-B1": "202.103.224.68",
    "CT-Guizhou-P1": "202.98.192.67",
    "CT-Guizhou-B1": "202.98.198.167",
    "CT-Henan-P1": "222.88.88.88",
    "CT-Henan-P2": "219.150.150.150",
    "CT-Henan-B1": "222.85.85.85",
    "CT-Henan-B2": "222.88.93.126",
    "CT-Heilongjiang-P1": "219.147.198.230",
    "CT-Heilongjiang-P2": "112.100.100.100",
    "CT-Heilongjiang-B1": "219.147.198.242",
    "CT-Hubei-P1": "202.103.24.68",
    "CT-Hubei-P2": "202.103.44.150",
    "CT-Hubei-B1": "202.103.0.68",
    "CT-Hunan-P1": "59.51.78.211",
    "CT-Hunan-P2": "222.246.129.80",
    "CT-Hunan-B1": "59.51.78.210",
    "CT-Hunan-B2": "222.246.129.81",
    "CT-Jiangsu-P1": "218.2.2.2",
    "CT-Jiangsu-P2": "61.147.37.1",
    "CT-Jiangsu-B1": "218.4.4.4",
    "CT-Jiangsu-B2": "218.2.135.1",
    "CT-Jiangxi-P1": "202.101.224.69",
    "CT-Jiangxi-P2": "202.101.226.69",
    "CT-Jiangxi-B1": "202.101.226.68",
    "CT-InnerMongolia-P1": "219.148.162.31",
    "CT-InnerMongolia-P2": "222.74.1.200",
    "CT-InnerMongolia-B1": "222.74.39.50",
    "CT-Shandong-P1": "219.146.1.66",
    "CT-Shandong-B1": "219.147.1.66",
    "CT-Shanxi-P1": "59.49.49.49",
    "CT-Shaanxi-P1": "218.30.19.40",
    "CT-Shaanxi-B1": "61.134.1.4",
    "CT-Sichuan-P1": "61.139.2.69",
    "CT-Sichuan-B1": "218.6.200.139",
    "CT-Yunnan-P1": "222.172.200.68",
    "CT-Yunnan-B1": "61.166.150.123",
    "CT-Zhejiang-P1": "202.101.172.35",
    "CT-Zhejiang-P2": "61.153.81.75",
    "CT-Zhejiang-P3": "60.191.134.206",
    "CT-Zhejiang-B1": "202.101.172.47",
    "CT-Zhejiang-B2": "61.153.177.196",
    "CT-Zhejiang-B3": "60.191.244.5",
    "CT-Hebei-P1": "222.222.202.202",
    "CT-Hainan-P1": "202.100.192.68",
    "CT-Liaoning-P1": "219.148.204.66",
    "CT-Jilin-P1": "219.149.194.55",
    "CT-Xinjiang-P1": "61.128.114.167",
    "CU-Beijing-P1": "123.123.123.123",
    "CU-Beijing-P2": "202.106.0.20",
    "CU-Beijing-B1": "123.123.123.124",
    "CU-Beijing-B2": "202.106.195.68",
    "CU-Shanghai-P1": "210.22.70.3",
    "CU-Shanghai-P2": "210.22.70.225",
    "CU-Shanghai-B1": "210.22.84.3",
    "CU-Tianjin-P1": "202.99.104.68",
    "CU-Tianjin-B1": "202.99.96.68",
    "CU-Chongqing-P1": "221.5.203.98",
    "CU-Chongqing-B1": "221.7.92.98",
    "CU-Guangdong-P1": "210.21.196.6",
    "CU-Guangdong-P2": "210.21.4.130",
    "CU-Guangdong-B1": "221.5.88.88",
    "CU-Hebei-P1": "202.99.160.68",
    "CU-Hebei-B1": "202.99.166.4",
    "CU-Henan-P1": "202.102.224.68",
    "CU-Henan-B1": "202.102.227.68",
    "CU-Heilongjiang-P1": "202.97.224.69",
    "CU-Heilongjiang-B1": "202.97.224.68",
    "CU-Jilin-P1": "202.98.0.68",
    "CU-Jilin-B1": "202.98.5.68",
    "CU-Jiangsu-P1": "221.6.4.66",
    "CU-Jiangsu-P2": "58.240.57.33",
    "CU-Jiangsu-B1": "221.6.4.67",
    "CU-InnerMongolia-P1": "202.99.224.68",
    "CU-InnerMongolia-B1": "202.99.224.8",
    "CU-Shandong-P1": "202.102.128.68",
    "CU-Shandong-P2": "202.102.134.68",
    "CU-Shandong-B1": "202.102.152.3",
    "CU-Shandong-B2": "202.102.154.3",
    "CU-Shanxi-P1": "202.99.192.66",
    "CU-Shanxi-P2": "202.97.131.178",
    "CU-Shanxi-B1": "202.99.192.68",
    "CU-Shaanxi-P1": "221.11.1.67",
    "CU-Shaanxi-B1": "221.11.1.68",
    "CU-Sichuan-P1": "119.6.6.6",
    "CU-Sichuan-B1": "124.161.87.155",
    "CU-Zhejiang-P1": "221.12.1.227",
    "CU-Zhejiang-P2": "221.12.33.227",
    "CU-Zhejiang-B1": "221.12.65.227",
    "CU-Liaoning-P1": "202.96.69.38",
    "CU-Liaoning-B1": "202.96.64.68",
    "CU-Guizhou-P1": "221.13.30.242",
    "CU-Gansu-P1": "221.7.34.11",
    "CU-Ningxia-P1": "221.199.12.157",
    "CU-Jiangxi-P1": "220.248.192.12",
    "CU-Guangxi-P1": "221.7.128.68",
    "CU-Tibet-P1": "221.13.65.34",
    "CU-Hainan-P1": "221.11.132.2",
    "CU-Hunan-P1": "58.20.127.238",
    "CU-Hubei-P1": "218.104.111.122",
    "CU-Anhui-P1": "218.104.78.2",
    "CU-Anhui-P2": "58.242.2.2",
    "CU-Fujian-P1": "218.104.128.106",
    "CU-Xinjiang-P1": "221.7.1.20",
    "CU-Yunnan-P1": "221.3.131.11",
    "CM-Beijing-P1": "211.138.30.66",
    "CM-Beijing-P2": "211.136.28.231",
    "CM-Beijing-P3": "211.136.28.237",
    "CM-Beijing-P4": "221.130.32.103",
    "CM-Beijing-P5": "221.130.32.106",
    "CM-Beijing-P6": "221.176.3.70",
    "CM-Beijing-P7": "221.176.3.76",
    "CM-Beijing-P8": "221.176.3.83",
    "CM-Beijing-P9": "221.176.4.6",
    "CM-Beijing-P10": "221.176.4.12",
    "CM-Beijing-P11": "221.176.4.18",
    "CM-Beijing-P12": "221.130.33.52",
    "CM-Beijing-B1": "211.136.17.107",
    "CM-Beijing-B2": "211.136.28.234",
    "CM-Beijing-B3": "211.136.28.228",
    "CM-Beijing-B4": "221.130.32.100",
    "CM-Beijing-B5": "221.130.32.109",
    "CM-Beijing-B6": "221.176.3.73",
    "CM-Beijing-B7": "221.176.3.79",
    "CM-Beijing-B8": "221.176.3.85",
    "CM-Beijing-B9": "221.176.4.9",
    "CM-Beijing-B10": "221.176.4.15",
    "CM-Beijing-B11": "221.176.4.21",
    "CM-Beijing-B12": "221.179.155.193",
    "CM-Shanghai-P1": "211.136.112.50",
    "CM-Shanghai-P2": "211.136.18.171",
    "CM-Shanghai-B1": "211.136.150.66",
    "CM-Tianjin-P1": "211.137.160.50",
    "CM-Tianjin-B1": "211.137.160.185",
    "CM-Chongqing-P1": "218.201.4.3",
    "CM-Chongqing-P2": "218.201.17.2",
    "CM-Chongqing-B1": "218.201.21.132",
    "CM-Anhui-P1": "211.138.180.2",
    "CM-Anhui-B1": "211.138.180.3",
    "CM-Shandong-P1": "218.201.96.130",
    "CM-Shandong-P2": "218.201.124.18",
    "CM-Shandong-B1": "211.137.191.26",
    "CM-Shandong-B2": "218.201.124.19",
    "CM-Shanxi-P1": "211.138.106.2",
    "CM-Shanxi-P2": "211.138.106.18",
    "CM-Shanxi-P3": "211.138.106.7",
    "CM-Shanxi-B1": "211.138.106.3",
    "CM-Shanxi-B2": "211.138.106.19",
    "CM-Jiangsu-P1": "221.131.143.69",
    "CM-Jiangsu-P2": "221.130.13.133",
    "CM-Jiangsu-P3": "221.130.56.241",
    "CM-Jiangsu-P4": "211.138.200.69",
    "CM-Jiangsu-B1": "112.4.0.55",
    "CM-Jiangsu-B2": "211.103.55.50",
    "CM-Jiangsu-B3": "211.103.13.101",
    "CM-Zhejiang-P1": "211.140.13.188",
    "CM-Zhejiang-P2": "211.140.10.2",
    "CM-Zhejiang-B1": "211.140.188.188",
    "CM-Hunan-P1": "211.142.210.98",
    "CM-Hunan-P2": "211.142.210.100",
    "CM-Hunan-P3": "211.142.211.124",
    "CM-Hunan-B1": "211.142.210.99",
    "CM-Hunan-B2": "211.142.210.101",
    "CM-Hunan-B3": "211.142.236.87",
    "CM-Hubei-P1": "211.137.58.20",
    "CM-Hubei-B1": "211.137.64.163",
    "CM-Jiangxi-P1": "211.141.90.68",
    "CM-Jiangxi-P2": "211.141.85.68",
    "CM-Jiangxi-B1": "211.141.90.69",
    "CM-Shaanxi-P1": "211.137.130.3",
    "CM-Shaanxi-P2": "218.200.6.139",
    "CM-Shaanxi-B1": "211.137.130.19",
    "CM-Sichuan-P1": "211.137.82.4",
    "CM-Sichuan-B1": "211.137.96.205",
    "CM-Guangdong-P1": "211.136.20.203",
    "CM-Guangdong-P2": "211.136.192.6",
    "CM-Guangdong-P3": "211.139.163.6",
    "CM-Guangdong-B1": "211.136.20.204",
    "CM-Guangdong-B2": "211.139.136.68",
    "CM-Guangdong-B3": "120.196.165.24",
    "CM-Guangxi-P1": "211.138.245.180",
    "CM-Guangxi-P2": "211.138.240.100",
    "CM-Guangxi-B1": "211.136.17.108",
    "CM-Guizhou-P1": "211.139.5.29",
    "CM-Guizhou-B1": "211.139.5.30",
    "CM-Fujian-P1": "211.138.151.161",
    "CM-Fujian-P2": "218.207.217.241",
    "CM-Fujian-P3": "211.143.181.178",
    "CM-Fujian-P4": "218.207.128.4",
    "CM-Fujian-P5": "211.138.145.194",
    "CM-Fujian-B1": "211.138.156.66",
    "CM-Fujian-B2": "218.207.217.242",
    "CM-Fujian-B3": "211.143.181.179",
    "CM-Fujian-B4": "218.207.130.118",
    "CM-Hebei-P1": "211.143.60.56",
    "CM-Hebei-P2": "111.11.1.1",
    "CM-Hebei-B1": "211.138.13.66",
    "CM-Henan-P1": "211.138.24.66",
    "CM-Gansu-P1": "218.203.160.194",
    "CM-Gansu-P2": "211.139.80.6",
    "CM-Gansu-B1": "218.203.160.195",
    "CM-Heilongjiang-P1": "211.137.241.34",
    "CM-Heilongjiang-P2": "218.203.59.216",
    "CM-Heilongjiang-B1": "211.137.241.35",
    "CM-Jilin-P1": "211.141.16.99",
    "CM-Jilin-B1": "211.141.0.99",
    "CM-Liaoning-P1": "211.137.32.178",
    "CM-Liaoning-B1": "211.140.197.58",
    "CM-Yunnan-P1": "211.139.29.68",
    "CM-Yunnan-P2": "211.139.29.150",
    "CM-Yunnan-P3": "218.202.1.166",
    "CM-Yunnan-B1": "211.139.29.69",
    "CM-Yunnan-B2": "211.139.29.170",
    "CM-Hainan-P1": "221.176.88.95",
    "CM-Hainan-B1": "211.138.164.6",
    "CM-InnerMongolia-P1": "211.138.91.1",
    "CM-InnerMongolia-B1": "211.138.91.2",
    "CM-Xinjiang-P1": "218.202.152.130",
    "CM-Xinjiang-B1": "218.202.152.131",
    "CM-Tibet-P1": "211.139.73.34",
    "CM-Tibet-P2": "211.139.73.50",
    "CM-Tibet-B1": "211.139.73.35",
    "CM-Qinghai-P1": "211.138.75.123",
    "CM-Ningxia-P1": "218.203.123.116",
}

# Based on current longest-prefix BGP origins. Public DNS services using their
# own Alibaba, Tencent, Volcengine, Baidu, CNNIC, or 114DNS networks remain
# untagged.
CARRIER_NAME_PREFIXES = {
    "CT-": "Telecom",
    "CU-": "Unicom",
    "CM-": "Mobile",
}

CARRIER_IPS = {
    "Telecom": {
        "202.141.162.123",  # USTC-LUG-2, currently announced by AS4134
        "101.226.4.6",      # 360DNS-1, China Telecom Shanghai
        "218.30.118.6",     # 360DNS-2, China Telecom
    },
    "Unicom": set(),
    "Mobile": set(),
    "Tietong": set(),
    "Education": {
        "101.6.6.6",        # Tsinghua University / CERNET
        "202.38.93.153",    # USTC / CERNET
        "202.112.0.44",     # Auth-CN / CERNET
        "203.119.25.1",
        "203.119.26.1",
        "203.119.27.1",
        "203.119.28.1",
        "203.119.29.1",
        "125.208.32.1",
        "125.208.33.1",
        "125.208.34.1",
        "125.208.35.1",
        "125.208.36.1",
        "125.208.40.1",
        "125.208.41.1",
        "125.208.42.1",
        "125.208.43.1",
        "125.208.44.1",
    },
}


def _carrier_for_resolver(name, server):
    for carrier, addresses in CARRIER_IPS.items():
        if server in addresses:
            return carrier
    for prefix, carrier in CARRIER_NAME_PREFIXES.items():
        if name.startswith(prefix):
            return carrier
    return None


def _add_carrier_tags(resolvers):
    tagged = {}
    for name, server in resolvers.items():
        carrier = _carrier_for_resolver(name, server)
        display_name = f"[{carrier}] {name}" if carrier else name
        tagged[display_name] = server
    return tagged


RESOLVERS = _add_carrier_tags(RESOLVERS)

DOMAINS = [
    "baidu.com", "qq.com", "taobao.com", "jd.com", "bilibili.com",
    "douyin.com", "weibo.com", "zhihu.com", "gov.cn", "12306.cn",
    "microsoft.com", "github.com", "apple.com", "cloudflare.com",
    "wikipedia.org", "openai.com", "store.steampowered.com", "www.amap.com",
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


def make_query(name, dnssec=False):
    query_id = random.randrange(0, 65536)
    additional = 1 if dnssec else 0
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, additional)
    packet += encode_name(name) + struct.pack("!HH", 1, 1)
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


def dns_query(server, name, timeout=1.5, tcp=False, dnssec=False):
    query_id, packet = make_query(name, dnssec=dnssec)
    started = time.perf_counter()
    try:
        if tcp:
            with socket.create_connection((server, 53), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                length_data = recv_exact(sock, 2)
                response = recv_exact(sock, struct.unpack("!H", length_data)[0])
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (server, 53))
                response, peer = sock.recvfrom(4096)
                if peer[0] != server:
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
        self.transport = None
        self.pending = {}
        self.fallback = False

    async def start(self):
        loop = asyncio.get_running_loop()
        try:
            await loop.create_datagram_endpoint(
                lambda: _DnsDatagramProtocol(self),
                remote_addr=(self.server, 53), family=socket.AF_INET,
            )
        except NotImplementedError:
            self.fallback = True

    def receive(self, data, address):
        if address and address[0] != self.server or len(data) < 2:
            return
        query_id = struct.unpack("!H", data[:2])[0]
        future = self.pending.get(query_id)
        if future is not None and not future.done():
            future.set_result(data)

    def receive_error(self, exc):
        for future in tuple(self.pending.values()):
            if not future.done():
                future.set_exception(exc)

    async def query(self, name, dnssec=False):
        started = time.perf_counter()
        try:
            if self.fallback:
                loop = asyncio.get_running_loop()
                query = functools.partial(dns_query, self.server, name, self.timeout, False, dnssec)
                return await loop.run_in_executor(None, query)
            loop = asyncio.get_running_loop()
            for _ in range(8):
                query_id, packet = make_query(name, dnssec=dnssec)
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
    client = AsyncDnsClient(server, args.timeout)
    try:
        await client.start()
        reachability_samples = await asyncio.gather(*(client.query("baidu.com") for _ in range(3)))
        reachability = summarize_queries(reachability_samples)
        if not any(item["ok"] for item in reachability_samples):
            return {"server": server, "reachability": reachability, "skipped": True}
        latency_summary, latency_samples = await run_latency_async(
            client, args.repeats, args.latency_workers
        )
        integrity = await run_integrity_async(client, server, token)
        concurrency = {}
        for workers in args.concurrency_levels:
            concurrency[str(workers)] = await run_concurrency_async(client, workers, args.requests)
        return {
            "server": server, "reachability": reachability,
            "latency": latency_summary, "latency_samples": latency_samples,
            "integrity": integrity, "concurrency": concurrency, "skipped": False,
        }
    except Exception as exc:
        return {
            "server": server, "skipped": True,
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
        },
        "resolvers": {}, "doh_references": {},
    }
    resolver_gate = asyncio.Semaphore(args.parallel_resolvers)
    completed = 0
    total = len(RESOLVERS)
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
    widths = [4, 34, 15, 9, 10, 9, 7, 9, 8, 9, 6]
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
        "  128 OK = success rate at 128 concurrent requests; QPS columns count successful responses.",
        "  Clean score = NXDOMAIN 30% + pollution probes 30% + sensitive domains 25% + known answers 5% + valid DNSSEC 5% + bogus DNSSEC blocked 3% + TCP 2%.",
        "  Pollution probes use randomized sensitive subdomains and trusted DoH baselines; unavailable baseline weights are excluded.",
        "  Exact IP mismatches alone are inconclusive because CDN and geographic answers can differ; JSON output includes per-domain verdicts.",
    ])
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--requests", type=int, default=192)
    parser.add_argument("--concurrency-levels", default="64,128", help="Comma-separated concurrency levels (default: 64,128)")
    parser.add_argument("--parallel-resolvers", type=int, default=32, help="Resolvers tested at the same time")
    parser.add_argument("--latency-workers", type=int, default=4, help="Low-concurrency workers per resolver for ordinary latency samples (default: 4)")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--doh-timeout", type=float, default=3.0, help="Timeout for each DNS-over-HTTPS reference query (default: 3.0)")
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
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
