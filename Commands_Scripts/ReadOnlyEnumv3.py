#!/usr/bin/env python3
"""
ReadOnlyEnum v3.0.0 - 100% Native Python Read-Only Enumeration & Configuration Audit Tool
Copyright (c) 2026 Isiah Jones. All Rights Reserved.

Comprehensive read-only enumeration for ICS/OT/IoT/IT/Cloud/AI/Cyber-Physical systems.
All protocol implementations are native Python - ZERO external tool dependencies.
Uses only Python standard library: socket, struct, ssl, http.client, urllib, json, subprocess.

For assurance testing, system V&V, and acceptance testing.
"""

import base64
import binascii
import collections
import copy
import datetime
import hashlib
import http.client
import io
import ipaddress
import json
import os
import platform
import re
import select
import socket
import ssl
import string
import struct
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ===============================================================================
# SECTION 1: CONSTANTS & CONFIGURATION
# ===============================================================================

VERSION = "3.0.0"
TOOL_NAME = "ReadOnlyEnum"
COPYRIGHT = "Copyright (c) 2026 Isiah Jones. All Rights Reserved."
BANNER = f"""
+======================================================================+
|                                                                      |
|   ____  _____    _    ____   ___  _   _ _  __                       |
|  |  _ \\| ____|  / \\  |  _ \\ / _ \\| \\ | | |/ /                       |
|  | |_) |  _|   / _ \\ | | | | | | |  \\| | ' /                        |
|  |  _ <| |___ / ___ \\| |_| | |_| | |\\  | . \\                        |
|  |_| \\_|_____/_/   \\_|____/ \\___/|_| \\_|_|\\_\\                       |
|                                                                      |
|   {TOOL_NAME} v{VERSION} - Read-Only Enumeration & Config Audit Tool  |
|   {COPYRIGHT}              |
|                                                                      |
|   [READ-ONLY] No writes, no exploits, no modifications.             |
|   100% Native Python - Zero external tool dependencies.              |
+======================================================================+
"""

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        for attr in ['RED','GREEN','YELLOW','BLUE','MAGENTA','CYAN','WHITE','GRAY','BOLD','RESET']:
            setattr(cls, attr, '')

# ========== STANDALONE FUNCTION (NOT INSIDE THE CLASS) ==========
def supports_ansi_colors():
    """Return True if terminal supports ANSI escape sequences (cross-platform)."""
    if not sys.stdout.isatty():
        return False
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode)
            return True
        except Exception:
            return False
    else:  # Linux, macOS, etc.
        return True
# ================================================================
# ===============================================================================
# SECTION 2: DATA MODELS
# ===============================================================================

class ModuleCategory(Enum):
    ICS_OT_PROTOCOL = "ics_ot"
    IT_PROTOCOL = "it_network"
    WIRELESS_IOT = "wireless_iot"
    CLOUD_AI_PROTOCOL = "cloud_ai"
    OS_CONFIG = "os_config"
    RTOS_CONFIG = "rtos_config"
    DEVICE_CONFIG = "device_config"
    ATTACK_SURFACE = "attack_surface"
    INTERFACE_ENUM = "interface_enum"

@dataclass
class EnumResult:
    module: str; host: str; check: str; output: str
    status: str = "info"; notes: str = ""; timestamp: str = ""
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()

@dataclass
class ScanTarget:
    hosts: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    station_names: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)

@dataclass
class ScanConfig:
    privileged: bool = False; timeout: int = 5; threads: int = 5
    verbose: bool = False; project: str = "ReadOnlyEnum_Scan"
    output_dir: str = "ReadOnlyEnum_Results"

# ===============================================================================
# SECTION 3: NATIVE UTILITY FUNCTIONS (no external tools)
# ===============================================================================

def print_color(msg, color=Colors.WHITE, end='\n'):
    print(f"{color}{msg}{Colors.RESET}", end=end)

def print_section(title):
    print_color(f"\n{'='*70}", Colors.CYAN)
    print_color(f"  {title}", Colors.BOLD + Colors.CYAN)
    print_color(f"{'='*70}", Colors.CYAN)

def print_subsection(title):
    print_color(f"\n  {'-'*60}", Colors.GRAY)
    print_color(f"  {title}", Colors.BOLD + Colors.WHITE)
    print_color(f"  {'-'*60}", Colors.GRAY)

def print_result(check, output, status="info", compliance_findings=None):
    icons = {"success": f"{Colors.GREEN}[+]", "fail": f"{Colors.RED}[x]",
             "info": f"{Colors.BLUE}[i]", "warn": f"{Colors.YELLOW}[!]",
             "skipped": f"{Colors.GRAY}[-]"}
    icon = icons.get(status, icons["info"])
    print(f"  {icon}{Colors.RESET} {Colors.WHITE}{check}{Colors.RESET}")
    if output:
        for line in str(output).split('\n'):
            if line.strip():
                print(f"      {Colors.GRAY}{line.strip()}{Colors.RESET}")
    # Compliance color-coded flags
    if compliance_findings:
        for severity, reqs, desc, fr in compliance_findings:
            color = compliance_color(severity)
            req_str = ", ".join(reqs[:5])
            print(f"      {color}[{severity}]{Colors.RESET} {desc}")
            print(f"      {color}  Reqs: {req_str} | {fr}{Colors.RESET}")

def tcp_connect(host, port, timeout=5):
    """Native TCP connection - returns socket or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        return None

def tcp_probe(host, port, send_data=None, timeout=5, recv_size=4096):
    """Send data over TCP and return response bytes, or None on failure."""
    s = tcp_connect(host, port, timeout)
    if not s:
        return None
    try:
        if send_data:
            s.sendall(send_data)
        s.settimeout(timeout)
        resp = s.recv(recv_size)
        return resp
    except Exception:
        return None
    finally:
        try: s.close()
        except: pass

def udp_probe(host, port, send_data, timeout=5, recv_size=4096):
    """Send data over UDP and return response bytes, or None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(send_data, (host, port))
        resp, addr = s.recvfrom(recv_size)
        s.close()
        return resp
    except Exception:
        return None

def ssl_probe(host, port, timeout=5):
    """Connect via TLS and return cert info dict, or None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cipher = ssock.cipher()
                ver = ssock.version()
                # Also get binary cert for raw info
                der = ssock.getpeercert(binary_form=True)
                return {"cert": cert, "cipher": cipher, "version": ver,
                        "der_len": len(der) if der else 0}
    except Exception:
        return None

def http_get(host, port=80, path="/", use_ssl=False, timeout=5, headers=None):
    """Native HTTP GET using http.client. Returns (status, headers_dict, body_snippet)."""
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        hdrs = {"User-Agent": "ReadOnlyEnum/2.0", "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read(8192).decode('utf-8', errors='replace')
        resp_headers = dict(resp.getheaders())
        conn.close()
        return (resp.status, resp_headers, body[:4096])
    except Exception as e:
        return (0, {}, str(e))

def http_request(method, url, data=None, headers=None, timeout=5):
    """Native HTTP request using urllib. Returns (status, headers, body)."""
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "ReadOnlyEnum/2.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if data:
            if isinstance(data, str):
                data = data.encode('utf-8')
            req.data = data
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(16384).decode('utf-8', errors='replace')
        return (resp.status, dict(resp.headers), body)
    except urllib.error.HTTPError as e:
        body = e.read(8192).decode('utf-8', errors='replace') if e.fp else ""
        return (e.code, dict(e.headers) if e.headers else {}, body)
    except Exception as e:
        return (0, {}, str(e))

def is_port_open(host, port, timeout=3):
    """Quick TCP port check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def parse_hosts(host_str):
    """Parse host specification: single IP, CIDR, range, or comma-separated."""
    hosts = []
    for part in host_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            try:
                for ip in ipaddress.ip_network(part, strict=False):
                    hosts.append(str(ip))
            except ValueError:
                hosts.append(part)
        elif '-' in part and not part.startswith('-'):
            try:
                base, end = part.rsplit('-', 1)
                base_parts = base.split('.')
                if len(base_parts) == 4:
                    start = int(base_parts[3])
                    end_num = int(end)
                    for i in range(start, end_num + 1):
                        hosts.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
            except (ValueError, IndexError):
                hosts.append(part)
        else:
            hosts.append(part)
    return hosts

def parse_ports(port_str):
    """Parse port specification: single, range, or comma-separated."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return sorted(set(ports))

def run_os_cmd(cmd, timeout=10):
    """Run an OS command via subprocess (for OS/RTOS config enumeration only)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        output = result.stdout.strip()
        if result.stderr.strip() and not output:
            output = result.stderr.strip()
        return output if output else "(no output)"
    except subprocess.TimeoutExpired:
        return "(command timed out)"
    except Exception as e:
        return f"(error: {e})"

def hex_dump(data, max_bytes=64):
    """Format bytes as hex dump string."""
    if not data:
        return "(empty)"
    d = data[:max_bytes]
    hex_str = ' '.join(f'{b:02x}' for b in d)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d)
    result = f"[{len(data)} bytes] {hex_str}"
    if len(data) > max_bytes:
        result += " ..."
    result += f"  |{ascii_str}|"
    return result

def safe_decode(data, max_len=500):
    """Safely decode bytes to string."""
    if not data:
        return "(empty)"
    try:
        return data.decode('utf-8', errors='replace')[:max_len]
    except Exception:
        return hex_dump(data)

# -- ASN.1/BER helpers for SNMP & LDAP ----------------------------------------

def ber_encode_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

def ber_encode_int(value):
    if value == 0:
        return b'\x02\x01\x00'
    result = []
    v = value
    while v > 0:
        result.insert(0, v & 0xFF)
        v >>= 8
    if result[0] & 0x80:
        result.insert(0, 0)
    data = bytes(result)
    return b'\x02' + ber_encode_length(len(data)) + data

def ber_encode_string(value):
    data = value.encode('utf-8') if isinstance(value, str) else value
    return b'\x04' + ber_encode_length(len(data)) + data

def ber_encode_oid(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    if len(parts) < 2:
        return b'\x06\x01\x00'
    encoded = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p < 128:
            encoded.append(p)
        else:
            tmp = []
            while p > 0:
                tmp.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(tmp) - 1):
                tmp[i] |= 0x80
            encoded.extend(tmp)
    data = bytes(encoded)
    return b'\x06' + ber_encode_length(len(data)) + data

def ber_encode_sequence(items):
    data = b''.join(items)
    return b'\x30' + ber_encode_length(len(data)) + data

def ber_decode_tlv(data, offset=0):
    """Decode one TLV from BER data. Returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        return (0, b'', offset)
    tag = data[offset]; offset += 1
    if offset >= len(data):
        return (tag, b'', offset)
    length = data[offset]; offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(data[offset:offset+num_bytes], 'big')
        offset += num_bytes
    value = data[offset:offset+length]
    return (tag, value, offset + length)

def ber_decode_oid(data):
    """Decode BER-encoded OID bytes to string."""
    if not data:
        return ""
    parts = [str(data[0] // 40), str(data[0] % 40)]
    i = 1
    while i < len(data):
        val = 0
        while i < len(data):
            val = (val << 7) | (data[i] & 0x7F)
            if not (data[i] & 0x80):
                i += 1
                break
            i += 1
        parts.append(str(val))
    return '.'.join(parts)



# ===============================================================================
# SECTION 4: BASE MODULE CLASS
# ===============================================================================

class BaseModule:
    name = "base"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Base module"
    default_ports = []
    requires_root = False

    def __init__(self, config=None, target=None):
        self.config = config or ScanConfig()
        self.target = target or ScanTarget()
        self.results: List[EnumResult] = []

    def _record(self, check, host, output, status="info", notes=""):
        """Record an enumeration result and print it."""
        r = EnumResult(module=self.name, host=host, check=check,
                       output=str(output), status=status, notes=notes)
        self.results.append(r)
        print_result(check, output, status)
        return r

    def _tcp(self, host, port, send_data=None, recv_size=4096):
        return tcp_probe(host, port, send_data, self.config.timeout, recv_size)

    def _udp(self, host, port, send_data, recv_size=4096):
        return udp_probe(host, port, send_data, self.config.timeout, recv_size)

    def _http(self, host, port=80, path="/", use_ssl=False, headers=None):
        return http_get(host, port, path, use_ssl, self.config.timeout, headers)

    def _ssl_info(self, host, port):
        return ssl_probe(host, port, self.config.timeout)

    def _os_cmd(self, cmd):
        return run_os_cmd(cmd, self.config.timeout)

    def run(self, host, ports=None):
        raise NotImplementedError


# ===============================================================================
# SECTION 5: PROTOCOL ENUMERATION MODULES
# ===============================================================================

# -----------------------------------------------------------------------------
# 5.1  ICS / OT PROTOCOL MODULES (39 modules)
# -----------------------------------------------------------------------------

class ModbusTCPModule(BaseModule):
    name = "modbus_tcp"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Modbus/TCP - Read coils, discrete inputs, holding/input registers, device ID (FC01-04,17,43)"
    default_ports = [502]

    def _modbus_request(self, host, port, unit_id, func_code, data=b''):
        """Build and send a Modbus TCP ADU, return response PDU or None."""
        pdu = bytes([unit_id, func_code]) + data
        # MBAP header: transaction_id(2), protocol_id(2)=0, length(2), then PDU
        mbap = struct.pack('>HHH', 1, 0, len(pdu)) + pdu
        resp = self._tcp(host, port, mbap)
        if resp and len(resp) >= 9:
            return resp[7:]  # Strip MBAP header + unit_id
        return resp

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Modbus/TCP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                self._record(f"Port {port} closed", host, "Port not reachable", "skipped")
                continue
            # FC 0x11 - Report Slave ID
            resp = self._modbus_request(host, port, 0, 0x11)
            if resp:
                self._record("FC17 Report Slave ID", host, hex_dump(resp), "success",
                             "Device identity and run status")
            else:
                self._record("FC17 Report Slave ID", host, "No response", "info")
            # FC 0x2B/0x0E - Read Device Identification (MEI)
            resp = self._modbus_request(host, port, 0, 0x2B, bytes([0x0E, 0x01, 0x00]))
            if resp and len(resp) > 2 and resp[0] != (0x2B + 0x80):
                self._record("FC43 Read Device ID", host, hex_dump(resp), "success",
                             "Vendor name, product code, revision")
            # FC 0x01 - Read Coils (address 0, qty 10)
            resp = self._modbus_request(host, port, 1, 0x01, struct.pack('>HH', 0, 10))
            if resp and len(resp) > 1 and resp[0] != 0x81:
                self._record("FC01 Read Coils [0:10]", host, hex_dump(resp), "success")
            # FC 0x02 - Read Discrete Inputs (address 0, qty 10)
            resp = self._modbus_request(host, port, 1, 0x02, struct.pack('>HH', 0, 10))
            if resp and len(resp) > 1 and resp[0] != 0x82:
                self._record("FC02 Read Discrete Inputs [0:10]", host, hex_dump(resp), "success")
            # FC 0x03 - Read Holding Registers (address 0, qty 10)
            resp = self._modbus_request(host, port, 1, 0x03, struct.pack('>HH', 0, 10))
            if resp and len(resp) > 1 and resp[0] != 0x83:
                vals = []
                if len(resp) >= 3:
                    byte_count = resp[1]
                    for i in range(0, byte_count, 2):
                        if i + 3 < len(resp):
                            vals.append(struct.unpack('>H', resp[2+i:4+i])[0])
                self._record("FC03 Read Holding Registers [0:10]", host,
                             f"Values: {vals}" if vals else hex_dump(resp), "success")
            # FC 0x04 - Read Input Registers (address 0, qty 10)
            resp = self._modbus_request(host, port, 1, 0x04, struct.pack('>HH', 0, 10))
            if resp and len(resp) > 1 and resp[0] != 0x84:
                self._record("FC04 Read Input Registers [0:10]", host, hex_dump(resp), "success")
            # Scan for active unit IDs (1-10)
            active_units = []
            for uid in range(1, 11):
                r = self._modbus_request(host, port, uid, 0x03, struct.pack('>HH', 0, 1))
                if r and len(r) > 1 and r[0] != 0x83:
                    active_units.append(uid)
            if active_units:
                self._record("Active Unit IDs (1-10)", host,
                             f"Responding units: {active_units}", "success")
        return self.results


class ModbusRTUModule(BaseModule):
    name = "modbus_rtu"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Modbus RTU via serial-to-TCP gateway - Read device ID, registers via gateway bridge"
    default_ports = [502, 4001, 950]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Modbus RTU (Serial Gateway) Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Same Modbus TCP framing through gateway
            pdu = struct.pack('>HHHBBBHH', 1, 0, 6, 1, 0x03, 0x00, 0, 1)
            resp = self._tcp(host, port, pdu)
            if resp:
                self._record(f"Modbus RTU gateway (port {port})", host, hex_dump(resp), "success",
                             "Serial gateway bridging Modbus RTU to TCP (Moxa/Digi/Lantronix)")
            else:
                self._record(f"Port {port} - no Modbus response", host, "Gateway may require different framing", "info")
            # FC 0x11 Report Slave ID
            pdu17 = struct.pack('>HHHBB', 2, 0, 2, 1, 0x11)
            resp = self._tcp(host, port, pdu17)
            if resp and len(resp) > 9:
                self._record("FC17 Report Slave ID via gateway", host, hex_dump(resp), "success")
        return self.results


class S7commModule(BaseModule):
    name = "s7comm"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Siemens S7comm - COTP connect, read CPU info, SZL lists, module data, firmware"
    default_ports = [102]

    def _cotp_connect(self, host, port, src_tsap=0x0100, dst_tsap=0x0102):
        s = tcp_connect(host, port, self.config.timeout)
        if not s:
            return None
        # COTP Connection Request
        cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                    0x00, 0x01, 0x00, 0xC1, 0x02,
                    (src_tsap >> 8) & 0xFF, src_tsap & 0xFF,
                    0xC2, 0x02,
                    (dst_tsap >> 8) & 0xFF, dst_tsap & 0xFF,
                    0xC0, 0x01, 0x0A])
        try:
            s.sendall(cr)
            resp = s.recv(1024)
            if resp and len(resp) >= 6 and resp[5] == 0xD0:  # CC = Connection Confirm
                return s
        except Exception:
            pass
        try: s.close()
        except: pass
        return None

    def _s7_setup(self, s):
        """S7 Communication Setup."""
        setup = bytes([0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80,
                       0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                       0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0])
        try:
            s.sendall(setup)
            return s.recv(1024)
        except Exception:
            return None

    def _read_szl(self, s, szl_id, szl_index=0x0000):
        """Read SZL (System Status List)."""
        szl_req = bytes([
            0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80,
            0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08,
            0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00,
            0xFF, 0x09, 0x00, 0x04,
            (szl_id >> 8) & 0xFF, szl_id & 0xFF,
            (szl_index >> 8) & 0xFF, szl_index & 0xFF
        ])
        try:
            s.sendall(szl_req)
            return s.recv(4096)
        except Exception:
            return None

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Siemens S7comm Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Try different TSAP combinations for S7-300/400/1200/1500
            for src, dst, desc in [(0x0100, 0x0102, "S7-300/400 Rack0Slot2"),
                                    (0x0100, 0x0100, "S7-1200/1500")]:
                s = self._cotp_connect(host, port, src, dst)
                if s:
                    self._record(f"COTP Connected ({desc})", host,
                                 f"TSAP {src:#06x} -> {dst:#06x}", "success")
                    setup = self._s7_setup(s)
                    if setup:
                        self._record("S7 Communication Setup", host, hex_dump(setup), "success")
                    # SZL 0x001C - Component Identification
                    szl = self._read_szl(s, 0x001C)
                    if szl and len(szl) > 30:
                        self._record("SZL 0x001C Component ID", host, hex_dump(szl), "success",
                                     "Module name, serial number, plant ID")
                    # SZL 0x0011 - Module Identification
                    szl = self._read_szl(s, 0x0011)
                    if szl and len(szl) > 30:
                        self._record("SZL 0x0011 Module ID", host, hex_dump(szl), "success",
                                     "Order number, firmware version")
                    # SZL 0x001A - CPU Features
                    szl = self._read_szl(s, 0x001A)
                    if szl and len(szl) > 20:
                        self._record("SZL 0x001A CPU Features", host, hex_dump(szl), "success")
                    # SZL 0x0074 - CPU Status
                    szl = self._read_szl(s, 0x0074)
                    if szl and len(szl) > 20:
                        self._record("SZL 0x0074 CPU Status", host, hex_dump(szl), "success",
                                     "Run/Stop/Error state")
                    try: s.close()
                    except: pass
                    break  # Connected successfully, no need to try other TSAPs
            else:
                self._record(f"COTP connection failed ({port})", host,
                             "No S7comm service or access denied", "info")
        return self.results


class EtherNetIPModule(BaseModule):
    name = "ethernet_ip"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "EtherNet/IP CIP - List Identity, List Services, List Interfaces, CIP paths"
    default_ports = [44818, 2222]

    def _enip_command(self, host, port, cmd_code, data=b''):
        """Send EtherNet/IP encapsulation command."""
        # EtherNet/IP header: command(2), length(2), session(4), status(4), context(8), options(4)
        header = struct.pack('<HHIIQI', cmd_code, len(data), 0, 0, 0, 0)
        return self._tcp(host, port, header + data)

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"EtherNet/IP CIP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # ListIdentity (0x0063)
            resp = self._enip_command(host, port, 0x0063)
            if resp and len(resp) > 26:
                self._record("ListIdentity", host, hex_dump(resp), "success",
                             "Vendor ID, device type, product name, serial, firmware")
                # Parse identity if possible
                try:
                    if len(resp) > 48:
                        vendor_id = struct.unpack('<H', resp[36:38])[0]
                        device_type = struct.unpack('<H', resp[38:40])[0]
                        product_code = struct.unpack('<H', resp[40:42])[0]
                        revision = f"{resp[42]}.{resp[43]}"
                        serial = struct.unpack('<I', resp[46:50])[0]
                        name_len = resp[50] if len(resp) > 50 else 0
                        name = resp[51:51+name_len].decode('utf-8', errors='replace') if name_len else ""
                        self._record("Device Identity Parsed", host,
                                     f"Vendor={vendor_id} DevType={device_type} Product={product_code} "
                                     f"Rev={revision} Serial={serial:#010x} Name={name}", "success")
                except Exception:
                    pass
            # ListServices (0x0004)
            resp = self._enip_command(host, port, 0x0004)
            if resp and len(resp) > 24:
                self._record("ListServices", host, hex_dump(resp), "success",
                             "Communications/encapsulation service capabilities")
            # ListInterfaces (0x0064)
            resp = self._enip_command(host, port, 0x0064)
            if resp and len(resp) > 24:
                self._record("ListInterfaces", host, hex_dump(resp), "success")
        # UDP broadcast ListIdentity
        try:
            udp_hdr = struct.pack('<HHIIQI', 0x0063, 0, 0, 0, 0, 0)
            resp = self._udp(host, 44818, udp_hdr)
            if resp and len(resp) > 26:
                self._record("UDP ListIdentity", host, hex_dump(resp), "success")
        except Exception:
            pass
        return self.results


class DNP3Module(BaseModule):
    name = "dnp3"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "DNP3 (IEEE 1815) - Read binary/analog inputs, counters, device attributes, file info"
    default_ports = [20000, 19999]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"DNP3 Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # DNP3 Data Link Layer frame - Read Class 0 (static data)
            # Start: 0x0564, Length: 0x05, Control: 0xC0 (DIR+PRM+FCV), Dest: 1, Src: 2
            dll_header = struct.pack('<BBHBBHH', 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00)
            # CRC placeholder (DNP3 uses CRC-16 on each block)
            # Simplified: send header and check for response format
            resp = self._tcp(host, port, dll_header)
            if resp and len(resp) >= 2 and resp[0] == 0x05 and resp[1] == 0x64:
                self._record("DNP3 Link Layer Response", host, hex_dump(resp), "success",
                             "DNP3 outstation responding. Parse for data objects.")
            else:
                self._record(f"DNP3 probe (port {port})", host,
                             hex_dump(resp) if resp else "No response", "info")
            # Try Application Layer - Read Class 0 Data
            # Full DNP3 frame with transport + application layers
            app_req = bytes([
                0x05, 0x64, 0x0B, 0xC4,  # DLL: Start, Length=11, Control=0xC4
                0x01, 0x00, 0x02, 0x00,   # Dest=1, Src=2
                0x00, 0x00,               # CRC placeholder
                0xC0,                      # Transport: FIR+FIN, seq=0
                0xC0, 0x01,               # App: FIR+FIN+CON, FC=1 (READ)
                0x3C, 0x02, 0x06,          # Obj60Var2 (Class 0) QC=0x06 (all)
                0x00, 0x00                 # CRC placeholder
            ])
            resp = self._tcp(host, port, app_req)
            if resp and len(resp) > 10:
                self._record("DNP3 Class 0 Read Response", host, hex_dump(resp), "success",
                             "Static data: binary inputs, analog inputs, counters")
        return self.results


class OPCUAModule(BaseModule):
    name = "opc_ua"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "OPC UA - Hello/ACK, GetEndpoints, server info, security policies, browse root"
    default_ports = [4840, 48010, 4843]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"OPC UA Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # OPC UA Hello message
            endpoint_url = f"opc.tcp://{host}:{port}".encode('utf-8')
            hello_body = struct.pack('<III', 65536, 65536, 4096)  # RcvBufSize, SndBufSize, MaxMsgSize
            hello_body += struct.pack('<I', 0)  # MaxChunkCount
            hello_body += struct.pack('<I', len(endpoint_url)) + endpoint_url
            # Message header: "HEL" + "F" + length(4)
            msg = b'HELF' + struct.pack('<I', 8 + len(hello_body)) + hello_body
            resp = self._tcp(host, port, msg, recv_size=8192)
            if resp and len(resp) >= 8:
                msg_type = resp[:3].decode('utf-8', errors='replace')
                if msg_type == 'ACK':
                    self._record("OPC UA Hello/ACK", host,
                                 f"Server responded with ACK. Protocol version supported.", "success")
                    # Parse ACK for buffer sizes
                    if len(resp) >= 28:
                        proto_ver = struct.unpack('<I', resp[8:12])[0]
                        recv_buf = struct.unpack('<I', resp[12:16])[0]
                        send_buf = struct.unpack('<I', resp[16:20])[0]
                        max_msg = struct.unpack('<I', resp[20:24])[0]
                        self._record("OPC UA Server Capabilities", host,
                                     f"Protocol={proto_ver} RcvBuf={recv_buf} SndBuf={send_buf} MaxMsg={max_msg}",
                                     "success")
                elif msg_type == 'ERR':
                    err_code = struct.unpack('<I', resp[8:12])[0] if len(resp) >= 12 else 0
                    self._record("OPC UA Error", host, f"Error code: {err_code:#010x}", "info")
                else:
                    self._record("OPC UA Response", host, hex_dump(resp), "info")
            # Check for HTTPS endpoints
            status, hdrs, body = self._http(host, port, "/", use_ssl=True)
            if status > 0:
                self._record("OPC UA HTTPS endpoint", host,
                             f"HTTP {status}, Server: {hdrs.get('Server', 'unknown')}", "info")
        return self.results



class OPCDAModule(BaseModule):
    name = "opc_da"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "OPC DA/DCOM - DCERPC endpoint map, OPC server enumeration via RPC"
    default_ports = [135]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"OPC DA (DCOM) Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # DCERPC Bind to Endpoint Mapper (EPM) UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa
            # RPC version 5.0 bind request
            epm_uuid = bytes([0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
                              0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA])
            # DCE/RPC Bind PDU (simplified)
            bind_pdu = struct.pack('<BBBBIHH', 5, 0, 0x0B, 0x03, 0x10, 72, 0)
            bind_pdu += struct.pack('<IHH', 0, 5840, 5840)  # call_id, max_xmit, max_recv
            bind_pdu += struct.pack('<I', 0)  # assoc_group
            bind_pdu += struct.pack('<I', 1)  # num_ctx_items
            bind_pdu += struct.pack('<HH', 0, 1)  # ctx_id, num_trans
            bind_pdu += epm_uuid
            bind_pdu += struct.pack('<HH', 3, 0)  # interface version
            # Transfer syntax NDR UUID
            bind_pdu += bytes([0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
                               0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60])
            bind_pdu += struct.pack('<I', 2)  # syntax version
            # Fix length
            bind_pdu = bind_pdu[:8] + struct.pack('<H', len(bind_pdu)) + bind_pdu[10:]
            resp = self._tcp(host, port, bind_pdu)
            if resp and len(resp) > 20:
                pdu_type = resp[2] if len(resp) > 2 else 0
                if pdu_type == 0x0C:  # Bind ACK
                    self._record("DCERPC Bind ACK (EPM)", host, hex_dump(resp[:60]), "success",
                                 "Endpoint Mapper accessible. OPC DA DCOM possible.")
                else:
                    self._record("DCERPC response", host, hex_dump(resp[:60]), "info")
            # Check dynamic RPC ports for OPC DA
            for opc_port in [49152, 49153, 49154, 49155]:
                if is_port_open(host, opc_port, 2):
                    self._record(f"Dynamic RPC port {opc_port} open", host,
                                 "Potential OPC DA service endpoint", "info")
        return self.results


class BACnetModule(BaseModule):
    name = "bacnet"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "BACnet/IP - Who-Is, Read Property (Object Name, Vendor, Model, Firmware, Location)"
    default_ports = [47808]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"BACnet/IP Enumeration: {host}")
        for port in ports:
            # BACnet Who-Is (broadcast/unicast) - BVLC + NPDU + APDU
            # BVLC: Type=0x81, Function=0x0A (Original-Unicast-NPDU), Length=12
            # NPDU: Version=1, Control=0x04
            # APDU: Type=1 (Unconfirmed), Service=8 (Who-Is)
            whois = bytes([0x81, 0x0A, 0x00, 0x0C, 0x01, 0x04, 0x00, 0x05,
                           0x01, 0x08, 0x00, 0x00])
            resp = self._udp(host, port, whois)
            if resp and len(resp) >= 12:
                self._record("BACnet Who-Is/I-Am Response", host, hex_dump(resp), "success",
                             "Device instance, vendor ID, segmentation, max APDU")
                # Parse I-Am response
                if len(resp) > 18 and resp[7] == 0x10:  # I-Am service
                    self._record("BACnet I-Am detected", host,
                                 "BACnet device responding to Who-Is", "success")
            # Read Property - Object Name (Object=Device:0, Property=77)
            read_prop = bytes([0x81, 0x0A, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05,
                               0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x19, 0x4D])
            resp = self._udp(host, port, read_prop)
            if resp and len(resp) > 12:
                self._record("BACnet Read Property (Object Name)", host, hex_dump(resp), "success")
            # Read Property - Vendor Name (property 121)
            read_vendor = bytes([0x81, 0x0A, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05,
                                 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x19, 0x79])
            resp = self._udp(host, port, read_vendor)
            if resp and len(resp) > 12:
                self._record("BACnet Read Property (Vendor Name)", host, hex_dump(resp), "success")
        return self.results


class PROFINETModule(BaseModule):
    name = "profinet"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "PROFINET DCP - Device identification, name, IP config, vendor info via UDP"
    default_ports = [34964, 34962]
    requires_root = True

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"PROFINET DCP Enumeration: {host}")
        for port in ports:
            # PROFINET DCP Identify Request via UDP
            # FrameID=0xFEFE (DCP-UC), ServiceID=5 (Identify), ServiceType=0 (Request)
            dcp_identify = struct.pack('>HH', 0xFEFE, 0x0500)
            dcp_identify += struct.pack('>IH', 0x00000001, 0x0004)  # Xid, ResponseDelay
            # Block: All (option=0xFF, suboption=0xFF)
            dcp_identify += struct.pack('>BBH', 0xFF, 0xFF, 0x0000)
            resp = self._udp(host, port, dcp_identify)
            if resp and len(resp) > 10:
                self._record("PROFINET DCP Identify Response", host, hex_dump(resp), "success",
                             "Device name, IP address, vendor, device type")
            else:
                self._record(f"PROFINET DCP (port {port})", host, "No DCP response", "info")
            # Also try TCP probe on the port
            if is_port_open(host, port, self.config.timeout):
                self._record(f"PROFINET TCP port {port} open", host, "PROFINET RT/IRT service", "info")
        return self.results


class IEC104Module(BaseModule):
    name = "iec104"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IEC 60870-5-104 - STARTDT, interrogation command, read data objects, test frame"
    default_ports = [2404]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IEC 60870-5-104 Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                # STARTDT act (U-frame): start byte 0x68, length 4, control 0x07000000
                startdt = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
                s.sendall(startdt)
                resp = s.recv(1024)
                if resp and len(resp) >= 6 and resp[0] == 0x68:
                    ctrl = resp[2]
                    if ctrl == 0x0B:  # STARTDT con
                        self._record("IEC 104 STARTDT Confirmed", host,
                                     "Data transfer activated", "success")
                    else:
                        self._record("IEC 104 response", host, hex_dump(resp), "info")
                    # Send General Interrogation Command (C_IC_NA_1, TypeID=100)
                    # I-frame: Control=0x00000000 (Seq 0), TypeID=100, VSQ=1, COT=6 (Activation)
                    gi_cmd = bytes([0x68, 0x0E,
                                    0x00, 0x00, 0x00, 0x00,  # I-frame control
                                    0x64,                     # TypeID = 100 (C_IC_NA_1)
                                    0x01,                     # VSQ = 1 object
                                    0x06, 0x00,               # COT = 6 (Activation)
                                    0x01, 0x00,               # OA=0, CA=1
                                    0x00, 0x00, 0x00,          # IOA = 0
                                    0x14])                     # QOI = 20 (Station)
                    s.sendall(gi_cmd)
                    time.sleep(1)
                    s.settimeout(3)
                    data_objects = b''
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            data_objects += chunk
                    except socket.timeout:
                        pass
                    if data_objects:
                        self._record("IEC 104 Interrogation Response", host,
                                     f"Received {len(data_objects)} bytes of data objects",
                                     "success", "Contains measured values, status points")
                else:
                    self._record(f"IEC 104 (port {port})", host,
                                 hex_dump(resp) if resp else "No response to STARTDT", "info")
            except Exception as e:
                self._record("IEC 104 probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results


class IEC101Module(BaseModule):
    name = "iec101"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IEC 60870-5-101 - Serial SCADA protocol, detect via serial-to-TCP gateways"
    default_ports = [2404, 4001, 950]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IEC 60870-5-101 (Serial Gateway) Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # IEC 101 uses serial framing - detect via gateway
            # Fixed-length frame: Start=0x10, FC=0x49 (Request Status of Link), Addr=1
            frame = bytes([0x10, 0x49, 0x01, 0x4A, 0x16])
            resp = self._tcp(host, port, frame)
            if resp and len(resp) >= 5:
                if resp[0] == 0x10:  # Fixed frame response
                    self._record("IEC 101 Link Status Response", host, hex_dump(resp), "success",
                                 "IEC 101 outstation on serial gateway")
                elif resp[0] == 0x68:  # Variable frame (could be 104)
                    self._record("IEC 101/104 Variable Frame", host, hex_dump(resp), "info")
                else:
                    self._record("IEC 101 gateway response", host, hex_dump(resp), "info")
            else:
                self._record(f"IEC 101 probe (port {port})", host,
                             "No IEC 101 framing detected", "info")
        return self.results


class IEC61850Module(BaseModule):
    name = "iec61850"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IEC 61850 MMS - COTP connect, MMS initiate, read logical devices, data objects"
    default_ports = [102]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IEC 61850 MMS Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # COTP Connection Request (same transport as S7comm)
            cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                             0x00, 0x01, 0x00, 0xC1, 0x02, 0x00, 0x01, 0xC2,
                             0x02, 0x00, 0x01, 0xC0, 0x01, 0x0A])
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                s.sendall(cotp_cr)
                resp = s.recv(1024)
                if resp and len(resp) >= 6 and resp[5] == 0xD0:
                    self._record("COTP Connected (MMS)", host, "Transport layer established", "success")
                    # MMS Initiate Request (simplified)
                    mms_init = bytes([
                        0x03, 0x00, 0x00, 0x1B, 0x02, 0xF0, 0x80,
                        0xA8, 0x10, 0x80, 0x01, 0x01, 0x81, 0x01, 0x01,
                        0x82, 0x01, 0x01, 0xA4, 0x06, 0x80, 0x01, 0x01,
                        0x81, 0x01, 0x01, 0xBE, 0x00
                    ])
                    s.sendall(mms_init)
                    resp = s.recv(4096)
                    if resp and len(resp) > 10:
                        self._record("MMS Initiate Response", host, hex_dump(resp), "success",
                                     "IEC 61850 MMS server. Contains supported services, version.")
                else:
                    self._record("COTP rejected", host, hex_dump(resp) if resp else "No response", "info")
            except Exception as e:
                self._record("IEC 61850 probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results


class IEC61850GOOSEModule(BaseModule):
    name = "iec61850_goose"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IEC 61850 GOOSE - Detect GOOSE multicast capability (Layer 2, EtherType 0x88B8)"
    default_ports = []
    requires_root = True

    def run(self, host, ports=None):
        print_subsection(f"IEC 61850 GOOSE Detection")
        # GOOSE is Layer 2 - check for multicast group membership and interface capability
        if platform.system() == "Linux":
            maddr = self._os_cmd("ip maddr show 2>/dev/null")
            if "01:0c:cd:01" in maddr.lower():
                self._record("GOOSE multicast groups detected", host, maddr, "success",
                             "GOOSE uses EtherType 0x88B8 on L2 multicast 01:0C:CD:01:xx:xx")
            else:
                self._record("GOOSE multicast check", host,
                             "No GOOSE multicast groups (01:0C:CD:01) on local interfaces", "info",
                             "Must be on same L2 segment as GOOSE publisher")
        self._record("GOOSE protocol info", host,
                     "GOOSE is Layer 2 only (no TCP/IP). Requires raw socket on same subnet.",
                     "info", "EtherType 0x88B8. Used for fast tripping in substations.")
        return self.results


class IEC61850SVModule(BaseModule):
    name = "iec61850_sv"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IEC 61850 Sampled Values - Detect SV multicast capability (Layer 2, EtherType 0x88BA)"
    default_ports = []
    requires_root = True

    def run(self, host, ports=None):
        print_subsection(f"IEC 61850 Sampled Values Detection")
        if platform.system() == "Linux":
            maddr = self._os_cmd("ip maddr show 2>/dev/null")
            if "01:0c:cd:04" in maddr.lower():
                self._record("SV multicast groups detected", host, maddr, "success")
            else:
                self._record("SV multicast check", host,
                             "No SV multicast groups (01:0C:CD:04) on local interfaces", "info")
        self._record("Sampled Values info", host,
                     "SV is Layer 2 only (EtherType 0x88BA). Process bus current/voltage samples.",
                     "info")
        return self.results


class HARTIPModule(BaseModule):
    name = "hart_ip"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "HART-IP - Read unique identifier (Cmd 0), dynamic/static vars, device status"
    default_ports = [5094]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"HART-IP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # HART-IP header: Version(1)=1, MsgType(1)=0(Request), MsgID(1)=0,
            # Status(1)=0, SeqNum(2)=1, ByteCount(2)=total_len
            # Then HART command: Delimiter=0x82(long frame), Address(5)=00000000xx,
            # Command=0, ByteCount=0
            hart_cmd0 = bytes([
                0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E,  # HART-IP header (14 bytes total)
                0x82,                           # Long frame delimiter
                0x00, 0x00, 0x00, 0x00, 0x00,   # Address (broadcast)
                0x00,                           # Command 0 (Read Unique ID)
                0x00                            # Byte count 0
            ])
            resp = self._tcp(host, port, hart_cmd0)
            if resp and len(resp) >= 8:
                self._record("HART-IP Cmd 0 (Read Unique ID)", host, hex_dump(resp), "success",
                             "Device manufacturer, device type, device ID, firmware revision")
            else:
                resp = self._udp(host, port, hart_cmd0)
                if resp:
                    self._record("HART-IP UDP Cmd 0", host, hex_dump(resp), "success")
            # HART Cmd 1 - Read Primary Variable
            hart_cmd1 = bytes([
                0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0E,
                0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
            ])
            resp = self._tcp(host, port, hart_cmd1)
            if resp and len(resp) >= 8:
                self._record("HART-IP Cmd 1 (Primary Variable)", host, hex_dump(resp), "success")
            # HART Cmd 13 - Read Tag/Descriptor/Date
            hart_cmd13 = bytes([
                0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0E,
                0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00
            ])
            resp = self._tcp(host, port, hart_cmd13)
            if resp and len(resp) >= 8:
                self._record("HART-IP Cmd 13 (Tag/Descriptor)", host, hex_dump(resp), "success")
        return self.results


class WirelessHARTModule(BaseModule):
    name = "wireless_hart"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "WirelessHART - Gateway enumeration via HART-IP, device list, network health"
    default_ports = [5094]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"WirelessHART Gateway Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Same HART-IP framing - Cmd 0 to gateway
            hart_cmd0 = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0E,
                               0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            resp = self._tcp(host, port, hart_cmd0)
            if resp:
                self._record("WirelessHART Gateway Cmd 0", host, hex_dump(resp), "success",
                             "WirelessHART gateway (Emerson, ABB, Honeywell). Bridges wireless to HART-IP.")
            # Check for web management (common on WirelessHART gateways)
            for webport in [80, 443]:
                status, hdrs, body = self._http(host, webport, "/", use_ssl=(webport==443))
                if status > 0 and status != 0:
                    self._record(f"Gateway web management (port {webport})", host,
                                 f"HTTP {status}, Server: {hdrs.get('Server','?')}", "info")
        return self.results


class FINSModule(BaseModule):
    name = "fins"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Omron FINS - Read CPU unit data, status, memory areas (DM, CIO, WR, HR)"
    default_ports = [9600]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Omron FINS Enumeration: {host}")
        for port in ports:
            # FINS over UDP
            # FINS header: ICF=0x80(cmd), RSV=0x00, GCT=0x02, DNA=0x00, DA1=0x00, DA2=0x00,
            #              SNA=0x00, SA1=0x00, SA2=0x00, SID=0x01
            # Command: 0x05 0x01 = Controller Data Read
            fins_header = bytes([0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00])
            fins_cmd = bytes([0x05, 0x01])  # Controller Data Read
            # First do FINS/TCP handshake if TCP
            if is_port_open(host, port, self.config.timeout):
                # FINS/TCP: Node Address Data Send (header command)
                tcp_header = struct.pack('>4sIII', b'FINS', 0x00000000, 0x0000000C, 0x00000000)
                tcp_header += struct.pack('>I', 0x00000000)  # Client node
                resp = self._tcp(host, port, tcp_header)
                if resp and len(resp) >= 16:
                    self._record("FINS/TCP Handshake", host, hex_dump(resp), "success",
                                 "FINS over TCP established. Server node address received.")
                # Also try FINS/UDP
                resp = self._udp(host, port, fins_header + fins_cmd)
                if resp:
                    self._record("FINS Controller Data Read", host, hex_dump(resp), "success",
                                 "CPU model, version, memory capacity")
                # Memory Read - DM area, start at 0, 10 words
                fins_mem = fins_header + bytes([0x01, 0x01,  # Memory Area Read
                                                0x82,        # DM area
                                                0x00, 0x00, 0x00,  # Start address
                                                0x00, 0x0A])  # Number of items
                resp = self._udp(host, port, fins_mem)
                if resp:
                    self._record("FINS DM Area Read [0:10]", host, hex_dump(resp), "success")
        return self.results


class MELSECModule(BaseModule):
    name = "melsec"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Mitsubishi MELSEC-Q/iQ-R - SLMP binary read, CPU type, device memory"
    default_ports = [5007, 5006]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Mitsubishi MELSEC Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # SLMP (Seamless Message Protocol) Binary - Read CPU Type
            # Subheader: 0x5000 (binary request), Network=0, Station=0xFF, Module=0x03FF
            # Monitoring timer=0x000A, Command=0x0101 (Read), Subcommand=0x0001
            slmp_header = struct.pack('<HBxHH', 0x5000, 0x00, 0xFF, 0x03FF)
            slmp_header += struct.pack('<HH', 0x000A, 0x0000)  # Timer, data_length placeholder
            # Read command: Device D0, 10 points
            read_cmd = struct.pack('<HH', 0x0401, 0x0000)  # Read command
            read_cmd += b'D*' + struct.pack('<IH', 0, 10)  # Device D, start 0, count 10
            slmp = slmp_header + struct.pack('<H', len(read_cmd)) + read_cmd
            resp = self._tcp(host, port, slmp)
            if resp and len(resp) > 10:
                self._record("MELSEC SLMP Response", host, hex_dump(resp), "success",
                             "Mitsubishi PLC responding. CPU type, memory data.")
            else:
                # Try MC Protocol (older format)
                mc_header = bytes([0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00,
                                   0x0E, 0x00, 0x0A, 0x00,
                                   0x01, 0x04, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0xA8, 0x0A, 0x00])
                resp = self._tcp(host, port, mc_header)
                if resp:
                    self._record("MC Protocol Response", host, hex_dump(resp), "success")
                else:
                    self._record(f"MELSEC probe (port {port})", host, "No response", "info")
        return self.results



class CCLinkModule(BaseModule):
    name = "cclink"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "CC-Link IE Field/TSN - Device scan, station info read via UDP"
    default_ports = [61414, 61450]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"CC-Link IE Enumeration: {host}")
        for port in ports:
            # CC-Link IE uses UDP multicast/unicast
            probe = struct.pack('>HH', 0x0001, 0x0000) + b'\x00' * 8
            resp = self._udp(host, port, probe)
            if resp:
                self._record(f"CC-Link IE response (port {port})", host, hex_dump(resp), "success",
                             "CC-Link IE Field or TSN device detected")
            elif is_port_open(host, port, self.config.timeout):
                self._record(f"CC-Link TCP port {port} open", host, "CC-Link IE service", "info")
        return self.results


class EtherCATModule(BaseModule):
    name = "ethercat"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "EtherCAT - Detect EtherCAT devices via UDP probe, mailbox/CoE info"
    default_ports = [34980, 6000]
    requires_root = True

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"EtherCAT Enumeration: {host}")
        # EtherCAT is primarily Layer 2 (EtherType 0x88A4)
        self._record("EtherCAT protocol info", host,
                     "EtherCAT is Layer 2 (EtherType 0x88A4). Direct device access requires raw socket on same segment.",
                     "info")
        for port in ports:
            if is_port_open(host, port, self.config.timeout):
                self._record(f"EtherCAT-related port {port} open", host,
                             "Possible EtherCAT over UDP or diagnostic service", "info")
                resp = self._tcp(host, port, b'\x00' * 12)
                if resp:
                    self._record(f"EtherCAT service response ({port})", host, hex_dump(resp), "success")
        return self.results


class POWERLINKModule(BaseModule):
    name = "powerlink"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Ethernet POWERLINK - MN identification, CN scanning via UDP"
    default_ports = [3819]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Ethernet POWERLINK Enumeration: {host}")
        self._record("POWERLINK protocol info", host,
                     "POWERLINK uses EtherType 0x88AB (Layer 2). IP-based management may be on port 3819.",
                     "info")
        for port in ports:
            if is_port_open(host, port, self.config.timeout):
                resp = self._tcp(host, port, b'\x00' * 8)
                if resp:
                    self._record(f"POWERLINK service ({port})", host, hex_dump(resp), "success")
            resp = self._udp(host, port, b'\x00' * 8)
            if resp:
                self._record(f"POWERLINK UDP ({port})", host, hex_dump(resp), "success")
        return self.results


class FoundationFieldbusModule(BaseModule):
    name = "foundation_fieldbus"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Foundation Fieldbus HSE - Device identification, block enumeration via UDP"
    default_ports = [1089, 1090]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Foundation Fieldbus HSE Enumeration: {host}")
        for port in ports:
            if is_port_open(host, port, self.config.timeout):
                self._record(f"FF-HSE port {port} open", host,
                             "Foundation Fieldbus HSE service detected", "info")
                resp = self._tcp(host, port, b'\x00' * 8)
                if resp:
                    self._record(f"FF-HSE response ({port})", host, hex_dump(resp), "success",
                                 "FF-HSE uses FDA (Fieldbus Device Access) protocol")
            resp = self._udp(host, port, b'\x00' * 8)
            if resp:
                self._record(f"FF-HSE UDP ({port})", host, hex_dump(resp), "success")
        return self.results


class GEsrtpModule(BaseModule):
    name = "ge_srtp"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "GE SRTP/SNP - Read PLC info, memory, firmware version, program name"
    default_ports = [18245]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"GE SRTP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # GE SRTP Service Request Protocol
            # Request Type 0x00 = Init, then 0x02 = Read PLC Info
            srtp_init = struct.pack('>BBHBBHI', 0x02, 0x00, 56, 0x00, 0x00, 0x00, 0x01)
            srtp_init += b'\x00' * 48  # Padding to 56 bytes
            resp = self._tcp(host, port, srtp_init)
            if resp and len(resp) >= 20:
                self._record("GE SRTP Init Response", host, hex_dump(resp), "success",
                             "GE PACSystems/VersaMax/Series 90 PLC")
                # Parse device info if possible
                if len(resp) >= 56:
                    self._record("GE SRTP Device Info", host, safe_decode(resp[20:56]), "success")
            else:
                self._record(f"GE SRTP (port {port})", host,
                             hex_dump(resp) if resp else "No response", "info")
        return self.results


class ABETHModule(BaseModule):
    name = "ab_eth"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Allen-Bradley Ethernet (PCCC/CSP) - Read identity, SLC/PLC5 data tables, status"
    default_ports = [44818, 2222]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Allen-Bradley PCCC/CSP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # EtherNet/IP RegisterSession (0x0065)
            reg_session = struct.pack('<HHIIQI', 0x0065, 4, 0, 0, 0, 0)
            reg_session += struct.pack('<HH', 1, 0)  # Protocol version 1
            resp = self._tcp(host, port, reg_session)
            if resp and len(resp) >= 28:
                session = struct.unpack('<I', resp[4:8])[0]
                if session > 0:
                    self._record("EtherNet/IP Session Registered", host,
                                 f"Session handle: {session:#010x}", "success")
                    # Send PCCC Execute via CIP
                    self._record("PCCC via CIP available", host,
                                 "Can read SLC5/PLC5 data tables via PCCC encapsulated in CIP",
                                 "info", "Allen-Bradley legacy protocol")
            # Also try ListIdentity for device info
            list_id = struct.pack('<HHIIQI', 0x0063, 0, 0, 0, 0, 0)
            resp = self._tcp(host, port, list_id)
            if resp and len(resp) > 30:
                self._record("AB ListIdentity", host, hex_dump(resp), "success")
        return self.results


class TriStationModule(BaseModule):
    name = "tristation"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Schneider Triconex TriStation - Read controller info, firmware, key switch state"
    default_ports = [1502]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"TriStation Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # TriStation connection request
            conn_req = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02])
            resp = self._tcp(host, port, conn_req)
            if resp:
                self._record("TriStation Response", host, hex_dump(resp), "success",
                             "Triconex SIS controller. TRITON/TRISIS targeted this (CVE-2017).")
            else:
                self._record(f"TriStation (port {port})", host, "No response", "info")
        return self.results


class FoxModule(BaseModule):
    name = "fox"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Tridium Fox - Read station name, app name, vendor, version, OS, timezone"
    default_ports = [1911]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Tridium Fox Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Fox hello handshake
            resp = self._tcp(host, port, b"fox a 1 -1 fox hello\n")
            if resp:
                decoded = safe_decode(resp)
                self._record("Fox Hello Response", host, decoded, "success",
                             "Look for: fox.version, hostName, app.name, vm.version, os.name")
                # Parse key-value pairs
                for line in decoded.split('\n'):
                    for key in ['hostName', 'app.name', 'fox.version', 'os.name', 'vm.version']:
                        if key in line:
                            self._record(f"Fox {key}", host, line.strip(), "success")
            else:
                self._record(f"Fox (port {port})", host, "No response", "info")
        return self.results


class CrimsonV3Module(BaseModule):
    name = "crimson_v3"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Red Lion Crimson v3 - Read device info, configuration, firmware version"
    default_ports = [789]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Crimson v3 Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            resp = self._tcp(host, port, b'\x00' * 8)
            if resp:
                self._record("Crimson v3 Response", host, hex_dump(resp), "success",
                             "Red Lion CR1000/CR3000/Graphite HMI")
            # Check web interface
            status, hdrs, body = self._http(host, 80, "/")
            if status > 0:
                server = hdrs.get('Server', '')
                if 'red lion' in body.lower() or 'crimson' in body.lower() or 'graphite' in body.lower():
                    self._record("Crimson web UI detected", host,
                                 f"HTTP {status}, Server={server}", "success")
        return self.results


class NiagaraFoxModule(BaseModule):
    name = "niagara_fox"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Niagara Fox (Tridium N4) - Station info, platform version, auth status"
    default_ports = [4911, 443]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Niagara Fox (N4) Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port in [443, 8443]:
                status, hdrs, body = self._http(host, port, "/login/", use_ssl=True)
                if status > 0:
                    if 'niagara' in body.lower() or 'tridium' in body.lower():
                        self._record("Niagara N4 HTTPS Login", host,
                                     f"HTTP {status} - Niagara 4 web management", "success")
                    else:
                        self._record(f"HTTPS service ({port})", host, f"HTTP {status}", "info")
            else:
                resp = self._tcp(host, port, b"fox a 1 -1 fox hello\n")
                if resp:
                    self._record("Niagara Fox Response", host, safe_decode(resp), "success")
        return self.results


class ROCModule(BaseModule):
    name = "roc"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Emerson ROC/ROC Plus - Read device info, config, I/O values, event log"
    default_ports = [4000]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"ROC/ROC Plus Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # ROC protocol: Opcode 6 (Request/Response), Group 0 (System Config)
            roc_hdr = struct.pack('<BBBBHBBH', 1, 1, 240, 0, 0, 6, 0, 0)
            resp = self._tcp(host, port, roc_hdr)
            if resp:
                self._record("ROC Response", host, hex_dump(resp), "success",
                             "Emerson ROC800/FloBoss - oil & gas flow measurement")
            else:
                self._record(f"ROC (port {port})", host, "No response", "info")
        return self.results


class DLMSCOSEMModule(BaseModule):
    name = "dlms_cosem"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "DLMS/COSEM - Smart meter protocol, read device identity, association objects"
    default_ports = [4059, 4060]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"DLMS/COSEM Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # DLMS AARQ (Association Request) in HDLC-like wrapper
            aarq = bytes([0x7E, 0xA0, 0x07, 0x03, 0x01, 0x00, 0x01, 0x00, 0x7E])
            resp = self._tcp(host, port, aarq)
            if resp:
                self._record("DLMS/COSEM Response", host, hex_dump(resp), "success",
                             "IEC 62056. Smart meters, AMI head-ends, energy gateways.")
            else:
                self._record(f"DLMS/COSEM (port {port})", host, "No response", "info")
        return self.results


class YokogawaModule(BaseModule):
    name = "yokogawa"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Yokogawa Vnet/IP - Read controller identity, network topology, station info"
    default_ports = [34151, 34152, 20171]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Yokogawa Vnet/IP Enumeration: {host}")
        for port in ports:
            if is_port_open(host, port, self.config.timeout):
                self._record(f"Yokogawa port {port} open", host,
                             "CENTUM VP/ProSafe-RS service", "success")
                resp = self._tcp(host, port, b'\x00' * 8)
                if resp:
                    self._record(f"Yokogawa response ({port})", host, hex_dump(resp), "success")
        # Web HMI check
        for wp in [80, 443]:
            status, hdrs, body = self._http(host, wp, "/", use_ssl=(wp==443))
            if status > 0 and ('yokogawa' in body.lower() or 'centum' in body.lower()):
                self._record(f"Yokogawa web HMI ({wp})", host, f"HTTP {status}", "success")
        return self.results


class ProConOSModule(BaseModule):
    name = "proconos"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "ProConOS - KW-Software PLC runtime, read controller info, project name"
    default_ports = [20547]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"ProConOS Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            resp = self._tcp(host, port, b'\xcc\x01\x00\x00\x00')
            if resp:
                self._record("ProConOS Response", host, hex_dump(resp), "success",
                             "KW-Software (Phoenix Contact, Wago). IEC 61131-3 PLC runtime.")
            else:
                self._record(f"ProConOS (port {port})", host, "No response", "info")
        return self.results


class MoxaNPortModule(BaseModule):
    name = "moxa_nport"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "Moxa NPort - Serial device server, firmware, config, serial port status"
    default_ports = [4001, 80, 4800, 950]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Moxa NPort Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port == 80:
                status, hdrs, body = self._http(host, 80, "/main.htm")
                if status > 0:
                    is_moxa = 'moxa' in body.lower() or 'nport' in body.lower()
                    self._record("Moxa NPort Web UI", host,
                                 f"HTTP {status} {'- Moxa detected' if is_moxa else ''}",
                                 "success" if is_moxa else "info")
            elif port == 4800:
                resp = self._tcp(host, port, b'\x01\x00\x00\x08')
                if resp:
                    self._record("Moxa admin protocol (4800)", host, hex_dump(resp), "success",
                                 "NPort Administrator protocol")
            else:
                resp = self._tcp(host, port, b'')
                banner = self._tcp(host, port, None)
                if banner:
                    self._record(f"Moxa serial data port ({port})", host, hex_dump(banner), "info",
                                 "Serial-to-TCP bridge port")
        # UDP discovery on 4800
        resp = self._udp(host, 4800, bytes([0x01, 0x00, 0x00, 0x08]))
        if resp:
            self._record("Moxa UDP discovery (4800)", host, hex_dump(resp), "success")
        return self.results


class ICCPModule(BaseModule):
    name = "iccp"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "ICCP/TASE.2 (IEC 60870-6) - Inter-control center comms, MMS-based detection"
    default_ports = [102]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"ICCP/TASE.2 Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # ICCP uses MMS (same COTP transport as IEC 61850)
            cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                             0x00, 0x01, 0x00, 0xC1, 0x02, 0x00, 0x01, 0xC2,
                             0x02, 0x00, 0x01, 0xC0, 0x01, 0x0A])
            resp = self._tcp(host, port, cotp_cr)
            if resp and len(resp) >= 6 and resp[5] == 0xD0:
                self._record("ICCP COTP Connected", host, hex_dump(resp), "success",
                             "ICCP/TASE.2 (IEC 60870-6) runs over MMS. Used between utility control centers.")
            else:
                self._record("ICCP probe", host, hex_dump(resp) if resp else "No response", "info")
        return self.results


class KNXModule(BaseModule):
    name = "knx"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "KNX/EIBnet/IP - Building automation, device discovery, tunneling info"
    default_ports = [3671]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"KNX/EIBnet/IP Enumeration: {host}")
        for port in ports:
            # KNXnet/IP Search Request (UDP)
            # Header: version=0x06, header_size=0x10, service=0x0201 (SEARCH_REQUEST), total_len=14
            # HPAI: struct_len=8, protocol=1(UDP), IP=0.0.0.0, port=0
            search_req = struct.pack('>BBHH', 0x06, 0x10, 0x0201, 0x000E)
            search_req += struct.pack('>BB4sH', 0x08, 0x01, b'\x00\x00\x00\x00', 0x0000)
            resp = self._udp(host, port, search_req)
            if resp and len(resp) > 8:
                self._record("KNXnet/IP Search Response", host, hex_dump(resp), "success",
                             "KNX building automation device. Parse for device name, serial, MAC.")
                # Try Description Request
                desc_req = struct.pack('>BBHH', 0x06, 0x10, 0x0203, 0x000E)
                desc_req += struct.pack('>BB4sH', 0x08, 0x01, b'\x00\x00\x00\x00', 0x0000)
                resp2 = self._udp(host, port, desc_req)
                if resp2:
                    self._record("KNXnet/IP Description", host, hex_dump(resp2), "success")
            if is_port_open(host, port, self.config.timeout):
                self._record(f"KNX TCP port {port} open", host, "KNX IP tunneling gateway", "info")
        return self.results


class LonWorksModule(BaseModule):
    name = "lonworks"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "LonWorks/LonTalk IP - Building automation, device discovery"
    default_ports = [1628, 1629]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"LonWorks/LonTalk Enumeration: {host}")
        for port in ports:
            if is_port_open(host, port, self.config.timeout):
                self._record(f"LonWorks port {port} open", host,
                             "LonTalk IP-852 channel", "success")
                resp = self._tcp(host, port, b'\x00' * 4)
                if resp:
                    self._record(f"LonWorks response ({port})", host, hex_dump(resp), "success")
            resp = self._udp(host, port, b'\x00' * 4)
            if resp:
                self._record(f"LonWorks UDP ({port})", host, hex_dump(resp), "success")
        return self.results


class IOLinkModule(BaseModule):
    name = "io_link"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "IO-Link - Smart sensor/actuator, gateway enumeration via REST API"
    default_ports = [80, 443]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IO-Link Gateway Enumeration: {host}")
        for port in ports:
            use_ssl = (port == 443)
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                is_iolink = any(k in body.lower() for k in ['io-link', 'iolink', 'iodd', 'ifm', 'balluff'])
                self._record(f"IO-Link gateway web ({port})", host,
                             f"HTTP {status} {'- IO-Link detected' if is_iolink else ''}",
                             "success" if is_iolink else "info")
            # Common IO-Link master REST endpoints
            for path in ['/iolinkmaster/port/1/iolinkdevice/pdin',
                         '/iolinkmaster/port/1/iolinkdevice/vendorid',
                         '/api/v1/devices']:
                status, _, body = self._http(host, port, path, use_ssl=use_ssl)
                if status == 200 and body.strip():
                    self._record(f"IO-Link API: {path}", host, body[:300], "success")
        return self.results


class CANopenModule(BaseModule):
    name = "canopen"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "CANopen - CAN bus enumeration via CAN-to-Ethernet gateways"
    default_ports = [11898, 80]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"CANopen Gateway Enumeration: {host}")
        for port in ports:
            if port == 80:
                status, hdrs, body = self._http(host, 80, "/")
                if status > 0:
                    is_can = any(k in body.lower() for k in ['canopen', 'can bus', 'anybus', 'peak', 'hilscher'])
                    if is_can:
                        self._record("CANopen gateway web UI", host, f"HTTP {status}", "success")
            elif is_port_open(host, port, self.config.timeout):
                self._record(f"CANopen-over-Ethernet port {port}", host,
                             "CAN bus gateway TCP service", "info")
                resp = self._tcp(host, port, b'\x00' * 4)
                if resp:
                    self._record(f"CANopen response ({port})", host, hex_dump(resp), "success")
        # Check for local CAN interfaces
        if platform.system() == "Linux" and self.config.privileged:
            result = self._os_cmd("ip link show type can 2>/dev/null")
            if 'can' in result.lower() and 'no' not in result.lower():
                self._record("Local CAN interfaces", host, result, "success")
        return self.results


class PROFIBUSModule(BaseModule):
    name = "profibus"
    category = ModuleCategory.ICS_OT_PROTOCOL
    description = "PROFIBUS DP/PA - Serial fieldbus, enumerate via PROFINET/gateway proxy"
    default_ports = [80, 34964]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"PROFIBUS Gateway Enumeration: {host}")
        self._record("PROFIBUS info", host,
                     "PROFIBUS DP/PA is serial RS-485. Access via PROFINET IO controllers or gateways.",
                     "info")
        for port in ports:
            if port == 80:
                status, hdrs, body = self._http(host, 80, "/")
                if status > 0:
                    is_pb = any(k in body.lower() for k in ['profibus', 'simatic', 'profinet'])
                    if is_pb:
                        self._record("PROFIBUS gateway web UI", host, f"HTTP {status}", "success")
            elif is_port_open(host, port, self.config.timeout):
                self._record(f"PROFINET/PROFIBUS port {port}", host, "Gateway service", "info")
        return self.results



# -----------------------------------------------------------------------------
# 5.2  IT / NETWORK PROTOCOL MODULES (15 modules) - All native Python
# -----------------------------------------------------------------------------

class SNMPModule(BaseModule):
    name = "snmp"
    category = ModuleCategory.IT_PROTOCOL
    description = "SNMP v1/v2c - Native BER/ASN.1 GetRequest, walk sysDescr, interfaces, ARP, MAC"
    default_ports = [161]

    def _snmp_get(self, host, port, community, oid):
        """Native SNMP GetRequest using BER encoding."""
        request_id = ber_encode_int(1)
        error_status = ber_encode_int(0)
        error_index = ber_encode_int(0)
        varbind = ber_encode_sequence([ber_encode_oid(oid), b'\x05\x00'])  # OID + NULL
        varbind_list = ber_encode_sequence([varbind])
        pdu_data = request_id + error_status + error_index + varbind_list
        pdu = b'\xA0' + ber_encode_length(len(pdu_data)) + pdu_data  # GetRequest PDU
        version = ber_encode_int(1)  # SNMPv2c
        comm = ber_encode_string(community)
        message = ber_encode_sequence([version, comm, pdu])
        return self._udp(host, port, message)

    def _snmp_getnext(self, host, port, community, oid):
        """Native SNMP GetNextRequest."""
        request_id = ber_encode_int(2)
        error_status = ber_encode_int(0)
        error_index = ber_encode_int(0)
        varbind = ber_encode_sequence([ber_encode_oid(oid), b'\x05\x00'])
        varbind_list = ber_encode_sequence([varbind])
        pdu_data = request_id + error_status + error_index + varbind_list
        pdu = b'\xA1' + ber_encode_length(len(pdu_data)) + pdu_data  # GetNextRequest
        version = ber_encode_int(1)
        comm = ber_encode_string(community)
        message = ber_encode_sequence([version, comm, pdu])
        return self._udp(host, port, message)

    def _parse_snmp_response(self, resp):
        """Parse SNMP response and extract OID-value pairs."""
        if not resp or len(resp) < 10:
            return None
        try:
            # Skip outer SEQUENCE, version, community to find PDU
            tag, val, off = ber_decode_tlv(resp, 0)  # SEQUENCE
            tag, ver, off = ber_decode_tlv(val, 0)    # version
            tag, comm, off = ber_decode_tlv(val, off)  # community
            tag, pdu_data, off = ber_decode_tlv(val, off)  # PDU
            # Parse PDU: requestId, errorStatus, errorIndex, varbindList
            tag, rid, poff = ber_decode_tlv(pdu_data, 0)
            tag, es, poff = ber_decode_tlv(pdu_data, poff)
            tag, ei, poff = ber_decode_tlv(pdu_data, poff)
            tag, vbl, poff = ber_decode_tlv(pdu_data, poff)  # varbindList SEQUENCE
            # Parse first varbind
            tag, vb, voff = ber_decode_tlv(vbl, 0)  # varbind SEQUENCE
            tag, oid_val, voff2 = ber_decode_tlv(vb, 0)  # OID
            tag, data_val, voff2 = ber_decode_tlv(vb, voff2)  # Value
            oid_str = ber_decode_oid(oid_val) if tag == 0x06 else ""
            return (oid_str, data_val, tag)
        except Exception:
            return None

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"SNMP Enumeration: {host}")
        communities = ['public', 'private', 'community', 'snmp', 'monitor', 'admin']
        oids = {
            '1.3.6.1.2.1.1.1.0': 'sysDescr',
            '1.3.6.1.2.1.1.3.0': 'sysUpTime',
            '1.3.6.1.2.1.1.4.0': 'sysContact',
            '1.3.6.1.2.1.1.5.0': 'sysName',
            '1.3.6.1.2.1.1.6.0': 'sysLocation',
            '1.3.6.1.2.1.1.7.0': 'sysServices',
        }
        for port in ports:
            found_community = None
            for comm in communities:
                resp = self._snmp_get(host, port, comm, '1.3.6.1.2.1.1.1.0')
                if resp and len(resp) > 20:
                    parsed = self._parse_snmp_response(resp)
                    if parsed:
                        oid, val, tag = parsed
                        self._record(f"SNMP community '{comm}' accepted", host,
                                     f"sysDescr: {safe_decode(val)}", "success")
                        found_community = comm
                        break
                    else:
                        self._record(f"SNMP response with '{comm}'", host, hex_dump(resp), "info")
                        found_community = comm
                        break
            if found_community:
                # Read remaining system OIDs
                for oid, name in list(oids.items())[1:]:
                    resp = self._snmp_get(host, port, found_community, oid)
                    if resp:
                        parsed = self._parse_snmp_response(resp)
                        if parsed:
                            self._record(f"SNMP {name}", host, safe_decode(parsed[1]), "success")
                # Walk interfaces table (first 5)
                current_oid = '1.3.6.1.2.1.2.2.1.2'  # ifDescr
                for _ in range(5):
                    resp = self._snmp_getnext(host, port, found_community, current_oid)
                    if resp:
                        parsed = self._parse_snmp_response(resp)
                        if parsed and parsed[0].startswith('1.3.6.1.2.1.2.2.1.2'):
                            self._record("SNMP ifDescr", host,
                                         f"{parsed[0]} = {safe_decode(parsed[1])}", "success")
                            current_oid = parsed[0]
                        else:
                            break
                    else:
                        break
            else:
                self._record("SNMP probe", host, "No community string accepted", "info")
        return self.results


class SMBModule(BaseModule):
    name = "smb"
    category = ModuleCategory.IT_PROTOCOL
    description = "SMB/CIFS - Native negotiate, null session, shares, OS info, domain, signing"
    default_ports = [445, 139]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"SMB Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # SMB2 Negotiate Protocol Request
            smb2_negotiate = bytearray(116)
            smb2_negotiate[0:4] = b'\x00\x00\x00\x70'  # NetBIOS Session (length 112)
            smb2_negotiate[4:8] = b'\xFE\x53\x4D\x42'   # SMB2 magic
            smb2_negotiate[8:10] = struct.pack('<H', 64)  # Header length
            smb2_negotiate[12:14] = struct.pack('<H', 0)  # Command: Negotiate
            smb2_negotiate[16:20] = struct.pack('<I', 0)  # Status
            smb2_negotiate[64:66] = struct.pack('<H', 36) # StructureSize
            smb2_negotiate[66:68] = struct.pack('<H', 3)  # DialectCount
            smb2_negotiate[68:70] = struct.pack('<H', 1)  # SecurityMode (signing enabled)
            smb2_negotiate[76:80] = struct.pack('<I', 0x7F) # Capabilities
            # Dialects: SMB 2.0.2, 2.1, 3.0
            smb2_negotiate[100:102] = struct.pack('<H', 0x0202)
            smb2_negotiate[102:104] = struct.pack('<H', 0x0210)
            smb2_negotiate[104:106] = struct.pack('<H', 0x0300)
            resp = self._tcp(host, port, bytes(smb2_negotiate))
            if resp and len(resp) > 72 and resp[4:8] == b'\xFE\x53\x4D\x42':
                # Parse negotiate response
                dialect = struct.unpack('<H', resp[68+4:70+4])[0] if len(resp) > 74 else 0
                sec_mode = struct.unpack('<H', resp[66+4:68+4])[0] if len(resp) > 72 else 0
                signing = "required" if sec_mode & 2 else "enabled" if sec_mode & 1 else "disabled"
                self._record("SMB2 Negotiate", host,
                             f"Dialect: {dialect:#06x}, Signing: {signing}", "success")
                # Extract server GUID
                if len(resp) > 92:
                    guid = resp[76+4:92+4]
                    self._record("SMB Server GUID", host, guid.hex(), "success")
            elif resp and len(resp) > 10:
                # Try SMB1 fallback
                self._record("SMB response (may be SMB1)", host, hex_dump(resp[:80]), "info")
            else:
                self._record(f"SMB (port {port})", host, "No response to negotiate", "info")
        return self.results


class SSHModule(BaseModule):
    name = "ssh"
    category = ModuleCategory.IT_PROTOCOL
    description = "SSH - Banner grab, server version, supported algorithms, auth methods"
    default_ports = [22, 2222]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"SSH Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                # Read server banner
                banner = s.recv(1024)
                if banner:
                    banner_str = safe_decode(banner).strip()
                    self._record("SSH Banner", host, banner_str, "success")
                    # Send our version
                    s.sendall(b"SSH-2.0-ReadOnlyEnum_2.0\r\n")
                    # Read Key Exchange Init (SSH_MSG_KEXINIT = 20)
                    kex_resp = s.recv(8192)
                    if kex_resp and len(kex_resp) > 20:
                        # Parse KEX_INIT message
                        # Skip packet length(4) + padding(1) + msg_type(1) + cookie(16)
                        offset = 22 if kex_resp[5] == 20 else 0
                        if offset == 0:
                            # May have different framing
                            for i in range(len(kex_resp) - 1):
                                if kex_resp[i] == 20:  # SSH_MSG_KEXINIT
                                    offset = i + 17
                                    break
                        if offset > 0 and offset < len(kex_resp):
                            algo_fields = ['kex_algorithms', 'server_host_key', 'encryption_c2s',
                                           'encryption_s2c', 'mac_c2s', 'mac_s2c', 'compression_c2s']
                            pos = offset
                            for fname in algo_fields:
                                if pos + 4 > len(kex_resp):
                                    break
                                str_len = struct.unpack('>I', kex_resp[pos:pos+4])[0]
                                pos += 4
                                if pos + str_len > len(kex_resp):
                                    break
                                algo_str = kex_resp[pos:pos+str_len].decode('utf-8', errors='replace')
                                pos += str_len
                                self._record(f"SSH {fname}", host, algo_str, "success")
                else:
                    self._record(f"SSH (port {port})", host, "No banner received", "info")
            except Exception as e:
                self._record("SSH probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results


class FTPModule(BaseModule):
    name = "ftp"
    category = ModuleCategory.IT_PROTOCOL
    description = "FTP - Native banner grab, anonymous login check, SYST, FEAT, directory listing"
    default_ports = [21]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"FTP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                banner = s.recv(1024)
                if banner:
                    self._record("FTP Banner", host, safe_decode(banner).strip(), "success")
                # Try anonymous login
                s.sendall(b"USER anonymous\r\n")
                resp = s.recv(1024)
                self._record("FTP USER anonymous", host, safe_decode(resp).strip(), "info")
                if b'331' in resp:
                    s.sendall(b"PASS anonymous@\r\n")
                    resp = s.recv(1024)
                    if b'230' in resp:
                        self._record("FTP Anonymous Login", host, "ALLOWED - anonymous access", "warn")
                        # SYST command
                        s.sendall(b"SYST\r\n")
                        resp = s.recv(1024)
                        if resp:
                            self._record("FTP SYST", host, safe_decode(resp).strip(), "success")
                        # FEAT command
                        s.sendall(b"FEAT\r\n")
                        resp = s.recv(2048)
                        if resp:
                            self._record("FTP FEAT", host, safe_decode(resp).strip(), "success")
                        # PWD
                        s.sendall(b"PWD\r\n")
                        resp = s.recv(1024)
                        if resp:
                            self._record("FTP PWD", host, safe_decode(resp).strip(), "success")
                    else:
                        self._record("FTP Anonymous Login", host, "DENIED", "info")
                s.sendall(b"QUIT\r\n")
            except Exception as e:
                self._record("FTP probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results


class TFTPModule(BaseModule):
    name = "tftp"
    category = ModuleCategory.IT_PROTOCOL
    description = "TFTP - Read request probe, firmware/config file access check"
    default_ports = [69]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"TFTP Enumeration: {host}")
        for port in ports:
            # TFTP Read Request (RRQ) for common filenames
            for fname in ['startup-config', 'running-config', 'config.cfg']:
                # RRQ: opcode=1, filename, 0, mode("octet"), 0
                rrq = struct.pack('>H', 1) + fname.encode() + b'\x00' + b'octet\x00'
                resp = self._udp(host, port, rrq)
                if resp and len(resp) >= 4:
                    opcode = struct.unpack('>H', resp[:2])[0]
                    if opcode == 3:  # DATA
                        self._record(f"TFTP RRQ '{fname}'", host,
                                     f"File accessible! Data block received ({len(resp)} bytes)",
                                     "warn", "No authentication - file readable")
                    elif opcode == 5:  # ERROR
                        err_code = struct.unpack('>H', resp[2:4])[0]
                        err_msg = resp[4:].split(b'\x00')[0].decode('utf-8', errors='replace')
                        self._record(f"TFTP RRQ '{fname}'", host,
                                     f"Error {err_code}: {err_msg}", "info")
                else:
                    self._record(f"TFTP probe (port {port})", host, "No TFTP response", "info")
                    break  # No service on this port
        return self.results


class TelnetModule(BaseModule):
    name = "telnet"
    category = ModuleCategory.IT_PROTOCOL
    description = "Telnet - Banner grab, option negotiation, service identification"
    default_ports = [23, 2323]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Telnet Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                # Read initial banner (may include telnet option negotiation)
                data = b''
                s.settimeout(3)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 8192:
                            break
                        # Respond to telnet WILL/DO with WONT/DONT
                        i = 0
                        while i < len(chunk) - 2:
                            if chunk[i] == 0xFF:
                                if chunk[i+1] == 0xFB:  # WILL -> DONT
                                    s.sendall(bytes([0xFF, 0xFE, chunk[i+2]]))
                                elif chunk[i+1] == 0xFD:  # DO -> WONT
                                    s.sendall(bytes([0xFF, 0xFC, chunk[i+2]]))
                                i += 3
                            else:
                                i += 1
                except socket.timeout:
                    pass
                # Strip telnet control sequences for display
                clean = bytearray()
                i = 0
                while i < len(data):
                    if data[i] == 0xFF and i + 2 < len(data):
                        i += 3  # Skip IAC + command + option
                    else:
                        clean.append(data[i])
                        i += 1
                banner = bytes(clean).decode('utf-8', errors='replace').strip()
                if banner:
                    self._record(f"Telnet Banner (port {port})", host, banner[:500], "success")
                else:
                    self._record(f"Telnet (port {port})", host, "Connected, no visible banner", "info")
            except Exception as e:
                self._record("Telnet probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results


class DNSModule(BaseModule):
    name = "dns"
    category = ModuleCategory.IT_PROTOCOL
    description = "DNS - Native query (A, AAAA, MX, NS, TXT, SOA, SRV), zone transfer attempt"
    default_ports = [53]

    def _dns_query(self, host, port, qname, qtype=1):
        """Build native DNS query packet. qtype: 1=A, 28=AAAA, 15=MX, 2=NS, 16=TXT, 6=SOA, 33=SRV, 252=AXFR"""
        txid = struct.pack('>H', 0x1234)
        flags = struct.pack('>H', 0x0100)  # Standard query, recursion desired
        counts = struct.pack('>HHHH', 1, 0, 0, 0)  # 1 question
        # Encode QNAME
        qn = b''
        for part in qname.split('.'):
            qn += bytes([len(part)]) + part.encode()
        qn += b'\x00'
        question = qn + struct.pack('>HH', qtype, 1)  # QTYPE, QCLASS=IN
        packet = txid + flags + counts + question
        if qtype == 252:  # AXFR uses TCP
            tcp_pkt = struct.pack('>H', len(packet)) + packet
            return self._tcp(host, port, tcp_pkt, recv_size=65535)
        else:
            return self._udp(host, port, packet)

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"DNS Enumeration: {host}")
        for port in ports:
            # Version query
            resp = self._dns_query(host, port, 'version.bind', 16)  # TXT
            if resp and len(resp) > 12:
                self._record("DNS version.bind", host, hex_dump(resp), "success")
            # Check if it's a resolver
            resp = self._dns_query(host, port, 'google.com', 1)  # A record
            if resp and len(resp) > 12:
                ancount = struct.unpack('>H', resp[6:8])[0]
                if ancount > 0:
                    self._record("DNS resolver active", host,
                                 f"Resolved google.com ({ancount} answers)", "success")
                else:
                    self._record("DNS service", host, "Responding but no answer for google.com", "info")
            # Zone transfer attempt (AXFR)
            resp = self._dns_query(host, port, host, 252)
            if resp and len(resp) > 20:
                # Check if we got records (RCODE=0 with answers)
                if len(resp) > 5:
                    rcode = resp[5] & 0x0F if len(resp) > 5 else 5
                    if rcode == 0:
                        self._record("DNS Zone Transfer", host,
                                     f"AXFR response received ({len(resp)} bytes)", "warn",
                                     "Zone transfer may be allowed")
                    else:
                        self._record("DNS AXFR refused", host, f"RCODE={rcode}", "info")
        return self.results


class DHCPModule(BaseModule):
    name = "dhcp"
    category = ModuleCategory.IT_PROTOCOL
    description = "DHCP - Native discover, server identification, lease info, options"
    default_ports = [67]
    requires_root = True

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"DHCP Enumeration: {host}")
        # DHCP Discover packet
        xid = struct.pack('>I', 0x12345678)
        dhcp = bytearray(300)
        dhcp[0] = 1       # BOOTREQUEST
        dhcp[1] = 1       # Ethernet
        dhcp[2] = 6       # HW addr len
        dhcp[4:8] = xid   # Transaction ID
        dhcp[236:240] = b'\x63\x82\x53\x63'  # Magic cookie
        # DHCP Options: 53=DHCP Discover, 255=End
        dhcp[240:243] = bytes([53, 1, 1])    # DHCP Discover
        dhcp[243] = 255                       # End
        for port in ports:
            resp = self._udp(host, port, bytes(dhcp))
            if resp and len(resp) > 240:
                if resp[0] == 2:  # BOOTREPLY
                    offered_ip = socket.inet_ntoa(resp[16:20])
                    server_ip = socket.inet_ntoa(resp[20:24])
                    self._record("DHCP Offer", host,
                                 f"Offered IP: {offered_ip}, Server: {server_ip}", "success")
                else:
                    self._record("DHCP response", host, hex_dump(resp[:50]), "info")
            else:
                self._record("DHCP probe", host, "No response (may require broadcast/root)", "info")
        return self.results


class LDAPModule(BaseModule):
    name = "ldap"
    category = ModuleCategory.IT_PROTOCOL
    description = "LDAP - Native BER bind, root DSE read, naming contexts, schema info"
    default_ports = [389, 636]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"LDAP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 636)
            # Anonymous simple bind
            msg_id = ber_encode_int(1)
            # BindRequest: version=3, name="", auth=simple("")
            bind = b'\x60' + ber_encode_length(12) + ber_encode_int(3) + ber_encode_string("") + b'\x80\x00'
            bind_msg = ber_encode_sequence([msg_id, bind])
            if use_ssl:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = socket.create_connection((host, port), timeout=self.config.timeout)
                    s = ctx.wrap_socket(s, server_hostname=host)
                except Exception:
                    self._record(f"LDAPS connection failed ({port})", host, "TLS handshake error", "info")
                    continue
            else:
                s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                s.sendall(bind_msg)
                resp = s.recv(4096)
                if resp and len(resp) > 5:
                    self._record("LDAP Anonymous Bind", host,
                                 f"Response received ({len(resp)} bytes)", "success")
                    # SearchRequest for Root DSE
                    msg_id2 = ber_encode_int(2)
                    # SearchRequest: baseObject="", scope=base(0), derefAliases=never(0),
                    # sizeLimit=0, timeLimit=0, typesOnly=false
                    search = b'\x63' + ber_encode_length(30)
                    search += ber_encode_string("")  # baseObject
                    search += ber_encode_int(0)      # scope=base
                    search += ber_encode_int(0)      # deref
                    search += ber_encode_int(0)      # sizeLimit
                    search += ber_encode_int(0)      # timeLimit
                    search += b'\x01\x01\x00'        # typesOnly=false
                    # Filter: present objectClass
                    search += b'\x87\x0B' + b'objectClass'
                    # Attributes: empty (return all)
                    search += ber_encode_sequence([])
                    search_msg = ber_encode_sequence([msg_id2, search])
                    s.sendall(search_msg)
                    resp = s.recv(8192)
                    if resp:
                        self._record("LDAP Root DSE", host, hex_dump(resp[:200]), "success",
                                     "namingContexts, supportedLDAPVersion, supportedSASLMechanisms")
                s.close()
            except Exception as e:
                self._record("LDAP probe", host, str(e), "info")
                try: s.close()
                except: pass
        return self.results


class HTTPModule(BaseModule):
    name = "http"
    category = ModuleCategory.IT_PROTOCOL
    description = "HTTP/HTTPS - Headers, server, security headers, robots.txt, certificate info"
    default_ports = [80, 443, 8080, 8443]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"HTTP/HTTPS Enumeration: {host}")
        for port in ports:
            use_ssl = port in [443, 8443]
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Main page
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                self._record(f"HTTP {'S' if use_ssl else ''} (port {port})", host,
                             f"Status: {status}, Server: {hdrs.get('Server', 'N/A')}", "success")
                # Security headers check
                sec_headers = ['Strict-Transport-Security', 'X-Frame-Options',
                               'X-Content-Type-Options', 'Content-Security-Policy',
                               'X-XSS-Protection', 'Referrer-Policy']
                present = [h for h in sec_headers if h.lower() in {k.lower(): v for k, v in hdrs.items()}]
                missing = [h for h in sec_headers if h.lower() not in {k.lower(): v for k, v in hdrs.items()}]
                if present:
                    self._record("Security headers present", host, ', '.join(present), "success")
                if missing:
                    self._record("Security headers missing", host, ', '.join(missing), "warn")
                # Title extraction
                title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    self._record("Page title", host, title_match.group(1).strip()[:200], "info")
            # robots.txt
            status2, _, body2 = self._http(host, port, "/robots.txt", use_ssl=use_ssl)
            if status2 == 200 and body2.strip() and 'user-agent' in body2.lower():
                self._record("robots.txt", host, body2[:500], "success")
            # TLS certificate info
            if use_ssl:
                cert_info = self._ssl_info(host, port)
                if cert_info:
                    self._record("TLS Certificate", host,
                                 f"Version: {cert_info['version']}, Cipher: {cert_info['cipher']}", "success")
                    if cert_info['cert']:
                        subj = cert_info['cert'].get('subject', '')
                        self._record("TLS Subject", host, str(subj), "success")
                        not_after = cert_info['cert'].get('notAfter', '')
                        if not_after:
                            self._record("TLS Expiry", host, not_after, "info")
        return self.results


class NFSModule(BaseModule):
    name = "nfs"
    category = ModuleCategory.IT_PROTOCOL
    description = "NFS - Native RPC portmap, exported shares enumeration"
    default_ports = [111, 2049]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"NFS Enumeration: {host}")
        for port in ports:
            if port == 111:
                # RPC Portmap DUMP request
                # XID(4), MSG_TYPE=CALL(0), RPC_VER=2, PROG=100000(portmap), VER=2, PROC=4(DUMP)
                xid = struct.pack('>I', 0x12340001)
                rpc_call = xid + struct.pack('>IIIIII', 0, 2, 100000, 2, 4, 0)
                rpc_call += struct.pack('>II', 0, 0)  # Credentials (AUTH_NULL)
                rpc_call += struct.pack('>II', 0, 0)  # Verifier (AUTH_NULL)
                # Over TCP: prepend fragment header
                tcp_rpc = struct.pack('>I', 0x80000000 | len(rpc_call)) + rpc_call
                resp = self._tcp(host, port, tcp_rpc, recv_size=8192)
                if resp and len(resp) > 28:
                    self._record("RPC Portmap DUMP", host, hex_dump(resp[:100]), "success",
                                 "Lists all registered RPC services (NFS, mountd, etc.)")
            if port == 2049 or port == 111:
                # Try NFS EXPORT/MOUNT list via portmap
                xid = struct.pack('>I', 0x12340002)
                mount_call = xid + struct.pack('>IIIIII', 0, 2, 100005, 3, 5, 0)  # MOUNT prog, EXPORT proc
                mount_call += struct.pack('>II', 0, 0)
                mount_call += struct.pack('>II', 0, 0)
                tcp_mount = struct.pack('>I', 0x80000000 | len(mount_call)) + mount_call
                resp = self._tcp(host, 111 if port == 111 else port, tcp_mount, recv_size=8192)
                if resp and len(resp) > 28:
                    self._record("NFS EXPORT list", host, hex_dump(resp[:200]), "success",
                                 "Exported NFS shares and allowed hosts")
            if is_port_open(host, 2049, self.config.timeout):
                self._record("NFS service (2049)", host, "NFS port open", "success")
        return self.results


class IPMIModule(BaseModule):
    name = "ipmi"
    category = ModuleCategory.IT_PROTOCOL
    description = "IPMI/BMC - Native RMCP ASF Ping, Get Channel Auth, firmware, user list"
    default_ports = [623]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IPMI/BMC Enumeration: {host}")
        for port in ports:
            # RMCP ASF Presence Ping (UDP)
            asf_ping = bytes([0x06, 0x00, 0xFF, 0x06,  # RMCP header
                              0x00, 0x00, 0x11, 0xBE,   # ASF header
                              0x80, 0x00, 0x00, 0x00])   # Ping
            resp = self._udp(host, port, asf_ping)
            if resp and len(resp) >= 12:
                self._record("IPMI RMCP Ping Response", host, hex_dump(resp), "success",
                             "BMC responding. Check for IPMI auth bypass (CVE-2013-4786).")
                # IPMI Get Channel Auth Capabilities
                ipmi_auth = bytes([
                    0x06, 0x00, 0xFF, 0x07,          # RMCP
                    0x00, 0x00, 0x00, 0x00,           # Session seq
                    0x00, 0x00, 0x00, 0x00,           # Session ID
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Auth code (null)
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x09,                              # Message length
                    0x20, 0x18, 0xC8, 0x81, 0x04,      # Target, LUN, NetFn, Seq
                    0x38,                              # Get Channel Auth Caps cmd
                    0x0E, 0x04,                        # Channel=current, Priv=Admin
                    0x00                               # Checksum placeholder
                ])
                resp2 = self._udp(host, port, ipmi_auth)
                if resp2:
                    self._record("IPMI Channel Auth Capabilities", host, hex_dump(resp2), "success")
            else:
                self._record(f"IPMI (port {port})", host, "No RMCP response", "info")
        return self.results


class RedfishModule(BaseModule):
    name = "redfish"
    category = ModuleCategory.IT_PROTOCOL
    description = "Redfish API - BMC/iLO/iDRAC system info, firmware, inventory via REST"
    default_ports = [443, 8443, 80]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Redfish API Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = port in [443, 8443]
            # Redfish service root
            status, hdrs, body = self._http(host, port, "/redfish/v1/", use_ssl=use_ssl)
            if status == 200 and body:
                self._record("Redfish Service Root", host, body[:500], "success",
                             "BMC management API (iLO, iDRAC, IMM, OpenBMC)")
                try:
                    data = json.loads(body)
                    for key in ['Name', 'RedfishVersion', 'UUID', 'Vendor']:
                        if key in data:
                            self._record(f"Redfish {key}", host, str(data[key]), "success")
                except json.JSONDecodeError:
                    pass
                # Systems collection
                status2, _, body2 = self._http(host, port, "/redfish/v1/Systems", use_ssl=use_ssl)
                if status2 == 200 and body2:
                    self._record("Redfish Systems", host, body2[:500], "success")
            elif status > 0:
                self._record(f"HTTP {status} on /redfish/v1/", host,
                             hdrs.get('Server', ''), "info")
        return self.results


class RDPModule(BaseModule):
    name = "rdp"
    category = ModuleCategory.IT_PROTOCOL
    description = "RDP - Native X.224 connection, NLA status, encryption, certificate info"
    default_ports = [3389]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"RDP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # X.224 Connection Request (RDP negotiation)
            # TPKT header + X.224 CR + RDP Negotiation Request
            x224_cr = bytes([
                0x03, 0x00, 0x00, 0x13,  # TPKT: version=3, length=19
                0x0E,                     # X.224: length indicator
                0xE0,                     # CR (Connection Request)
                0x00, 0x00,               # DST-REF
                0x00, 0x00,               # SRC-REF
                0x00,                     # Class 0
                0x01,                     # RDP Neg Request type
                0x00,                     # flags
                0x08, 0x00, 0x00, 0x00,   # length = 8
                0x03, 0x00, 0x00, 0x00    # protocols: TLS + CredSSP
            ])
            resp = self._tcp(host, port, x224_cr)
            if resp and len(resp) >= 11:
                if resp[0] == 0x03:  # TPKT
                    pdu_type = resp[5] if len(resp) > 5 else 0
                    if pdu_type == 0xD0:  # CC (Connection Confirm)
                        self._record("RDP X.224 Connection Confirmed", host,
                                     hex_dump(resp), "success")
                        # Check for RDP Negotiation Response
                        if len(resp) >= 19:
                            neg_type = resp[11] if len(resp) > 11 else 0
                            if neg_type == 0x02:  # RDP Neg Response
                                proto = struct.unpack('<I', resp[15:19])[0] if len(resp) >= 19 else 0
                                protos = []
                                if proto & 1: protos.append("TLS")
                                if proto & 2: protos.append("CredSSP/NLA")
                                self._record("RDP Security Protocol", host,
                                             f"Selected: {', '.join(protos) if protos else 'Standard RDP'}", "success")
                            elif neg_type == 0x03:  # Neg Failure
                                self._record("RDP Negotiation Failed", host,
                                             "Server rejected security protocol", "warn")
                    else:
                        self._record("RDP response", host, hex_dump(resp), "info")
            # TLS certificate
            cert = self._ssl_info(host, port)
            if cert:
                self._record("RDP TLS Certificate", host,
                             f"Version: {cert['version']}, Cipher: {cert['cipher']}", "success")
                if cert['cert']:
                    self._record("RDP Cert Subject", host, str(cert['cert'].get('subject', '')), "success")
        return self.results


class VNCModule(BaseModule):
    name = "vnc"
    category = ModuleCategory.IT_PROTOCOL
    description = "VNC - Native RFB handshake, server version, auth type, security level"
    default_ports = [5900, 5901, 5800]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"VNC Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            s = tcp_connect(host, port, self.config.timeout)
            if not s:
                continue
            try:
                # RFB Protocol Version handshake
                banner = s.recv(1024)
                if banner and b'RFB' in banner:
                    version = safe_decode(banner).strip()
                    self._record("VNC RFB Version", host, version, "success")
                    # Send our version back
                    s.sendall(b"RFB 003.008\n")
                    # Read security types
                    sec_resp = s.recv(1024)
                    if sec_resp and len(sec_resp) >= 1:
                        num_types = sec_resp[0]
                        if num_types > 0 and len(sec_resp) >= 1 + num_types:
                            types = list(sec_resp[1:1+num_types])
                            type_names = {0: 'Invalid', 1: 'None(NO AUTH)', 2: 'VNC',
                                          5: 'RA2', 6: 'RA2ne', 16: 'Tight', 18: 'TLS',
                                          19: 'VeNCrypt', 22: 'SASL'}
                            type_strs = [f"{t}({type_names.get(t, 'unknown')})" for t in types]
                            self._record("VNC Security Types", host,
                                         f"Auth methods: {', '.join(type_strs)}", "success")
                            if 1 in types:
                                self._record("VNC NO AUTH", host,
                                             "VNC allows connection without password!", "warn")
                        elif num_types == 0 and len(sec_resp) > 4:
                            # Error message follows
                            err_len = struct.unpack('>I', sec_resp[1:5])[0] if len(sec_resp) >= 5 else 0
                            err_msg = sec_resp[5:5+err_len].decode('utf-8', errors='replace')
                            self._record("VNC error", host, err_msg, "info")
                elif banner:
                    self._record(f"VNC port {port} banner", host, safe_decode(banner), "info")
            except Exception as e:
                self._record("VNC probe", host, str(e), "info")
            finally:
                try: s.close()
                except: pass
        return self.results



# -----------------------------------------------------------------------------
# 5.3  WIRELESS / IoT PROTOCOL MODULES (10 modules)
# -----------------------------------------------------------------------------

class MQTTModule(BaseModule):
    name = "mqtt"
    category = ModuleCategory.WIRELESS_IOT
    description = "MQTT - Native CONNECT, broker info, anonymous access, topic enumeration"
    default_ports = [1883, 8883]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"MQTT Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 8883)
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    raw = socket.create_connection((host, port), timeout=self.config.timeout)
                    s = ctx.wrap_socket(raw, server_hostname=host)
                else:
                    s = tcp_connect(host, port, self.config.timeout)
                if not s:
                    continue
                # MQTT CONNECT packet (anonymous)
                client_id = b'ReadOnlyEnum'
                proto_name = struct.pack('>H', 4) + b'MQTT'
                proto_level = bytes([0x04])  # MQTT 3.1.1
                connect_flags = bytes([0x02])  # Clean session
                keep_alive = struct.pack('>H', 60)
                payload = struct.pack('>H', len(client_id)) + client_id
                var_header = proto_name + proto_level + connect_flags + keep_alive
                remaining = var_header + payload
                # Fixed header: type=CONNECT(1), remaining length
                fixed = bytes([0x10]) + bytes([len(remaining)])
                s.sendall(fixed + remaining)
                resp = s.recv(1024)
                if resp and len(resp) >= 4 and resp[0] == 0x20:  # CONNACK
                    return_code = resp[3]
                    codes = {0: "Accepted", 1: "Unacceptable protocol", 2: "ID rejected",
                             3: "Server unavailable", 4: "Bad credentials", 5: "Not authorized"}
                    self._record("MQTT CONNACK", host,
                                 f"Return code: {return_code} ({codes.get(return_code, 'unknown')})",
                                 "success" if return_code == 0 else "info")
                    if return_code == 0:
                        self._record("MQTT Anonymous Access", host, "ALLOWED - no auth required", "warn")
                        # Subscribe to $SYS/# for broker info
                        topic = b'$SYS/#'
                        sub_payload = struct.pack('>H', 1)  # Packet ID
                        sub_payload += struct.pack('>H', len(topic)) + topic + bytes([0])
                        sub_fixed = bytes([0x82, len(sub_payload)])
                        s.sendall(sub_fixed + sub_payload)
                        time.sleep(1)
                        s.settimeout(2)
                        try:
                            pub_data = s.recv(4096)
                            if pub_data:
                                self._record("MQTT $SYS topics", host,
                                             hex_dump(pub_data[:200]), "success",
                                             "Broker info: version, clients, messages, uptime")
                        except socket.timeout:
                            pass
                        # DISCONNECT
                        s.sendall(bytes([0xE0, 0x00]))
                s.close()
            except Exception as e:
                self._record(f"MQTT (port {port})", host, str(e), "info")
        return self.results


class MQTTSNModule(BaseModule):
    name = "mqtt_sn"
    category = ModuleCategory.WIRELESS_IOT
    description = "MQTT-SN - UDP-based, gateway discovery, SEARCHGW probe"
    default_ports = [1883, 10000]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"MQTT-SN Enumeration: {host}")
        for port in ports:
            # MQTT-SN SEARCHGW: Length=3, Type=0x01(SEARCHGW), Radius=0
            searchgw = bytes([0x03, 0x01, 0x00])
            resp = self._udp(host, port, searchgw)
            if resp and len(resp) >= 3:
                msg_type = resp[1] if len(resp) > 1 else 0
                if msg_type == 0x02:  # GWINFO
                    self._record("MQTT-SN GWINFO", host, hex_dump(resp), "success",
                                 "MQTT-SN gateway found. UDP-based IoT messaging.")
                else:
                    self._record("MQTT-SN response", host, hex_dump(resp), "info")
        return self.results


class CoAPModule(BaseModule):
    name = "coap"
    category = ModuleCategory.WIRELESS_IOT
    description = "CoAP - Native resource discovery (.well-known/core), GET requests"
    default_ports = [5683, 5684]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"CoAP Enumeration: {host}")
        for port in ports:
            # CoAP GET .well-known/core
            # Header: Ver=1, Type=CON(0), TKL=0, Code=GET(0.01), MsgID=1
            coap_get = bytes([0x40, 0x01, 0x00, 0x01])
            # Option: Uri-Path = ".well-known" (delta=11, len=11)
            coap_get += bytes([0xBB]) + b'.well-known'
            # Option: Uri-Path = "core" (delta=0, len=4)
            coap_get += bytes([0x04]) + b'core'
            resp = self._udp(host, port, coap_get)
            if resp and len(resp) >= 4:
                code_class = (resp[1] >> 5) & 0x07
                code_detail = resp[1] & 0x1F
                self._record("CoAP .well-known/core", host,
                             f"Response {code_class}.{code_detail:02d}: {safe_decode(resp[4:])}",
                             "success" if code_class == 2 else "info",
                             "Resource directory listing for IoT device")
        return self.results


class LwM2MModule(BaseModule):
    name = "lwm2m"
    category = ModuleCategory.WIRELESS_IOT
    description = "LwM2M - OMA IoT device management over CoAP, bootstrap/registration probe"
    default_ports = [5683, 5684]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"LwM2M Enumeration: {host}")
        for port in ports:
            # CoAP GET /rd (registration directory)
            coap = bytes([0x40, 0x01, 0x00, 0x02, 0x22]) + b'rd'
            resp = self._udp(host, port, coap)
            if resp and len(resp) >= 4:
                self._record("LwM2M registration dir", host, safe_decode(resp), "success",
                             "LwM2M objects: /1(Server), /3(Device), /5(FW Update)")
            # CoAP GET /bs (bootstrap)
            coap_bs = bytes([0x40, 0x01, 0x00, 0x03, 0x22]) + b'bs'
            resp = self._udp(host, port, coap_bs)
            if resp and len(resp) >= 4:
                self._record("LwM2M bootstrap", host, safe_decode(resp), "info")
        return self.results


class AMQPModule(BaseModule):
    name = "amqp"
    category = ModuleCategory.WIRELESS_IOT
    description = "AMQP - Native protocol header exchange, server properties, vhosts"
    default_ports = [5672, 5671]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"AMQP Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 5671)
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    raw = socket.create_connection((host, port), timeout=self.config.timeout)
                    s = ctx.wrap_socket(raw, server_hostname=host)
                else:
                    s = tcp_connect(host, port, self.config.timeout)
                if not s:
                    continue
                # AMQP 0-9-1 Protocol Header
                s.sendall(b'AMQP\x00\x00\x09\x01')
                resp = s.recv(4096)
                if resp and len(resp) > 10:
                    if resp[0:4] == b'AMQP':
                        self._record("AMQP Version Mismatch", host,
                                     f"Server wants: {resp[5]}.{resp[6]}.{resp[7]}", "info")
                    else:
                        # Connection.Start frame
                        self._record("AMQP Connection.Start", host, hex_dump(resp[:100]), "success",
                                     "Server properties: product, version, platform, mechanisms")
                        # Try to extract server product from frame
                        for marker in [b'product', b'version', b'platform', b'RabbitMQ', b'ActiveMQ']:
                            idx = resp.find(marker)
                            if idx > 0:
                                snippet = resp[idx:idx+50]
                                self._record("AMQP server info", host, safe_decode(snippet), "success")
                                break
                s.close()
            except Exception as e:
                self._record(f"AMQP (port {port})", host, str(e), "info")
        return self.results


class ZigbeeModule(BaseModule):
    name = "zigbee"
    category = ModuleCategory.WIRELESS_IOT
    description = "Zigbee - Network discovery (requires Zigbee adapter: CC2531, ConBee)"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Zigbee Detection")
        self._record("Zigbee info", host,
                     "Zigbee is 802.15.4 wireless (2.4GHz). Requires USB adapter (CC2531, ConBee II, HUSBZB-1).",
                     "info")
        # Check for local Zigbee adapters
        if platform.system() == "Linux":
            usb = self._os_cmd("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null")
            if usb and '/dev/' in usb:
                self._record("Potential Zigbee adapters", host, usb, "info")
        return self.results


class BLEModule(BaseModule):
    name = "ble"
    category = ModuleCategory.WIRELESS_IOT
    description = "Bluetooth Low Energy - Device scan, service discovery (requires BLE adapter)"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"BLE Detection")
        self._record("BLE info", host,
                     "BLE requires local Bluetooth adapter. Use hcitool/bluetoothctl for scanning.",
                     "info")
        if platform.system() == "Linux":
            hci = self._os_cmd("hciconfig -a 2>/dev/null")
            if 'hci' in hci.lower():
                self._record("BLE adapter detected", host, hci[:300], "success")
        return self.results


class WifiModule(BaseModule):
    name = "wifi"
    category = ModuleCategory.WIRELESS_IOT
    description = "Wi-Fi - AP scan, SSID enumeration (requires wireless adapter)"
    default_ports = []
    requires_root = True

    def run(self, host, ports=None):
        print_subsection(f"Wi-Fi Detection")
        if platform.system() == "Linux":
            iw = self._os_cmd("iw dev 2>/dev/null")
            if 'Interface' in iw:
                self._record("Wi-Fi interfaces", host, iw[:500], "success")
                if self.config.privileged:
                    scan = self._os_cmd("iw dev $(iw dev | grep Interface | head -1 | awk '{print $2}') scan 2>/dev/null | head -50")
                    if 'SSID' in scan:
                        self._record("Wi-Fi AP scan", host, scan[:500], "success")
            else:
                self._record("Wi-Fi", host, "No wireless interfaces found", "info")
        else:
            self._record("Wi-Fi", host, "Wireless scanning requires Linux with iw tools", "info")
        return self.results


class LoRaWANModule(BaseModule):
    name = "lorawan"
    category = ModuleCategory.WIRELESS_IOT
    description = "LoRaWAN - Gateway detection (requires LoRa hardware)"
    default_ports = [1700]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"LoRaWAN Enumeration: {host}")
        for port in ports:
            # LoRaWAN Semtech UDP Forwarder - PUSH_DATA / PULL_DATA
            # Protocol version=2, random token, PULL_DATA(0x02), gateway EUI
            pull_data = struct.pack('>BHB', 0x02, 0x1234, 0x02)
            pull_data += b'\x00' * 8  # Gateway EUI
            resp = self._udp(host, port, pull_data)
            if resp and len(resp) >= 4:
                self._record("LoRaWAN Forwarder Response", host, hex_dump(resp), "success",
                             "Semtech UDP packet forwarder (port 1700)")
            # Check for web management
            status, hdrs, body = self._http(host, 80, "/")
            if status > 0 and any(k in body.lower() for k in ['lorawan', 'lora', 'gateway', 'chirpstack']):
                self._record("LoRaWAN web management", host, f"HTTP {status}", "success")
        return self.results


class ZWaveModule(BaseModule):
    name = "zwave"
    category = ModuleCategory.WIRELESS_IOT
    description = "Z-Wave - Node enumeration (requires Z-Wave USB stick)"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Z-Wave Detection")
        self._record("Z-Wave info", host,
                     "Z-Wave is 908MHz wireless. Requires USB stick (Aeotec Z-Stick, Zooz ZST10).",
                     "info")
        if platform.system() == "Linux":
            usb = self._os_cmd("ls /dev/ttyACM* 2>/dev/null")
            if usb and '/dev/' in usb:
                self._record("Potential Z-Wave adapters", host, usb, "info")
        return self.results



# -----------------------------------------------------------------------------
# 5.4  CLOUD / AI / CONTAINER PROTOCOL MODULES (8 modules)
# -----------------------------------------------------------------------------

class DockerModule(BaseModule):
    name = "docker"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "Docker - Native HTTP API: containers, images, networks, volumes, daemon info"
    default_ports = [2375, 2376]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Docker API Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 2376)
            endpoints = [
                ("/version", "Docker version, API version, OS, arch, kernel"),
                ("/info", "Containers, images, storage driver, runtime, security options"),
                ("/containers/json?all=true", "All containers: names, status, ports, image"),
                ("/images/json", "All images: repository, tags, size, created"),
                ("/networks", "Docker networks: bridge, overlay, host, custom"),
                ("/volumes", "Docker volumes: names, drivers, mount points"),
            ]
            for path, desc in endpoints:
                status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
                if status == 200 and body:
                    try:
                        data = json.loads(body)
                        summary = json.dumps(data, indent=2)[:500]
                    except json.JSONDecodeError:
                        summary = body[:500]
                    self._record(f"Docker {path}", host, summary, "success", desc)
                elif status == 403:
                    self._record(f"Docker {path}", host, "Access denied (TLS client cert required?)", "info")
                elif status > 0:
                    self._record(f"Docker {path}", host, f"HTTP {status}", "info")
                    break  # Probably not Docker API
        return self.results


class KubernetesModule(BaseModule):
    name = "kubernetes"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "Kubernetes - Native HTTPS API: version, namespaces, pods, services, nodes"
    default_ports = [6443, 8443, 443, 10250]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Kubernetes API Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port == 10250:
                # Kubelet API
                status, hdrs, body = self._http(host, port, "/pods", use_ssl=True)
                if status == 200:
                    self._record("Kubelet /pods", host, body[:500], "success",
                                 "Kubelet API exposed - lists all pods on this node")
                status, _, body = self._http(host, port, "/healthz", use_ssl=True)
                if status == 200:
                    self._record("Kubelet healthz", host, body[:200], "success")
                continue
            # K8s API server
            endpoints = [
                ("/version", "Kubernetes version, platform, build info"),
                ("/api/v1/namespaces", "All namespaces"),
                ("/api/v1/pods", "All pods across namespaces"),
                ("/api/v1/services", "All services"),
                ("/api/v1/nodes", "Cluster nodes"),
                ("/api/v1/secrets", "Secrets (should be denied)"),
                ("/apis", "Available API groups"),
            ]
            for path, desc in endpoints:
                status, hdrs, body = self._http(host, port, path, use_ssl=True)
                if status == 200:
                    try:
                        data = json.loads(body)
                        summary = json.dumps(data, indent=2)[:500]
                    except json.JSONDecodeError:
                        summary = body[:500]
                    self._record(f"K8s {path}", host, summary, "success", desc)
                elif status == 401:
                    self._record(f"K8s {path}", host, "Unauthorized (auth required)", "info")
                    break
                elif status == 403:
                    self._record(f"K8s {path}", host, "Forbidden (RBAC)", "info")
        return self.results


class AWSModule(BaseModule):
    name = "aws"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "AWS - Instance metadata (IMDSv1/v2), security credentials, IAM, user-data"
    default_ports = [80]

    def run(self, host, ports=None):
        print_subsection(f"AWS Metadata Enumeration: {host}")
        meta_host = "169.254.169.254"
        # IMDSv1 (no token)
        paths = [
            "/latest/meta-data/", "/latest/meta-data/ami-id",
            "/latest/meta-data/instance-id", "/latest/meta-data/instance-type",
            "/latest/meta-data/local-ipv4", "/latest/meta-data/public-ipv4",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/hostname", "/latest/meta-data/placement/availability-zone",
            "/latest/user-data", "/latest/dynamic/instance-identity/document",
        ]
        # Try IMDSv2 first (token-based)
        token = None
        try:
            status, hdrs, body = http_request("PUT",
                f"http://{meta_host}/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=2)
            if status == 200 and body:
                token = body.strip()
                self._record("AWS IMDSv2 Token", host, "Token acquired", "success")
        except Exception:
            pass
        for path in paths:
            headers = {"X-aws-ec2-metadata-token": token} if token else {}
            try:
                status, _, body = http_request("GET", f"http://{meta_host}{path}",
                                               headers=headers, timeout=2)
                if status == 200 and body:
                    self._record(f"AWS {path}", host, body[:500], "success")
            except Exception:
                break  # Not on AWS
        # Check if target host has AWS services exposed
        for svc_port in [80, 443]:
            status, hdrs, body = self._http(host, svc_port, "/", use_ssl=(svc_port==443))
            if status > 0:
                amz_headers = {k: v for k, v in hdrs.items() if 'amz' in k.lower() or 'aws' in k.lower()}
                if amz_headers:
                    self._record(f"AWS headers on {host}:{svc_port}", host,
                                 str(amz_headers), "success")
        return self.results


class GCPModule(BaseModule):
    name = "gcp"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "GCP - Instance metadata, service account, project info, network"
    default_ports = [80]

    def run(self, host, ports=None):
        print_subsection(f"GCP Metadata Enumeration: {host}")
        meta_host = "metadata.google.internal"
        base = f"http://{meta_host}/computeMetadata/v1/"
        headers = {"Metadata-Flavor": "Google"}
        paths = [
            "project/project-id", "project/numeric-project-id",
            "instance/name", "instance/id", "instance/zone",
            "instance/machine-type", "instance/hostname",
            "instance/network-interfaces/0/ip",
            "instance/service-accounts/default/email",
            "instance/service-accounts/default/token",
        ]
        for path in paths:
            try:
                status, _, body = http_request("GET", base + path,
                                               headers=headers, timeout=2)
                if status == 200 and body:
                    self._record(f"GCP {path}", host, body[:300], "success")
            except Exception:
                break
        return self.results


class AzureModule(BaseModule):
    name = "azure"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "Azure - IMDS metadata, managed identity, subscription, network info"
    default_ports = [80]

    def run(self, host, ports=None):
        print_subsection(f"Azure IMDS Enumeration: {host}")
        meta_host = "169.254.169.254"
        base = f"http://{meta_host}/metadata/instance"
        headers = {"Metadata": "true"}
        paths = [
            "?api-version=2021-02-01",
            "/compute?api-version=2021-02-01",
            "/network?api-version=2021-02-01",
        ]
        for path in paths:
            try:
                status, _, body = http_request("GET", base + path,
                                               headers=headers, timeout=2)
                if status == 200 and body:
                    self._record(f"Azure IMDS {path.split('?')[0]}", host,
                                 body[:500], "success")
            except Exception:
                break
        # Managed Identity token
        try:
            status, _, body = http_request("GET",
                f"http://{meta_host}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                headers=headers, timeout=2)
            if status == 200:
                self._record("Azure Managed Identity Token", host, body[:200], "warn")
        except Exception:
            pass
        return self.results


class OCIModule(BaseModule):
    name = "oci"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "Oracle Cloud (OCI) - Instance metadata, VNIC, identity"
    default_ports = [80]

    def run(self, host, ports=None):
        print_subsection(f"OCI Metadata Enumeration: {host}")
        meta_host = "169.254.169.254"
        paths = [
            "/opc/v2/instance/", "/opc/v2/instance/id",
            "/opc/v2/instance/displayName", "/opc/v2/instance/compartmentId",
            "/opc/v2/instance/region", "/opc/v2/instance/shape",
            "/opc/v2/vnics/",
        ]
        headers = {"Authorization": "Bearer Oracle"}
        for path in paths:
            try:
                status, _, body = http_request("GET", f"http://{meta_host}{path}",
                                               headers=headers, timeout=2)
                if status == 200 and body:
                    self._record(f"OCI {path}", host, body[:300], "success")
            except Exception:
                break
        return self.results


class MCPModule(BaseModule):
    name = "mcp"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "MCP (Model Context Protocol) - SSE/JSON-RPC endpoint, tool listing, server info"
    default_ports = [3000, 8080, 8000, 5000]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"MCP Server Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            # Try SSE endpoint
            for path in ['/sse', '/mcp', '/events', '/']:
                for use_ssl in [False, True]:
                    status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
                    if status == 200:
                        ct = hdrs.get('Content-Type', hdrs.get('content-type', ''))
                        if 'event-stream' in ct or 'json' in ct:
                            self._record(f"MCP endpoint {path} (port {port})", host,
                                         f"Content-Type: {ct}, Body: {body[:300]}", "success",
                                         "Model Context Protocol server")
                        elif body.strip():
                            self._record(f"HTTP {path} (port {port})", host,
                                         f"Status {status}: {body[:200]}", "info")
                        break
            # Try JSON-RPC initialize
            rpc_init = json.dumps({"jsonrpc": "2.0", "method": "initialize",
                                   "params": {"capabilities": {}}, "id": 1})
            status, hdrs, body = http_request("POST", f"http://{host}:{port}/",
                                              data=rpc_init,
                                              headers={"Content-Type": "application/json"},
                                              timeout=self.config.timeout)
            if status == 200 and body:
                try:
                    resp_data = json.loads(body)
                    if 'result' in resp_data:
                        self._record("MCP JSON-RPC initialize", host,
                                     json.dumps(resp_data['result'], indent=2)[:500], "success")
                except json.JSONDecodeError:
                    pass
        return self.results


class APIModule(BaseModule):
    name = "api"
    category = ModuleCategory.CLOUD_AI_PROTOCOL
    description = "REST/GraphQL/gRPC API - Endpoint discovery, schema, health, versioning"
    default_ports = [80, 443, 8080, 8443, 3000, 5000]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"API Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = port in [443, 8443]
            # Common API discovery paths
            api_paths = [
                "/api", "/api/v1", "/api/v2", "/v1", "/v2",
                "/swagger.json", "/openapi.json", "/api-docs",
                "/swagger-ui.html", "/docs", "/redoc",
                "/graphql", "/.well-known/openid-configuration",
                "/health", "/healthz", "/ready", "/status",
                "/metrics", "/actuator", "/actuator/health",
            ]
            found = False
            for path in api_paths:
                status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
                if status == 200 and body.strip():
                    ct = hdrs.get('Content-Type', hdrs.get('content-type', ''))
                    if 'json' in ct or 'yaml' in ct or 'xml' in ct or body.strip().startswith('{'):
                        self._record(f"API {path} (port {port})", host, body[:400], "success")
                        found = True
                elif status in [301, 302, 401, 403]:
                    self._record(f"API {path} (port {port})", host,
                                 f"HTTP {status} - endpoint exists", "info")
                    found = True
            # GraphQL introspection
            gql_query = json.dumps({"query": "{__schema{types{name}}}"})
            status, hdrs, body = http_request("POST",
                f"{'https' if use_ssl else 'http'}://{host}:{port}/graphql",
                data=gql_query, headers={"Content-Type": "application/json"},
                timeout=self.config.timeout)
            if status == 200 and '__schema' in body:
                self._record("GraphQL introspection", host, body[:500], "success",
                             "GraphQL schema exposed")
            if not found:
                self._record(f"No API endpoints found ({port})", host, "", "info")
        return self.results



# -----------------------------------------------------------------------------
# 5.5  OS CONFIGURATION MODULES (4 modules) - subprocess to OS-native commands
# -----------------------------------------------------------------------------

class WindowsConfigModule(BaseModule):
    name = "windows_config"
    category = ModuleCategory.OS_CONFIG
    description = "Windows - Users, groups, shares, services, registry, firewall, patches, scheduled tasks"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Windows Configuration Enumeration")
        if platform.system() != "Windows":
            self._record("Windows config", host, "Not a Windows system - skipping", "skipped")
            return self.results
        # Format: (name, command, timeout_seconds) - slow commands get 60s+
        checks = [
            ("Hostname", "hostname", 10),
            ("OS Version", "ver", 10),
            ("System Info", "systeminfo", 120),
            ("IP Configuration", "ipconfig /all", 15),
            ("Local Users", "net user", 15),
            ("Local Groups", "net localgroup", 15),
            ("Administrators", "net localgroup administrators", 15),
            ("Domain Info", "net config workstation", 15),
            ("Shared Folders", "net share", 15),
            ("Running Services", "sc query state= all", 30),
            ("Running Processes", "tasklist /v", 30),
            ("Listening Ports", "netstat -an", 15),
            ("Established Connections", 'netstat -an | findstr "ESTABLISHED"', 15),
            ("Firewall Status", "netsh advfirewall show allprofiles state", 15),
            ("Firewall Rules", "netsh advfirewall firewall show rule name=all", 30),
            ("Installed Programs (registry)", 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s /v DisplayName 2>nul | findstr "DisplayName"', 30),
            ("Installed Hotfixes", "wmic qfe list brief", 60),
            ("Scheduled Tasks", "schtasks /query /fo list", 60),
            ("Startup Programs", "wmic startup list brief", 30),
            ("Environment Variables", "set", 10),
            ("Audit Policy", "auditpol /get /category:*", 15),
            ("Security Policy", "secedit /export /cfg %temp%\\secpol.cfg && type %temp%\\secpol.cfg", 30),
            ("Registry AutoRun", "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 10),
            ("Registry AutoRun (User)", "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 10),
            ("RDP Status", 'reg query "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', 10),
            ("WinRM Status", "winrm get winrm/config", 15),
            ("PowerShell Version", "powershell -NoProfile -c $PSVersionTable.PSVersion", 15),
            ("Defender Status", "powershell -NoProfile -c Get-MpComputerStatus", 30),
            ("BitLocker Status", "manage-bde -status", 15),
            ("Local Security Settings", "net accounts", 10),
            ("Password Policy", "net accounts", 10),
            ("Drive Info", "wmic logicaldisk get caption,description,filesystem,freespace,size", 30),
            ("USB Devices", "wmic path Win32_USBControllerDevice get Dependent", 30),
            ("BIOS Info", "wmic bios get serialnumber,manufacturer,smbiosbiosversion", 15),
            ("Network Adapters", "wmic nic get name,macaddress,speed,netconnectionstatus", 15),
        ]
        for name, cmd, cmd_timeout in checks:
            if not self.config.privileged and any(k in cmd for k in ['secedit', 'auditpol', 'manage-bde']):
                self._record(name, host, "Requires elevated privileges", "skipped")
                continue
            result = run_os_cmd(cmd, timeout=cmd_timeout)
            self._record(name, host, result[:1000], "success" if "(no output)" not in result else "info")
        return self.results


class LinuxConfigModule(BaseModule):
    name = "linux_config"
    category = ModuleCategory.OS_CONFIG
    description = "Linux - Users, groups, services, packages, firewall, cron, kernel, mounts, processes"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Linux Configuration Enumeration")
        if platform.system() != "Linux":
            self._record("Linux config", host, "Not a Linux system - skipping", "skipped")
            return self.results
        checks = [
            ("Hostname", "hostname -f"),
            ("OS Release", "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null"),
            ("Kernel Version", "uname -a"),
            ("Uptime", "uptime"),
            ("CPU Info", "lscpu 2>/dev/null || cat /proc/cpuinfo | head -30"),
            ("Memory Info", "free -h"),
            ("Disk Usage", "df -h"),
            ("Block Devices", "lsblk 2>/dev/null"),
            ("Mount Points", "mount | grep -v cgroup"),
            ("IP Addresses", "ip addr show 2>/dev/null || ifconfig"),
            ("Routing Table", "ip route show 2>/dev/null || route -n"),
            ("ARP Table", "ip neigh show 2>/dev/null || arp -an"),
            ("DNS Config", "cat /etc/resolv.conf"),
            ("Listening Ports", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
            ("Established Connections", "ss -tnp 2>/dev/null | head -30"),
            ("Local Users", "cat /etc/passwd"),
            ("Local Groups", "cat /etc/group"),
            ("Sudo Users", "getent group sudo wheel 2>/dev/null"),
            ("Shadow (privileged)", "cat /etc/shadow 2>/dev/null || echo 'Permission denied'"),
            ("SSH Config", "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'"),
            ("SSH Authorized Keys", "find /home -name authorized_keys -exec echo {} \\; -exec cat {} \\; 2>/dev/null"),
            ("Running Processes", "ps auxf --cols 200 2>/dev/null | head -50"),
            ("Systemd Services", "systemctl list-units --type=service --state=running 2>/dev/null | head -30"),
            ("Enabled Services", "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30"),
            ("Cron Jobs (system)", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null"),
            ("Cron Jobs (user)", "crontab -l 2>/dev/null || echo 'No user crontab'"),
            ("Installed Packages (dpkg)", "dpkg -l 2>/dev/null | tail -20"),
            ("Installed Packages (rpm)", "rpm -qa --last 2>/dev/null | head -20"),
            ("Firewall (iptables)", "iptables -L -n 2>/dev/null || echo 'Requires root'"),
            ("Firewall (nftables)", "nft list ruleset 2>/dev/null || echo 'Requires root or not nftables'"),
            ("Firewall (ufw)", "ufw status verbose 2>/dev/null"),
            ("SELinux Status", "getenforce 2>/dev/null || echo 'SELinux not installed'"),
            ("AppArmor Status", "aa-status 2>/dev/null || echo 'AppArmor not installed'"),
            ("Kernel Modules", "lsmod | head -20"),
            ("Kernel Parameters", "sysctl -a 2>/dev/null | grep -E 'forward|syn|exec|core_pattern|randomize' | head -20"),
            ("SUID Binaries", "find / -perm -4000 -type f 2>/dev/null | head -20"),
            ("Writable Directories", "find / -writable -type d 2>/dev/null | grep -v proc | head -10"),
            ("Docker Socket", "ls -la /var/run/docker.sock 2>/dev/null"),
            ("Containers Running", "cat /proc/1/cgroup 2>/dev/null | head -5"),
            ("Environment Variables", "env"),
            ("Last Logins", "last -20 2>/dev/null"),
            ("Failed Logins", "lastb -5 2>/dev/null || echo 'Requires root'"),
        ]
        for name, cmd in checks:
            if not self.config.privileged and any(k in name.lower() for k in ['shadow', 'firewall', 'suid']):
                result = self._os_cmd(cmd)
                status = "success" if result and "(no output)" not in result and "denied" not in result.lower() else "info"
            else:
                result = self._os_cmd(cmd)
                status = "success" if result and "(no output)" not in result else "info"
            self._record(name, host, result[:1000], status)
        return self.results


class MacOSConfigModule(BaseModule):
    name = "macos_config"
    category = ModuleCategory.OS_CONFIG
    description = "macOS - System info, users, services, firewall, Gatekeeper, SIP, network"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"macOS Configuration Enumeration")
        if platform.system() != "Darwin":
            self._record("macOS config", host, "Not a macOS system - skipping", "skipped")
            return self.results
        checks = [
            ("System Info", "sw_vers"),
            ("Hostname", "hostname"),
            ("Hardware", "system_profiler SPHardwareDataType 2>/dev/null"),
            ("Kernel", "uname -a"),
            ("Users", "dscl . list /Users | grep -v '^_'"),
            ("Admin Users", "dscl . read /Groups/admin GroupMembership"),
            ("Network", "ifconfig"),
            ("Listening Ports", "lsof -i -P -n | grep LISTEN"),
            ("Firewall Status", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
            ("SIP Status", "csrutil status"),
            ("Gatekeeper", "spctl --status"),
            ("FileVault", "fdesetup status"),
            ("Running Services", "launchctl list | head -30"),
            ("Installed Apps", "ls /Applications/"),
            ("Homebrew Packages", "brew list 2>/dev/null || echo 'Homebrew not installed'"),
        ]
        for name, cmd in checks:
            result = self._os_cmd(cmd)
            self._record(name, host, result[:1000],
                         "success" if "(no output)" not in result else "info")
        return self.results


class UnixConfigModule(BaseModule):
    name = "unix_config"
    category = ModuleCategory.OS_CONFIG
    description = "Unix (Solaris/AIX/HP-UX/FreeBSD) - System info, users, services, patches"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Unix Configuration Enumeration")
        os_name = platform.system()
        if os_name not in ("SunOS", "AIX", "HP-UX", "FreeBSD", "OpenBSD", "NetBSD"):
            self._record("Unix config", host, f"OS '{os_name}' - trying generic Unix checks", "info")
        checks = [
            ("Hostname", "hostname"),
            ("OS Info", "uname -a"),
            ("Users", "cat /etc/passwd"),
            ("Groups", "cat /etc/group"),
            ("Network", "ifconfig -a 2>/dev/null || ip addr 2>/dev/null"),
            ("Listening Ports", "netstat -an 2>/dev/null | grep LISTEN | head -20"),
            ("Processes", "ps -ef | head -30"),
            ("Disk", "df -k"),
            ("Mounts", "mount"),
            ("Kernel Params", "sysctl -a 2>/dev/null | head -20"),
        ]
        # OS-specific additions
        if os_name == "SunOS":
            checks.extend([("Solaris Patches", "patchadd -p 2>/dev/null | tail -10"),
                           ("Solaris Packages", "pkginfo | head -20"),
                           ("Solaris Zones", "zoneadm list -cv 2>/dev/null")])
        elif os_name == "AIX":
            checks.extend([("AIX Level", "oslevel -s"),
                           ("AIX Packages", "lslpp -l | head -20")])
        for name, cmd in checks:
            result = self._os_cmd(cmd)
            self._record(name, host, result[:1000],
                         "success" if "(no output)" not in result else "info")
        return self.results


# -----------------------------------------------------------------------------
# 5.6  RTOS CONFIGURATION MODULES (6 modules)
# -----------------------------------------------------------------------------

class VxWorksConfigModule(BaseModule):
    name = "vxworks_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "VxWorks - Detect via banners, debug shell, WDB agent (port 17185)"
    default_ports = [21, 23, 80, 17185]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"VxWorks RTOS Enumeration: {host}")
        # WDB Agent probe (UDP 17185)
        wdb_connect = struct.pack('>IIIIIIIIII', 0x00000000, 0x00000002, 0x00000000,
                                   0x00000001, 0x00000001, 0x00000000,
                                   0x00000000, 0x00000000, 0x00000000, 0x00000000)
        resp = self._udp(host, 17185, wdb_connect)
        if resp:
            self._record("VxWorks WDB Agent", host, hex_dump(resp), "success",
                         "WDB debug agent exposed! Full memory read/write possible.")
        # Telnet banner check
        if is_port_open(host, 23, self.config.timeout):
            resp = self._tcp(host, 23, None)
            if resp and (b'vxworks' in resp.lower() or b'->') in resp:
                self._record("VxWorks shell (telnet)", host, safe_decode(resp), "success",
                             "VxWorks debug shell - C interpreter access")
        # FTP banner
        if is_port_open(host, 21, self.config.timeout):
            resp = self._tcp(host, 21, None)
            if resp and b'vxworks' in resp.lower():
                self._record("VxWorks FTP", host, safe_decode(resp), "success")
        # HTTP banner
        status, hdrs, body = self._http(host, 80, "/")
        if status > 0:
            server = hdrs.get('Server', '')
            if 'vxworks' in server.lower() or 'vxworks' in body.lower() or 'wind' in server.lower():
                self._record("VxWorks HTTP", host, f"Server: {server}", "success")
        return self.results


class QNXConfigModule(BaseModule):
    name = "qnx_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "QNX Neutrino - Detect via QCONN debug service, banners, Photon web server"
    default_ports = [8000, 23, 22, 80]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"QNX RTOS Enumeration: {host}")
        # QCONN debug service (TCP 8000)
        if is_port_open(host, 8000, self.config.timeout):
            resp = self._tcp(host, 8000, b"info\n")
            if resp:
                self._record("QNX QCONN", host, safe_decode(resp), "success",
                             "QNX debug service - process listing, memory access")
        # Banner checks
        for port in [22, 23]:
            if is_port_open(host, port, self.config.timeout):
                resp = self._tcp(host, port, None)
                if resp and (b'qnx' in resp.lower() or b'neutrino' in resp.lower()):
                    self._record(f"QNX banner (port {port})", host, safe_decode(resp), "success")
        # HTTP
        status, hdrs, body = self._http(host, 80, "/")
        if status > 0 and ('qnx' in body.lower() or 'photon' in hdrs.get('Server', '').lower()):
            self._record("QNX HTTP", host, f"Server: {hdrs.get('Server', '')}", "success")
        return self.results


class NucleusConfigModule(BaseModule):
    name = "nucleus_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "Nucleus RTOS - Detect via banners, HTTP fingerprint"
    default_ports = [80, 21, 23]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Nucleus RTOS Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port == 80:
                status, hdrs, body = self._http(host, 80, "/")
                if status > 0:
                    server = hdrs.get('Server', '')
                    if 'nucleus' in server.lower() or 'nucleus' in body.lower():
                        self._record("Nucleus RTOS HTTP", host, f"Server: {server}", "success")
            else:
                resp = self._tcp(host, port, None)
                if resp and b'nucleus' in resp.lower():
                    self._record(f"Nucleus banner (port {port})", host, safe_decode(resp), "success")
        return self.results


class WindowsIoTConfigModule(BaseModule):
    name = "windows_iot_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "Windows IoT Core/Enterprise - Device portal, SSH, system info"
    default_ports = [8080, 22, 5985]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Windows IoT Enumeration: {host}")
        # Windows Device Portal (WDP) - HTTP 8080
        if is_port_open(host, 8080, self.config.timeout):
            status, hdrs, body = self._http(host, 8080, "/api/os/info")
            if status == 200 and body:
                self._record("Windows IoT Device Portal", host, body[:500], "success",
                             "Windows Device Portal API - OS info, processes, network")
            status, _, body = self._http(host, 8080, "/api/networking/ipconfig")
            if status == 200:
                self._record("Windows IoT Network Config", host, body[:500], "success")
        # SSH
        if is_port_open(host, 22, self.config.timeout):
            resp = self._tcp(host, 22, None)
            if resp and (b'windows' in resp.lower() or b'iot' in resp.lower()):
                self._record("Windows IoT SSH", host, safe_decode(resp), "success")
        # WinRM
        if is_port_open(host, 5985, self.config.timeout):
            self._record("WinRM port open", host, "Windows Remote Management available", "info")
        return self.results


class IntegrityConfigModule(BaseModule):
    name = "integrity_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "Green Hills INTEGRITY - Detect via banners, HTTP fingerprint"
    default_ports = [80, 23]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"INTEGRITY RTOS Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port == 80:
                status, hdrs, body = self._http(host, 80, "/")
                if status > 0:
                    server = hdrs.get('Server', '')
                    if 'integrity' in server.lower() or 'green hills' in body.lower():
                        self._record("INTEGRITY RTOS HTTP", host, f"Server: {server}", "success")
            else:
                resp = self._tcp(host, port, None)
                if resp and (b'integrity' in resp.lower() or b'green hills' in resp.lower()):
                    self._record(f"INTEGRITY banner ({port})", host, safe_decode(resp), "success")
        return self.results


class FreeRTOSConfigModule(BaseModule):
    name = "freertos_config"
    category = ModuleCategory.RTOS_CONFIG
    description = "FreeRTOS/Amazon FreeRTOS - Detect via MQTT/HTTP, task info"
    default_ports = [80, 1883, 8883]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"FreeRTOS Enumeration: {host}")
        for port in ports:
            if not is_port_open(host, port, self.config.timeout):
                continue
            if port in [1883, 8883]:
                # MQTT connection - FreeRTOS devices often use MQTT
                use_ssl = (port == 8883)
                try:
                    if use_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                        raw = socket.create_connection((host, port), timeout=self.config.timeout)
                        s = ctx.wrap_socket(raw, server_hostname=host)
                    else:
                        s = tcp_connect(host, port, self.config.timeout)
                    if s:
                        connect_pkt = bytes([0x10, 0x10, 0x00, 0x04]) + b'MQTT' + bytes([0x04, 0x02, 0x00, 0x3C, 0x00, 0x04]) + b'enum'
                        s.sendall(connect_pkt)
                        resp = s.recv(1024)
                        if resp and resp[0] == 0x20:
                            self._record(f"MQTT broker (port {port})", host,
                                         "MQTT service - possible FreeRTOS device", "info")
                        s.close()
                except Exception:
                    pass
            elif port == 80:
                status, hdrs, body = self._http(host, 80, "/")
                if status > 0 and ('freertos' in body.lower() or 'amazon' in body.lower()):
                    self._record("FreeRTOS HTTP", host, body[:300], "success")
        return self.results



# -----------------------------------------------------------------------------
# 5.7  DEVICE CONFIGURATION MODULES (5 modules)
# -----------------------------------------------------------------------------

class NetworkDeviceModule(BaseModule):
    name = "network_device"
    category = ModuleCategory.DEVICE_CONFIG
    description = "Network devices (routers/switches/firewalls) - SNMP, HTTP, SSH, banner fingerprint"
    default_ports = [22, 23, 80, 443, 161]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Network Device Enumeration: {host}")
        # SSH banner for device type
        if is_port_open(host, 22, self.config.timeout):
            resp = self._tcp(host, 22, None)
            if resp:
                banner = safe_decode(resp).strip()
                self._record("Network device SSH banner", host, banner, "success")
                for vendor in ['Cisco', 'Juniper', 'Arista', 'Palo Alto', 'Fortinet', 'MikroTik',
                               'HP', 'Dell', 'Aruba', 'Brocade', 'Huawei', 'Ubiquiti', 'Extreme']:
                    if vendor.lower() in banner.lower():
                        self._record(f"Vendor: {vendor}", host, banner, "success")
                        break
        # Telnet banner
        if is_port_open(host, 23, self.config.timeout):
            resp = self._tcp(host, 23, None)
            if resp:
                self._record("Network device telnet banner", host, safe_decode(resp)[:300], "success")
        # HTTP management
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                server = hdrs.get('Server', '')
                self._record(f"Web management ({port})", host,
                             f"HTTP {status}, Server: {server}", "success")
                # Vendor-specific paths
                for path, desc in [("/login", "Login page"), ("/webui", "Web UI"),
                                    ("/api/v1/system", "REST API"), ("/rest/system/identity", "MikroTik")]:
                    s2, _, b2 = self._http(host, port, path, use_ssl=use_ssl)
                    if s2 == 200:
                        self._record(f"Device {path}", host, b2[:200], "success")
        # SNMP sysDescr for device identification
        snmp_mod = SNMPModule(self.config, self.target)
        resp = snmp_mod._snmp_get(host, 161, 'public', '1.3.6.1.2.1.1.1.0')
        if resp:
            parsed = snmp_mod._parse_snmp_response(resp)
            if parsed:
                self._record("SNMP sysDescr", host, safe_decode(parsed[1]), "success")
        return self.results


class PLCModule(BaseModule):
    name = "plc_config"
    category = ModuleCategory.DEVICE_CONFIG
    description = "PLC multi-vendor - Siemens, AB, Schneider, Omron, Mitsubishi, GE, ABB, Honeywell"
    default_ports = [80, 443, 102, 502, 44818, 9600, 5007, 18245, 1502, 20547]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"PLC Configuration Enumeration: {host}")
        # HTTP management interfaces
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                server = hdrs.get('Server', '')
                combined = (server + body).lower()
                vendors = {'siemens': 'Siemens', 'allen-bradley': 'Allen-Bradley', 'rockwell': 'Rockwell',
                           'schneider': 'Schneider', 'modicon': 'Schneider', 'omron': 'Omron',
                           'mitsubishi': 'Mitsubishi', 'melsec': 'Mitsubishi', 'ge fanuc': 'GE',
                           'emerson': 'Emerson', 'abb': 'ABB', 'honeywell': 'Honeywell',
                           'phoenix contact': 'Phoenix Contact', 'wago': 'WAGO',
                           'beckhoff': 'Beckhoff', 'codesys': 'CODESYS'}
                for key, name in vendors.items():
                    if key in combined:
                        self._record(f"PLC Vendor: {name}", host,
                                     f"HTTP {status}, Server: {server}", "success")
                        break
        # Protocol-based identification
        probes = [
            (102, "S7comm/MMS", bytes([0x03,0x00,0x00,0x16,0x11,0xE0,0x00,0x00,0x00,0x01,0x00,
                                       0xC1,0x02,0x01,0x00,0xC2,0x02,0x01,0x02,0xC0,0x01,0x0A])),
            (502, "Modbus", struct.pack('>HHHBB', 1, 0, 2, 0, 0x11)),
            (44818, "EtherNet/IP", struct.pack('<HHIIQI', 0x0063, 0, 0, 0, 0, 0)),
        ]
        for port, proto, payload in probes:
            if is_port_open(host, port, self.config.timeout):
                resp = self._tcp(host, port, payload)
                if resp:
                    self._record(f"PLC {proto} (port {port})", host, hex_dump(resp[:60]), "success")
        return self.results


class HMISCADAModule(BaseModule):
    name = "hmi_scada"
    category = ModuleCategory.DEVICE_CONFIG
    description = "HMI/SCADA - Web interface fingerprint, common management paths, TLS cert"
    default_ports = [80, 443, 8080, 8443, 502, 102]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"HMI/SCADA Enumeration: {host}")
        hmi_indicators = ['scada', 'hmi', 'wonderware', 'ignition', 'factorytalk', 'citect',
                          'wincc', 'intouch', 'genesis', 'indusoft', 'vijeo', 'simatic',
                          'cimplicity', 'ifix', 'iconics', 'vtscada', 'webaccess']
        for port in [80, 443, 8080, 8443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = port in [443, 8443]
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                combined = (hdrs.get('Server', '') + body).lower()
                for indicator in hmi_indicators:
                    if indicator in combined:
                        self._record(f"HMI/SCADA detected: {indicator}", host,
                                     f"HTTP {status} on port {port}", "success")
                        break
                # Check common HMI paths
                for path in ['/login', '/main', '/dashboard', '/system', '/config', '/api/status']:
                    s2, h2, b2 = self._http(host, port, path, use_ssl=use_ssl)
                    if s2 == 200 and b2.strip():
                        self._record(f"HMI path {path}", host, b2[:200], "info")
            if use_ssl:
                cert = self._ssl_info(host, port)
                if cert and cert['cert']:
                    self._record(f"HMI TLS cert ({port})", host, str(cert['cert'].get('subject', '')), "success")
        return self.results


class GatewayModule(BaseModule):
    name = "gateway_config"
    category = ModuleCategory.DEVICE_CONFIG
    description = "Protocol gateways - Moxa, Digi, HMS, Lantronix, SEL, serial converters"
    default_ports = [80, 443, 4001, 4800, 950, 9999, 10001]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Protocol Gateway Enumeration: {host}")
        gw_indicators = ['moxa', 'nport', 'digi', 'portserver', 'anybus', 'hms',
                         'lantronix', 'sel', 'comtrol', 'perle', 'advantech']
        # Web management
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                combined = (hdrs.get('Server', '') + body).lower()
                for gw in gw_indicators:
                    if gw in combined:
                        self._record(f"Gateway vendor: {gw}", host,
                                     f"HTTP {status}, Server: {hdrs.get('Server', '')}", "success")
                        break
        # Serial data ports
        for port in [4001, 950, 9999, 10001]:
            if is_port_open(host, port, self.config.timeout):
                self._record(f"Serial gateway port {port} open", host,
                             "Potential serial-to-TCP bridge", "info")
                resp = self._tcp(host, port, b'\r\n')
                if resp:
                    self._record(f"Gateway data port {port}", host, hex_dump(resp), "success")
        return self.results


class RadioModule(BaseModule):
    name = "radio_config"
    category = ModuleCategory.DEVICE_CONFIG
    description = "Industrial radios - MDS, GE, Cisco, Motorola, Cambium, Ubiquiti wireless bridges"
    default_ports = [80, 443, 22, 23, 161]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Industrial Radio Enumeration: {host}")
        radio_indicators = ['mds', 'orbit', 'ge-mds', 'freewave', 'rajant', 'cambium',
                            'ubiquiti', 'airmax', 'motorola', 'canopy', 'mikrotik']
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            status, hdrs, body = self._http(host, port, "/", use_ssl=use_ssl)
            if status > 0:
                combined = (hdrs.get('Server', '') + body).lower()
                for radio in radio_indicators:
                    if radio in combined:
                        self._record(f"Radio vendor: {radio}", host,
                                     f"HTTP {status}", "success")
                        break
                title = re.search(r'<title>(.*?)</title>', body, re.I)
                if title:
                    self._record(f"Radio web title ({port})", host, title.group(1).strip(), "info")
        # SNMP for radio identification
        snmp_mod = SNMPModule(self.config, self.target)
        resp = snmp_mod._snmp_get(host, 161, 'public', '1.3.6.1.2.1.1.1.0')
        if resp:
            parsed = snmp_mod._parse_snmp_response(resp)
            if parsed:
                self._record("Radio SNMP sysDescr", host, safe_decode(parsed[1]), "success")
        return self.results


# -----------------------------------------------------------------------------
# 5.8  ATTACK SURFACE MODULE
# -----------------------------------------------------------------------------

class AttackSurfaceModule(BaseModule):
    name = "attack_surface"
    category = ModuleCategory.ATTACK_SURFACE
    description = "Common attack surface checks: default ports, services, credentials, exposure"
    default_ports = list(range(1, 1024)) + [1433, 1521, 1883, 2049, 2375, 2376, 3306, 3389,
                    4840, 5432, 5672, 5900, 5984, 6379, 6443, 8080, 8443, 8883, 9090,
                    9200, 9600, 11211, 27017, 44818, 47808, 50000, 61616]

    def run(self, host, ports=None):
        print_subsection(f"Attack Surface Enumeration: {host}")
        # 1. Port scan (top ports)
        scan_ports = [21, 22, 23, 25, 53, 80, 102, 110, 111, 135, 139, 143, 161, 389, 443,
                      445, 502, 636, 993, 995, 1433, 1502, 1521, 1883, 1911, 2049, 2222,
                      2375, 2404, 3306, 3389, 3671, 4000, 4840, 4911, 5007, 5060, 5094,
                      5432, 5672, 5683, 5900, 6379, 6443, 7547, 8080, 8443, 8883,
                      9090, 9200, 9600, 10250, 11211, 18245, 20000, 20547, 27017,
                      34964, 44818, 47808, 50000, 61414, 61616]
        open_ports = []
        self._record("Port Scan Starting", host, f"Scanning {len(scan_ports)} common ports", "info")
        for p in scan_ports:
            if is_port_open(host, p, 1):
                open_ports.append(p)
        if open_ports:
            self._record("Open Ports", host, f"{len(open_ports)} open: {open_ports}", "success")
        # 2. Service identification on open ports
        well_known = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                      80: "HTTP", 102: "S7comm/MMS", 110: "POP3", 111: "RPCbind",
                      135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
                      389: "LDAP", 443: "HTTPS", 445: "SMB", 502: "Modbus",
                      636: "LDAPS", 1433: "MSSQL", 1502: "TriStation",
                      1521: "Oracle", 1883: "MQTT", 1911: "Fox",
                      2049: "NFS", 2375: "Docker", 2404: "IEC 104",
                      3306: "MySQL", 3389: "RDP", 3671: "KNX",
                      4840: "OPC UA", 5432: "PostgreSQL", 5672: "AMQP",
                      5683: "CoAP", 5900: "VNC", 6379: "Redis",
                      6443: "Kubernetes", 8080: "HTTP-Alt", 8883: "MQTT-TLS",
                      9200: "Elasticsearch", 9600: "FINS", 11211: "Memcached",
                      18245: "GE SRTP", 20000: "DNP3", 27017: "MongoDB",
                      44818: "EtherNet/IP", 47808: "BACnet"}
        for p in open_ports:
            if p in well_known:
                self._record(f"Service: {well_known[p]}", host, f"Port {p}", "info")
        # 3. High-risk service checks
        high_risk = [p for p in open_ports if p in [23, 21, 502, 2375, 161, 5900, 6379, 11211, 27017, 9200]]
        if high_risk:
            self._record("High-Risk Services", host,
                         f"Potentially insecure: {high_risk}", "warn",
                         "These services often lack authentication by default")
        # 4. Default credential ports (services known for default creds)
        default_cred_ports = {23: "Telnet", 80: "HTTP", 443: "HTTPS", 161: "SNMP (public)",
                              502: "Modbus (no auth)", 1911: "Fox (no auth)", 5900: "VNC",
                              47808: "BACnet (no auth)", 2404: "IEC 104 (no auth)"}
        for p in open_ports:
            if p in default_cred_ports:
                self._record(f"Default credential risk: {default_cred_ports[p]}", host,
                             f"Port {p} - verify authentication", "warn")
        # 5. OS fingerprint from banners
        for p in [22, 23, 21, 80]:
            if p not in open_ports:
                continue
            if p in [22, 23, 21]:
                resp = self._tcp(host, p, None)
            else:
                _, hdrs, body = self._http(host, 80, "/")
                resp = (hdrs.get('Server', '') + body[:200]).encode() if hdrs else None
            if resp:
                banner = safe_decode(resp)[:200]
                self._record(f"Banner (port {p})", host, banner, "info")
        return self.results


# -----------------------------------------------------------------------------
# 5.9  INTERFACE ENUMERATION MODULE
# -----------------------------------------------------------------------------

class InterfaceEnumModule(BaseModule):
    name = "interfaces"
    category = ModuleCategory.INTERFACE_ENUM
    description = "Local interface enumeration - Ethernet, serial, USB, wireless, VLAN, bridges, VPN"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Interface Enumeration (local)")
        os_type = platform.system()
        if os_type == "Linux":
            checks = [
                ("Network Interfaces", "ip -d link show"),
                ("IP Addresses", "ip -4 addr show"),
                ("IPv6 Addresses", "ip -6 addr show"),
                ("Routing Table", "ip route show"),
                ("ARP/Neighbor Table", "ip neigh show"),
                ("VLANs", "cat /proc/net/vlan/config 2>/dev/null || echo 'No 802.1Q VLANs'"),
                ("Bridge Interfaces", "bridge link show 2>/dev/null || echo 'No bridges'"),
                ("Bond Interfaces", "cat /proc/net/bonding/bond* 2>/dev/null || echo 'No bonds'"),
                ("Serial Ports", "ls -la /dev/ttyS* /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || echo 'None found'"),
                ("USB Devices", "lsusb 2>/dev/null || echo 'lsusb not available'"),
                ("PCI Devices (network)", "lspci 2>/dev/null | grep -iE 'net|eth|wifi|wireless' || echo 'lspci not available'"),
                ("Wireless Interfaces", "ls /sys/class/net/*/wireless 2>/dev/null && echo 'Wireless found' || echo 'No wireless'"),
                ("CAN Interfaces", "ip link show type can 2>/dev/null || echo 'No CAN interfaces'"),
                ("Docker Networks", "ls /sys/class/net/ 2>/dev/null | grep -E 'docker|veth|br-'"),
                ("VPN Tunnels", "ip link show type tun 2>/dev/null; ip link show type gre 2>/dev/null"),
                ("Listening Sockets", "ss -tlnp 2>/dev/null | head -20"),
            ]
        elif os_type == "Windows":
            checks = [
                ("Network Adapters", "ipconfig /all"),
                ("Routing Table", "route print"),
                ("ARP Table", "arp -a"),
                ("Serial Ports", "mode"),
                ("USB Devices", "wmic path Win32_USBHub get DeviceID,Description"),
            ]
        elif os_type == "Darwin":
            checks = [
                ("Network Interfaces", "ifconfig"),
                ("Routing Table", "netstat -rn"),
                ("Serial Ports", "ls /dev/tty.* /dev/cu.* 2>/dev/null"),
            ]
        else:
            checks = [("Interfaces", "ifconfig -a 2>/dev/null || ip addr 2>/dev/null")]
        for name, cmd in checks:
            result = self._os_cmd(cmd)
            self._record(name, host, result[:1000],
                         "success" if result and "(no output)" not in result else "info")
        return self.results



# ===============================================================================
# SECTION 6: MODULE REGISTRY
# ===============================================================================



# =============================================================================
# 5.10  COMPLIANCE DATABASE (62443-3-3, 4-2, PLC Top 20)
# =============================================================================

# Compliance severity levels for color-coded output
COMPLIANCE_CRITICAL = "CRITICAL"  # RED - Must-fix, blocks certification
COMPLIANCE_HIGH = "HIGH"          # MAGENTA - Significant gap
COMPLIANCE_MEDIUM = "MEDIUM"      # YELLOW - Notable weakness
COMPLIANCE_LOW = "LOW"            # CYAN - Minor finding
COMPLIANCE_PASS = "PASS"          # GREEN - Meets requirement

# Requirements database: maps detectable conditions to standard requirements
COMPLIANCE_DB = {
    # FR1 - Identification and Authentication
    "no_auth": {
        "reqs": ["SR 1.1", "SR 1.2", "EDR 1.1", "EDR 1.2", "HDR 1.1", "SAR 1.1"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "No authentication required - violates IAC requirements",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "default_creds": {
        "reqs": ["SR 1.5", "SR 1.7", "HDR 1.7", "PLC-01"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "Default/weak credentials accepted",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "anonymous_access": {
        "reqs": ["SR 1.1", "SR 1.2", "SR 1.13", "NDR 1.13"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "Anonymous/unauthenticated access allowed",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "snmp_public": {
        "reqs": ["SR 1.5", "SR 1.7", "EDR 1.2", "NDR 1.6"],
        "severity": COMPLIANCE_HIGH,
        "desc": "SNMP default community string 'public' accepted",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "no_encryption": {
        "reqs": ["SR 4.1", "SR 4.3", "NDR 3.1", "HDR 4.1"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Unencrypted protocol in use - data confidentiality gap",
        "fr": "FR4 - Data Confidentiality"
    },
    "weak_tls": {
        "reqs": ["SR 4.3", "SR 1.8", "SR 1.9"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "Weak TLS version or cipher suite",
        "fr": "FR4 - Data Confidentiality"
    },
    "missing_security_headers": {
        "reqs": ["SR 3.5", "SR 3.8", "SAR 3.5", "SAR 3.8"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "Missing HTTP security headers (XSS, CSRF, clickjacking)",
        "fr": "FR3 - System Integrity"
    },
    "no_session_lock": {
        "reqs": ["SR 2.5", "SR 2.6", "SR 2.7"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "No session lock/timeout configured",
        "fr": "FR2 - Use Control"
    },
    "no_audit_logging": {
        "reqs": ["SR 2.8", "SR 2.9", "SR 6.1", "EDR 2.8", "HDR 2.8", "PLC-14"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Audit logging not enabled or not accessible",
        "fr": "FR6 - Timely Response to Events"
    },
    "no_network_segmentation": {
        "reqs": ["SR 5.1", "SR 5.2", "NDR 5.1", "NDR 5.2"],
        "severity": COMPLIANCE_HIGH,
        "desc": "No network segmentation / zone boundary protection",
        "fr": "FR5 - Restricted Data Flow"
    },
    "debug_service_exposed": {
        "reqs": ["SR 7.7", "SR 2.1", "EDR 2.1", "PLC-18"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "Debug/diagnostic service exposed (WDB, QCONN, JTAG, etc.)",
        "fr": "FR7 - Resource Availability"
    },
    "firmware_outdated": {
        "reqs": ["SR 3.4", "SR 7.6", "EDR 3.14", "HDR 3.13", "PLC-05"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Outdated firmware/software version detected",
        "fr": "FR3 - System Integrity"
    },
    "no_input_validation": {
        "reqs": ["SR 3.5", "EDR 3.5", "SAR 3.5", "PLC-08", "PLC-09"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Input validation weakness detected",
        "fr": "FR3 - System Integrity"
    },
    "plc_no_integrity_check": {
        "reqs": ["PLC-04", "PLC-05", "PLC-10"],
        "severity": COMPLIANCE_HIGH,
        "desc": "PLC missing integrity checks (flags, checksums, field device validation)",
        "fr": "PLC Top 20 Secure Coding"
    },
    "plc_no_safe_state": {
        "reqs": ["PLC-11", "PLC-19"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "No defined safe process state on failure/restart",
        "fr": "PLC Top 20 Secure Coding"
    },
    "plc_no_monitoring": {
        "reqs": ["PLC-12", "PLC-13", "PLC-15", "PLC-16", "PLC-17", "PLC-20"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "PLC monitoring gaps (uptime, cycle times, memory, logging)",
        "fr": "PLC Top 20 Secure Coding"
    },
    "telnet_enabled": {
        "reqs": ["SR 4.1", "SR 4.3", "SR 1.13", "NDR 1.13"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Telnet (cleartext) protocol enabled",
        "fr": "FR4 - Data Confidentiality"
    },
    "ftp_anonymous": {
        "reqs": ["SR 1.1", "SR 2.1", "SR 4.1"],
        "severity": COMPLIANCE_HIGH,
        "desc": "FTP anonymous access enabled",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "vnc_no_auth": {
        "reqs": ["SR 1.1", "SR 2.1", "HDR 1.1"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "VNC allows connection without authentication",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "zone_transfer_allowed": {
        "reqs": ["SR 5.2", "SR 5.3", "NDR 5.2"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "DNS zone transfer allowed - information disclosure",
        "fr": "FR5 - Restricted Data Flow"
    },
    "ipmi_exposed": {
        "reqs": ["SR 1.1", "SR 7.7", "HDR 1.1"],
        "severity": COMPLIANCE_HIGH,
        "desc": "IPMI BMC exposed - potential auth bypass (CVE-2013-4786)",
        "fr": "FR7 - Resource Availability"
    },
    "docker_api_exposed": {
        "reqs": ["SR 2.1", "SR 5.2", "SR 7.7"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "Docker API exposed without TLS client auth",
        "fr": "FR2 - Use Control"
    },
    "k8s_anonymous": {
        "reqs": ["SR 1.1", "SR 2.1", "SAR 1.1", "SAR 2.1"],
        "severity": COMPLIANCE_CRITICAL,
        "desc": "Kubernetes API allows anonymous access",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "cloud_metadata_exposed": {
        "reqs": ["SR 4.1", "SR 5.2", "SR 7.6"],
        "severity": COMPLIANCE_HIGH,
        "desc": "Cloud instance metadata/credentials accessible",
        "fr": "FR4 - Data Confidentiality"
    },
    "smb_signing_disabled": {
        "reqs": ["SR 3.1", "NDR 3.1"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "SMB message signing not required",
        "fr": "FR3 - System Integrity"
    },
    "expired_certificate": {
        "reqs": ["SR 1.8", "SR 4.3"],
        "severity": COMPLIANCE_HIGH,
        "desc": "TLS certificate expired or self-signed",
        "fr": "FR1 - Identification and Authentication Control"
    },
    "graphql_introspection": {
        "reqs": ["SR 5.3", "SAR 3.5", "SAR 3.7"],
        "severity": COMPLIANCE_MEDIUM,
        "desc": "GraphQL introspection enabled - schema disclosure",
        "fr": "FR5 - Restricted Data Flow"
    },
}

def check_compliance(result):
    """Check an EnumResult against compliance database. Returns list of (severity, reqs, desc, fr)."""
    findings = []
    output_lower = (result.output + " " + result.notes).lower()
    check_lower = result.check.lower()

    # Pattern matching rules
    rules = [
        ("no_auth", ["no auth", "anonymous access", "allowed - anonymous", "no authentication",
                      "return code: 0", "accepted - no auth"]),
        ("default_creds", ["default", "admin:admin", "root:root", "password:", "community 'public'"]),
        ("anonymous_access", ["anonymous", "ALLOWED - anonymous", "anonymous login"]),
        ("snmp_public", ["community 'public' accepted", "community string", "snmp community"]),
        ("no_encryption", ["cleartext", "unencrypted", "plain text", "no tls", "port 23 ", "port 21 ",
                           "modbus", "bacnet", "dnp3", "fins", "melsec", "s7comm", "ethernet/ip"]),
        ("weak_tls", ["sslv3", "tlsv1.0", "tlsv1.1", "rc4", "des-cbc", "null cipher"]),
        ("missing_security_headers", ["security headers missing", "x-frame-options", "x-content-type"]),
        ("no_audit_logging", ["no audit", "logging not", "no log", "log not accessible"]),
        ("debug_service_exposed", ["wdb agent", "qconn", "debug", "diagnostic service"]),
        ("telnet_enabled", ["telnet banner", "telnet (port"]),
        ("ftp_anonymous", ["ftp anonymous login", "allowed - anonymous"]),
        ("vnc_no_auth", ["vnc no auth", "vnc allows connection without"]),
        ("zone_transfer_allowed", ["zone transfer", "axfr response received"]),
        ("ipmi_exposed", ["ipmi rmcp", "bmc responding"]),
        ("docker_api_exposed", ["docker /version", "docker /info", "docker /containers"]),
        ("k8s_anonymous", ["k8s /api/v1/pods", "k8s /api/v1/namespaces"]),
        ("cloud_metadata_exposed", ["aws imdsv2 token", "aws /latest/meta-data", "gcp project",
                                     "azure imds", "managed identity token"]),
        ("smb_signing_disabled", ["signing: disabled", "signing: enabled"]),
        ("expired_certificate", ["certificate expired", "self-signed", "not after"]),
        ("graphql_introspection", ["graphql introspection", "__schema"]),
    ]

    for rule_key, patterns in rules:
        for pattern in patterns:
            if pattern.lower() in output_lower or pattern.lower() in check_lower:
                if rule_key in COMPLIANCE_DB:
                    db = COMPLIANCE_DB[rule_key]
                    findings.append((db["severity"], db["reqs"], db["desc"], db["fr"]))
                break
    return findings


def compliance_color(severity):
    """Return ANSI color for compliance severity."""
    return {
        COMPLIANCE_CRITICAL: Colors.RED,
        COMPLIANCE_HIGH: Colors.MAGENTA,
        COMPLIANCE_MEDIUM: Colors.YELLOW,
        COMPLIANCE_LOW: Colors.CYAN,
        COMPLIANCE_PASS: Colors.GREEN,
    }.get(severity, Colors.WHITE)


# =============================================================================
# 5.11  ICS CONFIG FILE READING MODULES
# =============================================================================

class ConfigFileReaderModule(BaseModule):
    name = "config_files"
    category = ModuleCategory.DEVICE_CONFIG
    description = "ICS/OT config file reader - GSD, GSDML, EDS, IODD, ESI, FDI, EDD via protocols"
    default_ports = [80, 443, 102, 44818, 34964, 5683]

    def _try_http_file(self, host, port, paths, use_ssl=False):
        """Try to read config files via HTTP from device web servers."""
        found = []
        for path in paths:
            status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
            if status == 200 and body.strip() and len(body) > 50:
                found.append((path, body[:2000]))
        return found

    def _analyze_gsd_gsdml(self, content, host):
        """Analyze PROFINET GSD/GSDML (XML) for security-relevant config."""
        findings = []
        lower = content.lower()
        if '<?xml' in lower and ('gsd' in lower or 'profinet' in lower):
            self._record("GSDML detected", host, content[:300], "success",
                         "PROFINET device description file")
            # Check for security gaps
            if 'password' not in lower and 'authentication' not in lower:
                self._record("GSDML: No auth config", host,
                             "No authentication parameters in device description",
                             "warn", "62443: SR 1.1, SR 1.2 - IAC gap")
            if 'snmp' in lower and 'community' in lower:
                self._record("GSDML: SNMP community configured", host,
                             "SNMP community string in device description",
                             "warn", "62443: SR 1.5 - Default credentials risk")
        return findings

    def _analyze_eds(self, content, host):
        """Analyze EtherNet/IP EDS (Electronic Data Sheet) for security config."""
        if '[device]' in content.lower() or 'vendname' in content.lower():
            self._record("EDS file detected", host, content[:300], "success",
                         "EtherNet/IP Electronic Data Sheet")
            if 'password' not in content.lower():
                self._record("EDS: No password config", host,
                             "No password/auth parameters in EDS",
                             "warn", "62443: SR 1.1, PLC-18 - No access control")

    def _analyze_iodd(self, content, host):
        """Analyze IO-Link IODD (XML) for security parameters."""
        lower = content.lower()
        if '<?xml' in lower and ('iodd' in lower or 'io-link' in lower):
            self._record("IODD detected", host, content[:300], "success",
                         "IO-Link Device Description (IODD)")

    def _analyze_esi(self, content, host):
        """Analyze EtherCAT ESI (XML) for security config."""
        lower = content.lower()
        if '<?xml' in lower and ('ethercat' in lower or 'esi' in lower):
            self._record("ESI detected", host, content[:300], "success",
                         "EtherCAT Slave Information file")

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"ICS Config File Enumeration: {host}")
        # Try to read config files via HTTP
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            # PROFINET GSD/GSDML paths
            gsdml_paths = ['/gsdml.xml', '/config/gsdml.xml', '/device.xml',
                           '/profinet/gsdml.xml', '/description.xml']
            for path, body in self._try_http_file(host, port, gsdml_paths, use_ssl):
                self._analyze_gsd_gsdml(body, host)
            # EtherNet/IP EDS paths
            eds_paths = ['/eds', '/config/eds', '/device.eds', '/config.eds']
            for path, body in self._try_http_file(host, port, eds_paths, use_ssl):
                self._analyze_eds(body, host)
            # IO-Link IODD
            iodd_paths = ['/iodd.xml', '/iodd/device.xml', '/iolinkmaster/iodd']
            for path, body in self._try_http_file(host, port, iodd_paths, use_ssl):
                self._analyze_iodd(body, host)
            # EtherCAT ESI
            esi_paths = ['/esi.xml', '/ethercat/esi.xml', '/slave.xml']
            for path, body in self._try_http_file(host, port, esi_paths, use_ssl):
                self._analyze_esi(body, host)
            # FDI/EDD - typically via HART-IP or web
            fdi_paths = ['/fdi/device.xml', '/edd/', '/hart/edd', '/fielddevice/config']
            for path, body in self._try_http_file(host, port, fdi_paths, use_ssl):
                self._record(f"FDI/EDD config: {path}", host, body[:300], "success",
                             "Field Device Integration / Electronic Device Description")
            # Generic config paths (Siemens, AB, Schneider web interfaces)
            generic_paths = ['/config', '/configuration', '/system/config',
                            '/api/config', '/api/v1/configuration', '/settings',
                            '/diagnostic', '/status.json', '/info.json']
            for path, body in self._try_http_file(host, port, generic_paths, use_ssl):
                self._record(f"Device config: {path}", host, body[:300], "info")
                # Check for hardcoded/default passwords in config
                lower = body.lower()
                for indicator in ['password', 'passwd', 'secret', 'credential', 'api_key', 'token']:
                    if indicator in lower:
                        self._record(f"Sensitive data in config: {path}", host,
                                     f"Found '{indicator}' in configuration data",
                                     "warn", "62443: SR 1.5, SR 4.1")
        return self.results


class ITConfigReaderModule(BaseModule):
    name = "it_config_files"
    category = ModuleCategory.DEVICE_CONFIG
    description = "IT/Cloud config reader - Docker Compose, K8s manifests, Terraform, Ansible, cloud configs"
    default_ports = [80, 443, 2375, 6443, 8080]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"IT/Cloud Config File Enumeration: {host}")
        for port in [80, 443, 8080]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = port in [443]
            # Common IT config endpoints
            paths = [
                '/.env', '/config.json', '/config.yaml', '/config.yml',
                '/docker-compose.yml', '/docker-compose.yaml',
                '/package.json', '/composer.json', '/Gemfile',
                '/.git/config', '/.svn/entries',
                '/server-status', '/server-info',
                '/phpinfo.php', '/info.php',
                '/actuator/env', '/actuator/configprops',
                '/api/v1/configmaps', '/api/v1/secrets',
                '/.well-known/security.txt', '/security.txt',
                '/robots.txt', '/sitemap.xml',
            ]
            for path in paths:
                status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
                if status == 200 and body.strip() and len(body) > 20:
                    lower = body.lower()
                    # Flag sensitive data exposure
                    sensitive = False
                    for indicator in ['password', 'secret', 'api_key', 'token', 'private_key',
                                      'aws_access', 'database_url', 'connection_string']:
                        if indicator in lower:
                            self._record(f"Sensitive config: {path}", host,
                                         f"Found '{indicator}' in exposed config",
                                         "warn", "62443: SR 4.1, SR 7.6")
                            sensitive = True
                            break
                    if not sensitive:
                        self._record(f"Config file: {path}", host, body[:200], "info")
                elif status == 403:
                    pass  # Expected - access denied
        return self.results


# =============================================================================
# 5.12  LOG AND EVENT READING MODULES
# =============================================================================

class WindowsLogReaderModule(BaseModule):
    name = "windows_logs"
    category = ModuleCategory.OS_CONFIG
    description = "Windows Event Logs - Security, System, Application events, login failures, audit"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Windows Event Log Enumeration")
        if platform.system() != "Windows":
            self._record("Windows logs", host, "Not a Windows system - skipping", "skipped")
            return self.results
        checks = [
            ("Security Log (last 20)", 'wevtutil qe Security /c:20 /f:text /rd:true', 30),
            ("Failed Logins", 'wevtutil qe Security /q:"*[System[EventID=4625]]" /c:10 /f:text /rd:true', 30),
            ("Successful Logins", 'wevtutil qe Security /q:"*[System[EventID=4624]]" /c:10 /f:text /rd:true', 30),
            ("Account Changes", 'wevtutil qe Security /q:"*[System[(EventID=4720 or EventID=4722 or EventID=4724)]]" /c:10 /f:text /rd:true', 30),
            ("System Log (last 20)", 'wevtutil qe System /c:20 /f:text /rd:true', 30),
            ("Application Log (last 20)", 'wevtutil qe Application /c:20 /f:text /rd:true', 30),
            ("Service Start/Stop", 'wevtutil qe System /q:"*[System[EventID=7036]]" /c:10 /f:text /rd:true', 30),
            ("Windows Firewall Log", r'type %SystemRoot%\system32\LogFiles\Firewall\pfirewall.log 2>nul | findstr /c:"DROP" | tail 20', 15),
            ("PowerShell Script Block Log", 'wevtutil qe "Microsoft-Windows-PowerShell/Operational" /c:10 /f:text /rd:true', 30),
            ("Audit Policy Status", "auditpol /get /category:*", 15),
        ]
        for name, cmd, cmd_timeout in checks:
            result = run_os_cmd(cmd, timeout=cmd_timeout)
            status = "success" if result and "(no output)" not in result and "error" not in result.lower() else "info"
            self._record(name, host, result[:1500], status)
            # Compliance check: if audit logging is not enabled
            if "no auditing" in result.lower() or "not configured" in result.lower():
                self._record(f"COMPLIANCE: {name}", host,
                             "Audit logging not properly configured",
                             "warn", "62443: SR 2.8, SR 6.1 - Auditable Events")
        return self.results


class LinuxLogReaderModule(BaseModule):
    name = "linux_logs"
    category = ModuleCategory.OS_CONFIG
    description = "Linux Logs - syslog, auth.log, journal, kern.log, audit.log, daemon events"
    default_ports = []

    def run(self, host, ports=None):
        print_subsection(f"Linux Log Enumeration")
        if platform.system() != "Linux":
            self._record("Linux logs", host, "Not a Linux system - skipping", "skipped")
            return self.results
        checks = [
            ("Auth Log (last 30)", "tail -30 /var/log/auth.log 2>/dev/null || journalctl -u sshd -n 30 --no-pager 2>/dev/null", 15),
            ("Failed SSH Logins", "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 || journalctl -u sshd --no-pager -n 20 2>/dev/null | grep -i fail", 15),
            ("Successful Logins", "last -20 2>/dev/null", 10),
            ("System Log (last 30)", "tail -30 /var/log/syslog 2>/dev/null || journalctl -n 30 --no-pager 2>/dev/null", 15),
            ("Kernel Log", "tail -20 /var/log/kern.log 2>/dev/null || dmesg | tail -20", 10),
            ("Audit Log", "tail -30 /var/log/audit/audit.log 2>/dev/null || ausearch -m LOGIN -ts recent 2>/dev/null | tail -20", 15),
            ("Daemon Log", "tail -20 /var/log/daemon.log 2>/dev/null", 10),
            ("Boot Log", "journalctl -b -n 20 --no-pager 2>/dev/null || tail -20 /var/log/boot.log 2>/dev/null", 10),
            ("Cron Log", "tail -20 /var/log/cron.log 2>/dev/null || journalctl -u cron -n 20 --no-pager 2>/dev/null", 10),
            ("Sudo Log", "grep 'sudo' /var/log/auth.log 2>/dev/null | tail -15", 10),
            ("Package Manager Log", "tail -20 /var/log/dpkg.log 2>/dev/null || tail -20 /var/log/yum.log 2>/dev/null", 10),
            ("Audit Status", "auditctl -s 2>/dev/null || echo 'auditd not running'", 5),
            ("Rsyslog Config", "cat /etc/rsyslog.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20", 5),
        ]
        for name, cmd, cmd_timeout in checks:
            result = run_os_cmd(cmd, timeout=cmd_timeout)
            status = "success" if result and "(no output)" not in result and "denied" not in result.lower() else "info"
            self._record(name, host, result[:1500], status)
        # Check audit configuration
        audit_status = run_os_cmd("auditctl -s 2>/dev/null", timeout=5)
        if "enabled 0" in audit_status or "not running" in audit_status.lower():
            self._record("COMPLIANCE: auditd disabled", host,
                         "Linux audit subsystem not enabled",
                         "warn", "62443: SR 2.8, SR 6.1 - Auditable Events")
        return self.results


class DeviceLogReaderModule(BaseModule):
    name = "device_logs"
    category = ModuleCategory.DEVICE_CONFIG
    description = "ICS/OT device logs via SNMP, HTTP, syslog - PLC events, HMI alarms, gateway logs"
    default_ports = [80, 443, 161, 514]

    def run(self, host, ports=None):
        ports = ports or self.default_ports
        print_subsection(f"Device Log Enumeration: {host}")
        # Try reading logs via HTTP (common on HMIs, gateways, managed switches)
        for port in [80, 443]:
            if not is_port_open(host, port, self.config.timeout):
                continue
            use_ssl = (port == 443)
            log_paths = [
                '/log', '/logs', '/syslog', '/eventlog', '/events',
                '/api/logs', '/api/v1/logs', '/api/events',
                '/diagnostic/log', '/diag/log', '/system/log',
                '/alarm', '/alarms', '/history', '/audit',
                '/cgi-bin/log.cgi', '/log.txt', '/event.log',
            ]
            for path in log_paths:
                status, hdrs, body = self._http(host, port, path, use_ssl=use_ssl)
                if status == 200 and body.strip() and len(body) > 30:
                    self._record(f"Device log: {path} ({port})", host, body[:500], "success",
                                 "Device event/alarm/audit log")
        # Try SNMP log table (OID: syslog / event table)
        snmp_mod = SNMPModule(self.config, self.target)
        resp = snmp_mod._snmp_get(host, 161, 'public', '1.3.6.1.2.1.1.3.0')  # sysUpTime
        if resp:
            parsed = snmp_mod._parse_snmp_response(resp)
            if parsed:
                self._record("SNMP sysUpTime", host, safe_decode(parsed[1]), "success")
        # Syslog UDP listener check
        if is_port_open(host, 514, 2):
            self._record("Syslog port 514 open", host, "Device may accept/send syslog", "info")
        return self.results


MODULE_REGISTRY: Dict[str, type] = OrderedDict()

def _register_modules():
    """Register all modules."""
    # ICS/OT Protocols (39 modules)
    for cls in [ModbusTCPModule, ModbusRTUModule, S7commModule, EtherNetIPModule,
                DNP3Module, OPCUAModule, OPCDAModule, BACnetModule, PROFINETModule,
                IEC104Module, IEC101Module, IEC61850Module, IEC61850GOOSEModule,
                IEC61850SVModule, HARTIPModule, WirelessHARTModule, FINSModule,
                MELSECModule, CCLinkModule, EtherCATModule, POWERLINKModule,
                FoundationFieldbusModule, GEsrtpModule, ABETHModule,
                TriStationModule, FoxModule, CrimsonV3Module, NiagaraFoxModule,
                ROCModule, DLMSCOSEMModule, YokogawaModule, ProConOSModule,
                MoxaNPortModule, ICCPModule, KNXModule, LonWorksModule,
                IOLinkModule, CANopenModule, PROFIBUSModule]:
        MODULE_REGISTRY[cls.name] = cls
    # IT/Network Protocols (15 modules)
    for cls in [SNMPModule, SMBModule, SSHModule, FTPModule, TFTPModule,
                TelnetModule, DNSModule, DHCPModule, LDAPModule, HTTPModule,
                NFSModule, IPMIModule, RedfishModule, RDPModule, VNCModule]:
        MODULE_REGISTRY[cls.name] = cls
    # Wireless/IoT (10 modules)
    for cls in [MQTTModule, MQTTSNModule, CoAPModule, LwM2MModule, AMQPModule,
                ZigbeeModule, BLEModule, WifiModule, LoRaWANModule, ZWaveModule]:
        MODULE_REGISTRY[cls.name] = cls
    # Cloud/AI/Container (8 modules)
    for cls in [DockerModule, KubernetesModule, AWSModule, GCPModule,
                AzureModule, OCIModule, MCPModule, APIModule]:
        MODULE_REGISTRY[cls.name] = cls
    # OS Config (4 modules)
    for cls in [WindowsConfigModule, LinuxConfigModule, MacOSConfigModule, UnixConfigModule,
                WindowsLogReaderModule, LinuxLogReaderModule]:
        MODULE_REGISTRY[cls.name] = cls
    # RTOS Config (6 modules)
    for cls in [VxWorksConfigModule, QNXConfigModule, NucleusConfigModule,
                WindowsIoTConfigModule, IntegrityConfigModule, FreeRTOSConfigModule]:
        MODULE_REGISTRY[cls.name] = cls
    # Device Config (5 modules)
    for cls in [NetworkDeviceModule, PLCModule, HMISCADAModule, GatewayModule, RadioModule,
                ConfigFileReaderModule, ITConfigReaderModule, DeviceLogReaderModule]:
        MODULE_REGISTRY[cls.name] = cls
    # Attack Surface & Interfaces
    MODULE_REGISTRY["attack_surface"] = AttackSurfaceModule
    MODULE_REGISTRY["interfaces"] = InterfaceEnumModule

_register_modules()

CATEGORY_GROUPS = OrderedDict([
    ("ICS/OT Protocols", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.ICS_OT_PROTOCOL]),
    ("IT/Network Protocols", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.IT_PROTOCOL]),
    ("Wireless/IoT", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.WIRELESS_IOT]),
    ("Cloud/AI/Container", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.CLOUD_AI_PROTOCOL]),
    ("Operating Systems", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.OS_CONFIG]),
    ("Real-Time OS (RTOS)", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.RTOS_CONFIG]),
    ("Device Types", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.DEVICE_CONFIG]),
    ("Attack Surface", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.ATTACK_SURFACE]),
    ("Interfaces", [n for n, c in MODULE_REGISTRY.items() if c.category == ModuleCategory.INTERFACE_ENUM]),
])


# ===============================================================================
# SECTION 7: REPORT GENERATION (all native Python - no external libraries)
# ===============================================================================

class ReportGenerator:
    """Generate reports in multiple formats using only Python standard library."""

    def __init__(self, results: List[EnumResult], config: ScanConfig, target: ScanTarget = None, selected_modules: List[str] = None):
        self.results = results
        self.config = config
        self.target = target or ScanTarget()
        self.selected_modules = selected_modules or []
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _config_block(self) -> str:
        """Return a formatted string of all user-set parameters."""
        lines = []
        lines.append("## User Configuration")
        lines.append(f"- **Project:** {self.config.project}")
        lines.append(f"- **Output Directory:** {self.config.output_dir}")
        lines.append(f"- **Timeout:** {self.config.timeout}s")
        lines.append(f"- **Threads:** {self.config.threads}")
        lines.append(f"- **Privileged Mode:** {self.config.privileged}")
        lines.append(f"- **Verbose:** {self.config.verbose}")
        lines.append(f"- **Targets:** {', '.join(self.target.hosts) if self.target.hosts else '(none)'}")
        lines.append(f"- **Custom Ports:** {self.target.ports if self.target.ports else '(module defaults)'}")
        lines.append("")
        lines.append("## Selected Modules")
        if not self.selected_modules:
            lines.append("(none selected)")
        else:
            for mod in self.selected_modules:
                cls = MODULE_REGISTRY.get(mod)
                if cls:
                    lines.append(f"- **{mod}** – {cls.description}")
                else:
                    lines.append(f"- **{mod}** (unknown)")
        lines.append("")
        return "\n".join(lines)
    
    def _compliance_findings(self):
        """Return a list of compliance findings for all results."""
        findings = []
        for r in self.results:
            comp = check_compliance(r)
            for sev, reqs, desc, fr in comp:
                findings.append({
                    "severity": sev,
                    "requirements": reqs,
                    "description": desc,
                    "fr": fr,
                    "module": r.module,
                    "check": r.check,
                    "host": r.host,
                    "output_snippet": r.output[:200] if r.output else ""
                })
        return findings

    def _compliance_section(self, format="markdown"):
        """Return formatted compliance section for reports."""
        findings = self._compliance_findings()
        if not findings:
            return "No compliance findings identified.\n"
        # Group by FR (standard)
        groups = {}
        for f in findings:
            fr = f["fr"]
            groups.setdefault(fr, []).append(f)
        lines = []
        lines.append("## Compliance Findings (ISA/IEC 62443-3-3, 4-2, PLC Top 20)")
        for fr, items in groups.items():
            lines.append(f"\n### {fr}")
            # Group by severity within each FR
            sev_order = [COMPLIANCE_CRITICAL, COMPLIANCE_HIGH, COMPLIANCE_MEDIUM, COMPLIANCE_LOW]
            for sev in sev_order:
                sev_items = [i for i in items if i["severity"] == sev]
                if not sev_items:
                    continue
                color_map = {
                    COMPLIANCE_CRITICAL: "🔴 CRITICAL",
                    COMPLIANCE_HIGH: "🟠 HIGH",
                    COMPLIANCE_MEDIUM: "🟡 MEDIUM",
                    COMPLIANCE_LOW: "🔵 LOW"
                }
                header = color_map.get(sev, sev)
                lines.append(f"\n#### {header} ({len(sev_items)})")
                for idx, item in enumerate(sev_items, 1):
                    lines.append(f"\n**{idx}. {item['description']}**")
                    lines.append(f"- **Module:** `{item['module']}`")
                    lines.append(f"- **Check:** {item['check']}")
                    lines.append(f"- **Host:** {item['host']}")
                    lines.append(f"- **Requirements:** {', '.join(item['requirements'])}")
                    if item['output_snippet']:
                        lines.append(f"- **Evidence:** ```{item['output_snippet']}```")
        return "\n".join(lines)
    
    def generate(self, formats: List[str]):
        try:
            os.makedirs(self.config.output_dir, exist_ok=True)
        except Exception as e:
            print_color(f"  [!] Cannot create output dir: {e}", Colors.RED)
            return []
        generated = []
        for fmt in formats:
            method = getattr(self, f"_gen_{fmt}", None)
            if method:
                try:
                    path = method()
                    if path:
                        generated.append(path)
                        print_color(f"  [+] Generated: {path}", Colors.GREEN)
                except Exception as e:
                    print_color(f"  [!] Report {fmt} failed: {e}", Colors.RED)
        return generated

    def _ensure_dir(self):
        os.makedirs(self.config.output_dir, exist_ok=True)

    def _gen_markdown(self):
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.md")
        lines = [f"# {TOOL_NAME} v{VERSION} - Enumeration Report",
                 f"\n**Project:** {self.config.project}",
                 f"**Date:** {datetime.datetime.now().isoformat()}",
                 f"**Total Findings:** {len(self.results)}\n"]
        lines.append(self._config_block())
        lines.append(self._compliance_section())
        by_module = OrderedDict()
        for r in self.results:
            by_module.setdefault(r.module, []).append(r)
        for mod, results in by_module.items():
            lines.append(f"\n## Module: {mod}\n")
            for r in results:
                icon = {"success": "+", "fail": "x", "warn": "!", "info": "i", "skipped": "-"}.get(r.status, "i")
                lines.append(f"- [{icon}] **{r.check}** ({r.host})")
                if r.output:
                    lines.append(f"  ```\n  {r.output}\n  ```")
                if r.notes:
                    lines.append(f"  > {r.notes}")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return path

    def _gen_json(self):
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.json")
        data = {
            "tool": TOOL_NAME, "version": VERSION, 
            "project": self.config.project,
            "timestamp": datetime.datetime.now().isoformat(),
            "total_findings": len(self.results),
            "user_configuration": {
                "project": self.config.project,
                "output_dir": self.config.output_dir,
                "timeout": self.config.timeout,
                "threads": self.config.threads,
                "privileged": self.config.privileged,
                "verbose": self.config.verbose,
                "targets": self.target.hosts,
                "custom_ports": self.target.ports,
                "selected_modules": self.selected_modules
            },
            "compliance_findings": self._compliance_findings(),
            "results": [{"module": r.module, "host": r.host, "check": r.check,
                          "output": r.output, "status": r.status, "notes": r.notes,
                          "timestamp": r.timestamp} for r in self.results]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    def _gen_txt(self):
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.txt")
        lines = [f"{TOOL_NAME} v{VERSION} - Enumeration Report",
                 f"Project: {self.config.project}",
                 f"Date: {datetime.datetime.now().isoformat()}",
                  "=" * 70, ""]
        lines.append(self._config_block().replace('##', '').replace('-', '•'))
        lines.append("")
        lines.append(self._compliance_section().replace('#', '').replace('###', '===').replace('####', '---'))
        for r in self.results:
            lines.append(f"[{r.status.upper():8s}] [{r.module}] {r.check} ({r.host})")
            if r.output:
                for line in r.output.split('\n'):
                    lines.append(f"           {line}")
            if r.notes:
                lines.append(f"           Note: {r.notes}")
            lines.append("")
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return path

    def _gen_html(self):
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.html")
        status_colors = {"success": "#28a745", "fail": "#dc3545", "warn": "#ffc107",
                         "info": "#17a2b8", "skipped": "#6c757d"}
        rows = ""
        for r in self.results:
            color = status_colors.get(r.status, "#17a2b8")
            output_esc = r.output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            notes_esc = r.notes.replace('&', '&amp;').replace('<', '&lt;')
            rows += f"""<tr>
                <td><span style="color:{color};font-weight:bold">{r.status.upper()}</span></td>
                <td>{r.module}</td><td>{r.host}</td><td>{r.check}</td>
                <td><pre style="margin:0;white-space:pre-wrap;font-size:11px">{output_esc}</pre></td>
                <td style="font-size:11px">{notes_esc}</td></tr>\n"""
        config_html = "<h2>User Configuration</h2><ul>"
        config_html += f"<li><strong>Project:</strong> {self.config.project}</li>"
        config_html += f"<li><strong>Output Dir:</strong> {self.config.output_dir}</li>"
        config_html += f"<li><strong>Timeout:</strong> {self.config.timeout}s</li>"
        config_html += f"<li><strong>Threads:</strong> {self.config.threads}</li>"
        config_html += f"<li><strong>Privileged:</strong> {self.config.privileged}</li>"
        config_html += f"<li><strong>Verbose:</strong> {self.config.verbose}</li>"
        config_html += f"<li><strong>Targets:</strong> {', '.join(self.target.hosts)}</li>"
        config_html += f"<li><strong>Custom Ports:</strong> {self.target.ports if self.target.ports else '(module defaults)'}</li>"
        config_html += "</ul><h2>Selected Modules</h2><ul>"
        for mod in self.selected_modules:
            config_html += f"<li>{mod}</li>"
        config_html += "</ul>"
        # Build compliance HTML separately
        compliance_section_raw = self._compliance_section()
        # Simple conversion of markdown-style to HTML (quick and dirty for reports)
        compliance_html = "<h2>Compliance Findings</h2>" + compliance_section_raw.replace('\n', '<br>').replace('###', '<h3>').replace('####', '<h4>')
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{TOOL_NAME} Report - {self.config.project}</title>
<style>
body{{background:#1a1a2e;color:#e0e0e0;font-family:monospace;margin:20px}}
h1{{color:#00ff88}}h2{{color:#00ccff}}h3{{color:#ffaa00}}h4{{color:#88ff88}}
table{{border-collapse:collapse;width:100%;margin-top:10px}}
th{{background:#16213e;color:#00ff88;padding:8px;text-align:left;border:1px solid #333}}
td{{padding:6px;border:1px solid #333;vertical-align:top;font-size:12px}}
tr:nth-child(even){{background:#16213e}}tr:hover{{background:#1a1a3e}}
pre{{background:#0d1117;padding:4px;border-radius:3px}}
</style></head><body>
{config_html}
{compliance_html}
<h1>{TOOL_NAME} v{VERSION} - Enumeration Report</h1>
<p><strong>Project:</strong> {self.config.project} | <strong>Date:</strong> {datetime.datetime.now().isoformat()}</p>
<p><strong>Total Findings:</strong> {len(self.results)}</p>
<table border="1">
<tr><th>Status</th><th>Module</th><th>Host</th><th>Check</th><th>Output</th><th>Notes</th></tr>
{rows}
</table>
</body></html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

    def _gen_pdf(self):
        """Generate multi-page PDF with all results (no truncation)."""
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.pdf")
        
        # Build full text content (no truncation)
        text_lines = []
        text_lines.append(f"{TOOL_NAME} v{VERSION} - Enumeration Report")
        text_lines.append(f"Project: {self.config.project}")
        text_lines.append(f"Date: {datetime.datetime.now().isoformat()}")
        text_lines.append(f"Total Findings: {len(self.results)}")
        text_lines.append("=" * 70)
        text_lines.append("")
        text_lines.extend(self._config_block().split('\n'))
        text_lines.append("")
        text_lines.extend(self._compliance_section().split('\n'))
        text_lines.append("")
        text_lines.append("## Results")
        text_lines.append("")
        for r in self.results:
            text_lines.append(f"[{r.status.upper()}] [{r.module}] {r.check} ({r.host})")
            if r.output:
                for line in r.output.split('\n'):
                    # Keep line length reasonable for PDF page width
                    text_lines.append(f"  {line[:90]}")
            if r.notes:
                text_lines.append(f"  Note: {r.notes}")
            text_lines.append("")
        
        # Encode all text as Latin-1 safe
        safe_lines = []
        for line in text_lines:
            safe = line.encode('ascii', errors='replace').decode('ascii')
            safe = safe.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            safe_lines.append(safe)
        
        # PDF page parameters
        lines_per_page = 60   # fit within 792 pt height
        total_lines = len(safe_lines)
        pages = [safe_lines[i:i+lines_per_page] for i in range(0, total_lines, lines_per_page)]
        
        objects = []
        # Catalog and Pages objects will be built after we know number of pages
        kids = []
        page_objects = []
        for page_num, page_lines in enumerate(pages):
            # Build content stream for this page
            stream = "BT\n/F1 8 Tf\n50 750 Td\n10 TL\n"
            y = 0
            for line in page_lines:
                stream += f"({line}) '\n"
                y += 1
                if y >= lines_per_page:
                    break
            stream += "ET"
            stream_bytes = stream.encode('ascii', errors='replace')
            page_obj_num = 3 + page_num * 2
            content_obj_num = page_obj_num + 1
            objects.append(f"{page_obj_num} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_obj_num} 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n".encode())
            objects.append(f"{content_obj_num} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode() + stream_bytes + b"\nendstream\nendobj\n")
            kids.append(f"{page_obj_num} 0 R")
        
        # Pages object
        pages_obj = f"2 0 obj\n<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>\nendobj\n".encode()
        # Catalog
        catalog_obj = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        # Font
        font_obj = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
        
        # Assemble all objects in order
        all_objects = [catalog_obj, pages_obj] + objects + [font_obj]
        
        with open(path, 'wb') as f:
            f.write(b"%PDF-1.4\n")
            offsets = []
            for obj in all_objects:
                offsets.append(f.tell())
                f.write(obj)
            xref_pos = f.tell()
            f.write(b"xref\n")
            f.write(f"0 {len(all_objects)+1}\n".encode('ascii'))
            f.write(b"0000000000 65535 f \n")
            for off in offsets:
                f.write(f"{off:010d} 00000 n \n".encode('ascii'))
            f.write(b"trailer\n")
            f.write(f"<< /Size {len(all_objects)+1} /Root 1 0 R >>\n".encode('ascii'))
            f.write(b"startxref\n")
            f.write(f"{xref_pos}\n".encode('ascii'))
            f.write(b"%%EOF\n")
        return path

    def _gen_docx(self):
        """Generate professional DOCX report with proper headings."""
        self._ensure_dir()
        path = os.path.join(self.config.output_dir, f"{self.config.project}_{self.timestamp}.docx")
        
        # Build table rows with full output
        rows_xml = ""
        for r in self.results:
            output_esc = r.output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            rows_xml += f"""<w:tr>
<w:tc><w:p><w:r><w:t>{r.status}</w:t></w:r></w:p></w:tc>
<w:tc><w:p><w:r><w:t>{r.module}</w:t></w:r></w:p></w:tc>
<w:tc><w:p><w:r><w:t>{r.host}</w:t></w:r></w:p></w:tc>
<w:tc><w:p><w:r><w:t>{r.check}</w:t></w:r></w:p></w:tc>
<w:tc><w:p><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t>{output_esc}</w:t></w:r></w:p></w:tc>
</w:tr>\n"""
        
        # Build config section with heading and styled paragraphs
        config_text = self._config_block().replace('##', '').replace('-', '•').replace('**', '')
        config_para = f"""<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>User Configuration</w:t></w:r></w:p>
<w:p><w:r><w:t>{config_text}</w:t></w:r></w:p>"""
        
        # Build compliance section with heading
        compliance_text = self._compliance_section().replace('#', '').replace('###', '=== ').replace('####', '--- ')
        compliance_para = f"""<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Compliance Findings (ISA/IEC 62443-3-3, 4-2, PLC Top 20)</w:t></w:r></w:p>
<w:p><w:r><w:t>{compliance_text}</w:t></w:r></w:p>"""
        
        doc_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>{TOOL_NAME} v{VERSION} - Enumeration Report</w:t></w:r></w:p>
<w:p><w:r><w:t>Project: {self.config.project} | Date: {datetime.datetime.now().isoformat()}</w:t></w:r></w:p>
<w:p><w:r><w:t>Total Findings: {len(self.results)}</w:t></w:r></w:p>
{config_para}
{compliance_para}
<w:tbl><w:tblPr>
<w:tblW w:w="9000" w:type="dxa"/>
<w:tblBorders>
<w:top w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/>
<w:bottom w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/>
<w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/>
</w:tblBorders>
<w:tblLayout w:type="fixed"/>
</w:tblPr>
<w:tr>
<w:tc><w:tcW w:w="800" w:type="dxa"/><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Status</w:t></w:r></w:p></w:tc>
<w:tc><w:tcW w:w="1200" w:type="dxa"/><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Module</w:t></w:r></w:p></w:tc>
<w:tc><w:tcW w:w="1000" w:type="dxa"/><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Host</w:t></w:r></w:p></w:tc>
<w:tc><w:tcW w:w="2000" w:type="dxa"/><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Check</w:t></w:r></w:p></w:tc>
<w:tc><w:tcW w:w="4000" w:type="dxa"/><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Output</w:t></w:r></w:p></w:tc>
</w:tr>
{rows_xml}
</w:tbl>
</w:body></w:document>"""
        
        # DOCX packaging (unchanged)
        rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
        content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
        word_rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"""
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml', content_types)
            zf.writestr('_rels/.rels', rels)
            zf.writestr('word/document.xml', doc_xml)
            zf.writestr('word/_rels/document.xml.rels', word_rels)
        return path

# ===============================================================================
# SECTION 8: INTERACTIVE CONSOLE
# ===============================================================================

class InteractiveConsole:
    """Metasploit-style interactive console for ReadOnlyEnum."""

    def __init__(self):
        self.config = ScanConfig()
        self.target = ScanTarget()
        self.selected_modules: List[str] = []
        self.all_results: List[EnumResult] = []

    def _prompt(self):
        return f"{Colors.RED}ReadOnlyEnum{Colors.RESET}({Colors.CYAN}{self.config.project}{Colors.RESET})> "

    def run(self):
        print(BANNER)
        print_color(f"  {len(MODULE_REGISTRY)} modules | 9 categories | 7 report formats", Colors.GREEN)
        print_color(f"  100% Native Python - Zero external dependencies\n", Colors.GREEN)
        print_color("  Type 'help' for commands.\n", Colors.GRAY)
        while True:
            try:
                cmd = input(self._prompt()).strip()
                if not cmd:
                    continue
                parts = cmd.split(None, 2)
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                if command in ('quit', 'exit', 'q'):
                    print_color("Exiting ReadOnlyEnum.", Colors.YELLOW)
                    break
                elif command == 'help':
                    self._cmd_help()
                elif command == 'banner':
                    print(BANNER)
                elif command == 'modules':
                    self._cmd_modules(args)
                elif command == 'set':
                    self._cmd_set(args)
                elif command == 'show':
                    self._cmd_show(args)
                elif command == 'target':
                    self._cmd_target(args)
                elif command == 'use':
                    self._cmd_use(args)
                elif command == 'scan':
                    self._cmd_scan(args)
                elif command == 'report':
                    self._cmd_report(args)
                elif command == 'results':
                    self._cmd_results()
                elif command == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                elif command == 'compliance':
                    self._cmd_compliance()
                elif command == 'tools':
                    self._cmd_tools()
                else:
                    print_color(f"  Unknown command: {command}. Type 'help' for commands.", Colors.RED)
            except KeyboardInterrupt:
                print()
            except EOFError:
                break

    def _cmd_help(self):
        help_text = f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.BOLD}║                            COMMAND REFERENCE                                  ║{Colors.RESET}
{Colors.BOLD}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.BOLD}  help{Colors.RESET}            Show this detailed help menu
{Colors.BOLD}  banner{Colors.RESET}          Display the tool banner
{Colors.BOLD}  clear{Colors.RESET}           Clear the screen
{Colors.BOLD}  quit{Colors.RESET}            Exit the console

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  MODULE SELECTION                                                            │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.BOLD}  use <module1,module2,...>{Colors.RESET}   Select specific modules by name
{Colors.BOLD}  use all{Colors.RESET}                    Select ALL available modules
{Colors.BOLD}  use <category>{Colors.RESET}             Select all modules in a category
{Colors.BOLD}  use none{Colors.RESET}                   Clear all selected modules

{Colors.BOLD}  Available categories:{Colors.RESET}
    • ICS/OT Protocols
    • IT/Network Protocols
    • Wireless/IoT
    • Cloud/AI/Container
    • Operating Systems
    • Real-Time OS (RTOS)
    • Device Types
    • Attack Surface
    • Interfaces

{Colors.BOLD}  Examples:{Colors.RESET}
    use modbus_tcp,s7comm,ethernet_ip
    use all
    use "ICS/OT Protocols"
    use Operating Systems

{Colors.BOLD}  modules{Colors.RESET}                    List all modules with descriptions
{Colors.BOLD}  modules <filter>{Colors.RESET}           List modules by category (e.g., modules ics)

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  TARGET CONFIGURATION                                                        │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.BOLD}  target <host>{Colors.RESET}              Set target host(s) – supports:
{Colors.BOLD}                                            • Single IP: 192.168.1.1
{Colors.BOLD}                                            • CIDR: 192.168.1.0/24
{Colors.BOLD}                                            • Range: 192.168.1.10-20
{Colors.BOLD}                                            • Comma list: 192.168.1.1,192.168.1.2
{Colors.BOLD}                                            • Mix: 192.168.1.0/24,10.0.0.1

{Colors.BOLD}  target{Colors.RESET} (no args)           Show current target(s)

{Colors.BOLD}  set ports <ports>{Colors.RESET}          Override default ports for all modules
{Colors.BOLD}                                            Examples: set ports 80,443,8080
{Colors.BOLD}                                                      set ports 1-1024

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  SCAN CONFIGURATION                                                          │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.BOLD}  set project <name>{Colors.RESET}         Set project name (used in report filenames)
{Colors.BOLD}  set output_dir <path>{Colors.RESET}      Directory where reports are saved
{Colors.BOLD}  set timeout <seconds>{Colors.RESET}      Connection timeout (default 5)
{Colors.BOLD}  set threads <number>{Colors.RESET}       Max concurrent threads (default 5)
{Colors.BOLD}  set privileged <true/false>{Colors.RESET} Enable OS-level privileged checks (default false)
{Colors.BOLD}  set verbose <true/false>{Colors.RESET}    Show verbose debug output (default false)

{Colors.BOLD}  show{Colors.RESET}                       Display all current settings:
{Colors.BOLD}                                            • Project, output directory
{Colors.BOLD}                                            • Timeout, threads, privileged, verbose
{Colors.BOLD}                                            • Targets, custom ports
{Colors.BOLD}                                            • List of selected modules with descriptions

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  RUNNING SCANS                                                               │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.BOLD}  scan{Colors.RESET}                      Run selected modules against current target(s)
{Colors.BOLD}  scan <host>{Colors.RESET}               Run scan against ad-hoc host (overrides target)

{Colors.BOLD}  results{Colors.RESET}                   Show scan results summary grouped by:
{Colors.BOLD}                                            • Status (success, warn, info, fail)
{Colors.BOLD}                                            • Module breakdown with finding counts

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  REPORT GENERATION                                                           │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.BOLD}  report <format>{Colors.RESET}           Generate report in specified format:
{Colors.BOLD}                                            • md   - Markdown
{Colors.BOLD}                                            • json - JSON
{Colors.BOLD}                                            • txt  - Plain text
{Colors.BOLD}                                            • html - HTML
{Colors.BOLD}                                            • pdf  - PDF
{Colors.BOLD}                                            • docx - Microsoft Word
{Colors.BOLD}                                            • all  - All six formats

{Colors.BOLD}  report all <directory>{Colors.RESET}     Generate all reports into specific directory
{Colors.BOLD}                                            Example: report all ./my_scan_results

{Colors.BOLD}  Note:{Colors.RESET} Reports include:
    • Full scan configuration (project, timeout, threads, privileged, targets, custom ports)
    • List of selected modules with descriptions
    • All enumeration findings with output and notes
    • Timestamp

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  TYPICAL WORKFLOW                                                            │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

  1. {Colors.GREEN}target 192.168.1.0/24{Colors.RESET}                # Set your target
  2. {Colors.GREEN}use modbus_tcp,s7comm,bacnet{Colors.RESET}       # Select specific modules
  3. {Colors.GREEN}set timeout 10{Colors.RESET}                     # Increase timeout for slow networks
  4. {Colors.GREEN}set privileged true{Colors.RESET}                # Enable deep OS checks (if root)
  5. {Colors.GREEN}show{Colors.RESET}                               # Verify everything
  6. {Colors.GREEN}scan{Colors.RESET}                               # Run the scan
  7. {Colors.GREEN}results{Colors.RESET}                            # Quick summary
  8. {Colors.GREEN}report all{Colors.RESET}                         # Save all reports to default directory

{Colors.BOLD}  To change output directory before report:{Colors.RESET}
    set output_dir /path/to/results
    report all

{Colors.BOLD}  To run a quick scan without changing target:{Colors.RESET}
    scan 10.0.0.1

{Colors.BOLD}  To clear all module selections:{Colors.RESET}
    use none

{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.BOLD}│  ADDITIONAL INFO                                                              │{Colors.RESET}
{Colors.BOLD}└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

  • All modules are 100% native Python – no external tools required.
  • Reports are saved in the configured output directory (default: ReadOnlyEnum_Results/).
  • Use {Colors.YELLOW}Ctrl+C{Colors.RESET} to interrupt a running scan.
  • Use {Colors.YELLOW}--no-color{Colors.RESET} flag when launching to disable ANSI colors.

{Colors.BOLD}  For more templates and tools, visit: https://isiahjonesstem.github.io/security-methodology/{Colors.RESET}
"""
        print(help_text)

    def _cmd_modules(self, args):
        cat_filter = ' '.join(args).lower() if args else None
        for cat_name, mod_names in CATEGORY_GROUPS.items():
            if cat_filter and cat_filter not in cat_name.lower():
                continue
            print_color(f"\n  {cat_name} ({len(mod_names)} modules):", Colors.BOLD + Colors.CYAN)
            for name in mod_names:
                cls = MODULE_REGISTRY[name]
                selected = " <--" if name in self.selected_modules else ""
                print(f"    {Colors.GREEN}{name:25s}{Colors.RESET} {cls.description[:60]}{Colors.YELLOW}{selected}{Colors.RESET}")
        print_color(f"\n  Total: {len(MODULE_REGISTRY)} modules", Colors.GRAY)

    def _cmd_use(self, args):
        if not args:
            print_color("  Usage: use <module1,module2,...> | use all | use <category>", Colors.YELLOW)
            return
        selection = ' '.join(args)
        if selection.lower() == 'all':
            self.selected_modules = list(MODULE_REGISTRY.keys())
            print_color(f"  Selected all {len(self.selected_modules)} modules", Colors.GREEN)
        elif selection.lower() == 'none':
            self.selected_modules = []
            print_color("  Cleared module selection", Colors.YELLOW)
        else:
            # Check if it's a category name
            for cat_name, mod_names in CATEGORY_GROUPS.items():
                if selection.lower() in cat_name.lower():
                    self.selected_modules.extend([m for m in mod_names if m not in self.selected_modules])
                    print_color(f"  Added {len(mod_names)} modules from {cat_name}", Colors.GREEN)
                    return
            # Parse as comma-separated module names
            for name in selection.split(','):
                name = name.strip()
                if name in MODULE_REGISTRY:
                    if name not in self.selected_modules:
                        self.selected_modules.append(name)
                        print_color(f"  Selected: {name}", Colors.GREEN)
                else:
                    print_color(f"  Unknown module: {name}", Colors.RED)

    def _cmd_target(self, args):
        if not args:
            if self.target.hosts:
                print_color(f"  Current targets: {', '.join(self.target.hosts)}", Colors.CYAN)
            else:
                print_color("  Usage: target <host/CIDR/range>", Colors.YELLOW)
            return
        self.target.hosts = parse_hosts(' '.join(args))
        print_color(f"  Targets set: {len(self.target.hosts)} host(s)", Colors.GREEN)

    def _cmd_set(self, args):
        if len(args) < 2:
            print_color("  Usage: set <project|timeout|threads|privileged|output_dir|verbose|ports> <value>", Colors.YELLOW)
            return
        key, val = args[0].lower(), ' '.join(args[1:]) if len(args) > 1 else args[1]
        if key == 'project':
            self.config.project = val
        elif key == 'timeout':
            self.config.timeout = int(val)
        elif key == 'threads':
            self.config.threads = int(val)
        elif key == 'privileged':
            self.config.privileged = val.lower() in ('true', 'yes', '1')
        elif key == 'output_dir':
            self.config.output_dir = val
        elif key == 'verbose':
            self.config.verbose = val.lower() in ('true', 'yes', '1')
        elif key == 'ports':
            self.target.ports = parse_ports(val)
        else:
            print_color(f"  Unknown key: {key}", Colors.RED)
            return
        print_color(f"  {key} => {val}", Colors.GREEN)

    def _cmd_show(self, args):
        print_color(f"\n  {'='*60}", Colors.CYAN)
        print_color("  CURRENT CONFIGURATION", Colors.BOLD + Colors.WHITE)
        print_color(f"  {'='*60}", Colors.CYAN)
        print_color(f"  Project:      {self.config.project}", Colors.WHITE)
        print_color(f"  Output Dir:   {self.config.output_dir}", Colors.WHITE)
        print_color(f"  Timeout:      {self.config.timeout}s", Colors.WHITE)
        print_color(f"  Threads:      {self.config.threads}", Colors.WHITE)
        print_color(f"  Privileged:   {self.config.privileged}", Colors.WHITE)
        print_color(f"  Verbose:      {self.config.verbose}", Colors.WHITE)
        print_color(f"  Custom Ports: {self.target.ports if self.target.ports else '(none, using module defaults)'}", Colors.WHITE)
        print_color(f"  Targets:      {', '.join(self.target.hosts) if self.target.hosts else '(none)'}", Colors.WHITE)
        
        print_color(f"\n  {'='*60}", Colors.CYAN)
        print_color("  SELECTED MODULES", Colors.BOLD + Colors.WHITE)
        print_color(f"  {'='*60}", Colors.CYAN)
        
        if not self.selected_modules:
            print_color("  (none selected)", Colors.GRAY)
        else:
            for mod_name in self.selected_modules:
                cls = MODULE_REGISTRY.get(mod_name)
                if cls:
                    desc = cls.description[:70]
                    ports = f"ports: {cls.default_ports}" if cls.default_ports else "no default ports"
                    cat = cls.category.value.replace('_', ' ').title()
                    print_color(f"  • {Colors.GREEN}{mod_name}{Colors.RESET}", Colors.WHITE, end='')
                    print_color(f"  [{cat}]", Colors.CYAN)
                    print_color(f"      {desc}", Colors.GRAY)
                    print_color(f"      {ports}", Colors.GRAY)
                else:
                    print_color(f"  • {mod_name} (unknown module)", Colors.YELLOW)
        
        print_color(f"\n  {'='*60}", Colors.GRAY)

    def _cmd_scan(self, args):
        # Allow ad-hoc target
        if args:
            self.target.hosts = parse_hosts(' '.join(args))
        if not self.target.hosts:
            print_color("  No target set. Use: target <host>", Colors.RED)
            return
        if not self.selected_modules:
            print_color("  No modules selected. Use: use <module> or use all", Colors.RED)
            return
        print_section(f"Scanning {len(self.target.hosts)} host(s) with {len(self.selected_modules)} module(s)")
        for host in self.target.hosts:
            for mod_name in self.selected_modules:
                cls = MODULE_REGISTRY.get(mod_name)
                if not cls:
                    continue
                try:
                    mod = cls(self.config, self.target)
                    ports = self.target.ports if self.target.ports else None
                    results = mod.run(host, ports)
                    self.all_results.extend(results)
                except Exception as e:
                    print_color(f"  [ERROR] {mod_name}: {e}", Colors.RED)
                    if self.config.verbose:
                        traceback.print_exc()
        print_section("Scan Complete")
        success = sum(1 for r in self.all_results if r.status == "success")
        warn = sum(1 for r in self.all_results if r.status == "warn")
        fail = sum(1 for r in self.all_results if r.status == "fail")
        print_color(f"  Total: {len(self.all_results)} findings", Colors.BOLD)
        print_color(f"  Success: {success} | Warnings: {warn} | Critical: {fail}", Colors.GREEN)
                # Detailed compliance findings with specific triggers
        all_comp = []
        for r in self.all_results:
            comps = check_compliance(r)
            for sev, reqs, desc, fr in comps:
                all_comp.append((sev, reqs, desc, fr, r.module, r.check, r.host))
        if all_comp:
            print_color(f"\n  {'='*60}", Colors.BOLD + Colors.RED)
            print_color("  COMPLIANCE FINDINGS (ISA/IEC 62443-3-3, 4-2, PLC Top 20)", Colors.BOLD + Colors.RED)
            print_color(f"  {'='*60}", Colors.BOLD + Colors.RED)
            groups = {}
            for sev, reqs, desc, fr, mod, chk, host in all_comp:
                groups.setdefault(fr, []).append((sev, reqs, desc, mod, chk, host))
            for fr, items in groups.items():
                print_color(f"\n  {fr}", Colors.BOLD + Colors.CYAN)
                for sev in [COMPLIANCE_CRITICAL, COMPLIANCE_HIGH, COMPLIANCE_MEDIUM, COMPLIANCE_LOW]:
                    sev_items = [i for i in items if i[0] == sev]
                    if not sev_items:
                        continue
                    color = compliance_color(sev)
                    print_color(f"    {color}[{sev}]{Colors.RESET} ({len(sev_items)})")
                    for idx, (_, reqs, desc, mod, chk, host) in enumerate(sev_items, 1):
                        print(f"      {idx}. {desc}")
                        print(f"         → Module: {mod} | Check: {chk} | Host: {host}")
                        print(f"         Reqs: {', '.join(reqs[:3])}")
        else:
            print_color(f"\n  No compliance findings identified.", Colors.GREEN)

    def _cmd_report(self, args):
        if not self.all_results:
            print_color("  No results to report. Run a scan first.", Colors.YELLOW)
            return
        if not args:
            print_color("  Usage: report <md|json|txt|html|pdf|docx|all>", Colors.YELLOW)
            return
        fmt = args[0].lower()
        if fmt == 'all':
            formats = ['markdown', 'json', 'txt', 'html', 'pdf', 'docx']
        else:
            fmt_map = {'md': 'markdown', 'json': 'json', 'txt': 'txt',
                       'html': 'html', 'pdf': 'pdf', 'docx': 'docx'}
            formats = [fmt_map.get(fmt, fmt)]
        gen = ReportGenerator(self.all_results, self.config, self.target, self.selected_modules)
        gen.generate(formats)

    def _cmd_results(self):
        if not self.all_results:
            print_color("  No results yet.", Colors.GRAY)
            return
        by_status = {}
        for r in self.all_results:
            by_status.setdefault(r.status, []).append(r)
        for status, results in by_status.items():
            print_color(f"\n  {status.upper()} ({len(results)}):", Colors.BOLD)
            for r in results[:20]:
                print(f"    [{r.module}] {r.check} ({r.host})")
            if len(results) > 20:
                print_color(f"    ... {len(results)-20} more", Colors.GRAY)

    def _cmd_compliance(self):
        """Show detailed compliance findings with evidence."""
        if not self.all_results:
            print_color("  No results yet. Run a scan first.", Colors.GRAY)
            return
        all_comp = []
        for r in self.all_results:
            comps = check_compliance(r)
            for sev, reqs, desc, fr in comps:
                all_comp.append({
                    "severity": sev,
                    "requirements": reqs,
                    "description": desc,
                    "fr": fr,
                    "module": r.module,
                    "check": r.check,
                    "host": r.host,
                    "output": r.output[:300] if r.output else ""
                })
        if not all_comp:
            print_color("  No compliance findings flagged.", Colors.GREEN)
            return
        print_color(f"\n  {'='*60}", Colors.BOLD + Colors.RED)
        print_color("  COMPLIANCE REPORT (ISA/IEC 62443-3-3, 4-2, PLC Top 20)", Colors.BOLD + Colors.RED)
        print_color(f"  {'='*60}", Colors.BOLD + Colors.RED)
        # Group by FR
        groups = {}
        for f in all_comp:
            groups.setdefault(f["fr"], []).append(f)
        for fr, items in groups.items():
            print_color(f"\n  {fr}", Colors.BOLD + Colors.CYAN)
            # Group by severity
            for sev in [COMPLIANCE_CRITICAL, COMPLIANCE_HIGH, COMPLIANCE_MEDIUM, COMPLIANCE_LOW]:
                sev_items = [i for i in items if i["severity"] == sev]
                if not sev_items:
                    continue
                color = compliance_color(sev)
                print_color(f"\n    {color}[{sev}]{Colors.RESET} ({len(sev_items)})")
                for idx, item in enumerate(sev_items, 1):
                    print(f"      {idx}. {item['description']}")
                    print(f"         Module: {item['module']} | Check: {item['check']} | Host: {item['host']}")
                    print(f"         Requirements: {', '.join(item['requirements'])}")
                    if item['output']:
                        print(f"         Evidence snippet: {item['output'][:150]}...")
        print_color(f"\n  Use 'report all' to save full compliance details to files.", Colors.GRAY)

    def _cmd_tools(self):
        print_color(f"\n  {TOOL_NAME} v{VERSION}", Colors.BOLD + Colors.GREEN)
        print_color(f"  {COPYRIGHT}\n", Colors.GRAY)
        print_color("  100% Native Python | Zero External Dependencies", Colors.CYAN)
        print_color(f"  Total Modules: {len(MODULE_REGISTRY)}\n", Colors.WHITE)
        for cat_name, mod_names in CATEGORY_GROUPS.items():
            print_color(f"    {cat_name}: {len(mod_names)} modules", Colors.WHITE)


# ===============================================================================
# SECTION 9: CLI PARSER & MAIN
# ===============================================================================

def list_modules():
    """Print all modules grouped by category."""
    print(BANNER)
    for cat_name, mod_names in CATEGORY_GROUPS.items():
        print_color(f"\n  {cat_name} ({len(mod_names)}):", Colors.BOLD + Colors.CYAN)
        for name in mod_names:
            cls = MODULE_REGISTRY[name]
            ports = f"Ports: {cls.default_ports}" if cls.default_ports else "Local/L2"
            print(f"    {Colors.GREEN}{name:25s}{Colors.RESET} {cls.description[:55]:55s} {Colors.GRAY}{ports}{Colors.RESET}")
    print_color(f"\n  Total: {len(MODULE_REGISTRY)} modules", Colors.BOLD)


def main():
    """Launch ReadOnlyEnum in interactive mode."""
    # ANSI color detection & fallback
    if '--no-color' in sys.argv:
        Colors.disable()
    elif not supports_ansi_colors():
        Colors.disable()
    console = InteractiveConsole()
    console.run()


if __name__ == "__main__":
    main()