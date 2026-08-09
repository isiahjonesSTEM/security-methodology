#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ICS / OT / IoT  62443 SL-3 CHECKLIST GENERATOR
 — single-file interactive tool that builds product-specific SL-3 testing
   cheat sheets mapped to ISA/IEC 62443-3-3 (system) and 4-2 (component)
================================================================================

A companion to the "ICS/OT/IoT Threat Modeler". Same standalone, model-agnostic,
single-file design and the same 4-step workflow — but instead of a threat model
it produces a detailed **ISA/IEC 62443-3-3 / 4-2 · SL-3 Testing Cheat Sheet** PDF
in the exact format of the hand-authored product cheat sheets
(https://github.com/isiahjonesSTEM/security-methodology).

    $ python3 ics_62443_sl3_checklist_generator.py            # http://127.0.0.1:8010
    $ python3 ics_62443_sl3_checklist_generator.py --port 9000 --open
    $ python3 ics_62443_sl3_checklist_generator.py --help

WORKFLOW (mirrors the threat modeler):
  Step 1  Choose ANY AI model & paste its API key (Anthropic, OpenAI, Google,
          DeepSeek, Kimi, or any local/OpenAI-compatible endpoint). That ONE key
          does everything — including web search. No second key is ever needed.
  Step 2  Describe the component (e.g. "Siemens SIPROTEC 5 7SJ85 relay").
  Step 3  Add sources — let the AI search the web on its own (using your model's
          key: Anthropic web search, Google grounding, OpenAI web search), and/or
          paste product/manual/datasheet URLs (scraped live), and/or upload user
          manuals & datasheets (large >400pp PDFs are chunked + distilled so the
          whole document is read).
  Step 4  The AI (1) locates the product, (2) determines whether it is an
          Embedded Device (EDR), Host Device (HDR), Network Device (NDR), or
          Software Application (SAR) — which you CONFIRM or OVERRIDE — then
          (3) generates the full SL-3 cheat sheet: FR1–FR7 with every SR/CR
          plus the component-specific EDR/HDR/NDR/SAR rows, an External Test
          Tools table, and a print-perfect landscape PDF.

DEPENDENCIES: NONE. Python 3.9+ standard library ONLY — nothing to pip install.
  * The landscape cheat-sheet PDF is produced by a built-in, dependency-free PDF
    engine (no reportlab). A print-to-PDF HTML sheet with the identical layout is
    also offered.
  * PDF/DOCX text and embedded images are parsed with the standard library
    (no pypdf / python-docx). Web pages and manuals are fetched with urllib.
    Everything runs on a clean Python install and degrades gracefully.

The 62443-3-3 / 4-2 requirement catalog is embedded below (FR1–FR7, full SR set,
full CR set, and the EDR/HDR/NDR/SAR component requirements). The requirement IDs
and names are ISA/IEC's own; concise summaries are paraphrased for mapping. The
standard remains the property of ISA/IEC — consult the primary source for
authoritative text (https://www.isa.org).

License: MIT.  Created by Isiah Jones.
================================================================================
"""
from __future__ import annotations

import argparse
import base64
import html as _htmlmod
import http.server
import io
import json
import os
import re
import socketserver
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zlib
from datetime import datetime, timezone

APP_NAME = "ICS/OT/IoT 62443 SL-3 Checklist Generator"
APP_VERSION = "1.0.0"
DEFAULT_DB = os.environ.get("ICG_DB", os.path.join(os.path.expanduser("~"), ".ics_62443_checklists.db"))

# =============================================================================
#  SECTION 1 — EMBEDDED ISA/IEC 62443-3-3 / 4-2 REQUIREMENT CATALOG
# =============================================================================
# Foundational Requirements (FR) titles as they appear on the cheat sheets.
FR_TITLES = {
    "FR1": "Identification & Authentication Control (IAC)",
    "FR2": "Use Control (UC)",
    "FR3": "System Integrity (SI)",
    "FR4": "Data Confidentiality (DC)",
    "FR5": "Restricted Data Flow (RDF)",
    "FR6": "Timely Response to Events (TRE)",
    "FR7": "Resource Availability (RA)",
}
FR_ORDER = ["FR1", "FR2", "FR3", "FR4", "FR5", "FR6", "FR7"]

# Component-type codes (ISA/IEC 62443-4-2). SAR is a subset of CRs plus its own
# rows; EDR/HDR/NDR extend the CR baseline with type-specific requirements.
COMPONENT_TYPES = {
    "EDR": "Embedded Device (EDR)",
    "HDR": "Host Device (HDR)",
    "NDR": "Network Device (NDR)",
    "SAR": "Software Application (SAR)",
}

IEC62443 = {
    "part_3_3": [  # IEC 62443-3-3 system requirements (full SR set)
        ("SR 1.1", "FR1", "Human user identification and authentication", "Identify and authenticate all human users on all interfaces."),
        ("SR 1.2", "FR1", "Software process and device identification and authentication", "Identify and authenticate software processes and devices."),
        ("SR 1.3", "FR1", "Account management", "Support management of all accounts (add/modify/disable/remove)."),
        ("SR 1.4", "FR1", "Identifier management", "Manage identifiers by user, group, role, or interface."),
        ("SR 1.5", "FR1", "Authenticator management", "Initialize, change, protect, and revoke authenticators; no default/hardcoded."),
        ("SR 1.6", "FR1", "Wireless access management", "Identify/authenticate/authorize wireless users and devices."),
        ("SR 1.7", "FR1", "Strength of password-based authentication", "Enforce configurable password strength/policy."),
        ("SR 1.8", "FR1", "Public key infrastructure (PKI) certificates", "Operate a PKI per best practice where certificates are used."),
        ("SR 1.9", "FR1", "Strength of public key authentication", "Validate certificates and protect private keys."),
        ("SR 1.10", "FR1", "Authenticator feedback", "Obscure feedback of authentication information."),
        ("SR 1.11", "FR1", "Unsuccessful login attempts", "Limit consecutive failed login attempts (lockout/backoff)."),
        ("SR 1.12", "FR1", "System use notification", "Display a system-use/authorization notification before access."),
        ("SR 1.13", "FR1", "Access via untrusted networks", "Monitor and control access from untrusted networks."),
        ("SR 2.1", "FR2", "Authorization enforcement", "Enforce least-privilege authorizations for users/processes."),
        ("SR 2.2", "FR2", "Wireless use control", "Authorize/monitor/enforce usage restrictions for wireless."),
        ("SR 2.3", "FR2", "Use control for portable and mobile devices", "Control use of portable/mobile devices."),
        ("SR 2.4", "FR2", "Mobile code", "Control and monitor the use of mobile code."),
        ("SR 2.5", "FR2", "Session lock", "Lock sessions after inactivity."),
        ("SR 2.6", "FR2", "Remote session termination", "Terminate remote sessions after inactivity or on demand."),
        ("SR 2.7", "FR2", "Concurrent session control", "Limit the number of concurrent sessions."),
        ("SR 2.8", "FR2", "Auditable events", "Generate audit records for security-relevant events."),
        ("SR 2.9", "FR2", "Audit storage capacity", "Provide sufficient audit storage and handling."),
        ("SR 2.10", "FR2", "Response to audit processing failures", "Handle audit processing failures safely."),
        ("SR 2.11", "FR2", "Timestamps", "Provide reliable, protected timestamps for audit records."),
        ("SR 2.12", "FR2", "Non-repudiation", "Provide non-repudiation for critical user actions."),
        ("SR 3.1", "FR3", "Communication integrity", "Protect integrity of transmitted information."),
        ("SR 3.2", "FR3", "Malicious code protection", "Protect against and detect malicious code."),
        ("SR 3.3", "FR3", "Security functionality verification", "Verify security functions operate correctly."),
        ("SR 3.4", "FR3", "Software and information integrity", "Detect unauthorized changes to software/information."),
        ("SR 3.5", "FR3", "Input validation", "Validate the syntax/content of inputs."),
        ("SR 3.6", "FR3", "Deterministic output", "Set outputs to a predetermined state if normal operation cannot be maintained."),
        ("SR 3.7", "FR3", "Error handling", "Handle error conditions without revealing sensitive info."),
        ("SR 3.8", "FR3", "Session integrity", "Protect the integrity of sessions."),
        ("SR 3.9", "FR3", "Protection of audit information", "Protect audit information and tools from unauthorized access."),
        ("SR 4.1", "FR4", "Information confidentiality", "Protect confidentiality of information at rest and in transit."),
        ("SR 4.2", "FR4", "Information persistence", "Purge sensitive information from released resources."),
        ("SR 4.3", "FR4", "Use of cryptography", "Use validated cryptographic mechanisms."),
        ("SR 5.1", "FR5", "Network segmentation", "Segment networks logically into zones and conduits."),
        ("SR 5.2", "FR5", "Zone boundary protection", "Protect zone boundaries and control conduit traffic (deny by default)."),
        ("SR 5.3", "FR5", "General purpose person-to-person communication restrictions", "Restrict general-purpose messaging."),
        ("SR 5.4", "FR5", "Application partitioning", "Partition data/applications based on criticality."),
        ("SR 6.1", "FR6", "Audit log accessibility", "Provide read access to audit logs for authorized users."),
        ("SR 6.2", "FR6", "Continuous monitoring", "Continuously monitor for security events and anomalies."),
        ("SR 7.1", "FR7", "Denial of service protection", "Protect essential functions from DoS."),
        ("SR 7.2", "FR7", "Resource management", "Manage resources to prevent exhaustion."),
        ("SR 7.3", "FR7", "Control system backup", "Support backup of critical files/configurations."),
        ("SR 7.4", "FR7", "Control system recovery and reconstitution", "Support recovery to a known secure state."),
        ("SR 7.5", "FR7", "Emergency power", "Support transition to/from emergency power without affecting security."),
        ("SR 7.6", "FR7", "Network and security configuration settings", "Manage and verify security configuration."),
        ("SR 7.7", "FR7", "Least functionality", "Restrict to least functionality (disable unused ports/services)."),
        ("SR 7.8", "FR7", "Control system component inventory", "Maintain a component inventory."),
    ],
    "part_4_2_cr": [  # IEC 62443-4-2 baseline component requirements (CR)
        ("CR 1.1", "FR1", "Human user identification and authentication", "Component identifies/authenticates human users on all interfaces."),
        ("CR 1.2", "FR1", "Software process and device identification and authentication", "Component identifies/authenticates processes/devices; applies to all interfaces incl. debug."),
        ("CR 1.3", "FR1", "Account management", "Support account management for the component."),
        ("CR 1.4", "FR1", "Identifier management", "Support identifier management."),
        ("CR 1.5", "FR1", "Authenticator management", "No hardcoded/default credentials; secure authenticator lifecycle."),
        ("CR 1.6", "FR1", "Wireless access management", "Authenticate/authorize wireless access."),
        ("CR 1.7", "FR1", "Strength of password-based authentication", "Enforce configurable password strength."),
        ("CR 1.8", "FR1", "Public key infrastructure certificates", "Support certificate-based authentication where used."),
        ("CR 1.9", "FR1", "Strength of public key authentication", "Validate certificates; protect private keys (hardware-backed)."),
        ("CR 1.10", "FR1", "Authenticator feedback", "Obscure authenticator feedback."),
        ("CR 1.11", "FR1", "Unsuccessful login attempts", "Limit/lockout after failed logins."),
        ("CR 1.12", "FR1", "System use notification", "Support system-use notification/banner."),
        ("CR 1.14", "FR1", "Strength of symmetric key authentication", "Protect and validate symmetric keys used for authentication."),
        ("CR 2.1", "FR2", "Authorization enforcement", "Enforce least-privilege RBAC on all functions."),
        ("CR 2.2", "FR2", "Wireless use control", "Enforce wireless usage restrictions."),
        ("CR 2.3", "FR2", "Use control for portable and mobile devices", "Support usage control for portable/mobile devices."),
        ("CR 2.4", "FR2", "Mobile code", "Control mobile code execution."),
        ("CR 2.5", "FR2", "Session lock", "Support session lock/timeout."),
        ("CR 2.6", "FR2", "Remote session termination", "Terminate remote sessions."),
        ("CR 2.7", "FR2", "Concurrent session control", "Limit concurrent sessions."),
        ("CR 2.8", "FR2", "Auditable events", "Generate audit records for security events."),
        ("CR 2.9", "FR2", "Audit storage capacity", "Provide adequate audit storage."),
        ("CR 2.10", "FR2", "Response to audit processing failures", "Handle audit failures safely."),
        ("CR 2.11", "FR2", "Timestamps", "Provide reliable, protected timestamps."),
        ("CR 2.12", "FR2", "Non-repudiation", "Support non-repudiation for critical actions."),
        ("CR 3.1", "FR3", "Communication integrity", "Protect integrity of communications."),
        ("CR 3.2", "FR3", "Protection from malicious code", "Support mechanisms to prevent/limit malicious code and memory corruption."),
        ("CR 3.3", "FR3", "Security functionality verification", "Support verification of security functions."),
        ("CR 3.4", "FR3", "Software and information integrity", "Verify integrity/authenticity of firmware/software/information (secure boot, signing)."),
        ("CR 3.5", "FR3", "Input validation", "Validate inputs to interfaces/protocols."),
        ("CR 3.6", "FR3", "Deterministic output", "Provide deterministic safe output state on failure."),
        ("CR 3.7", "FR3", "Error handling", "Handle errors without leaking sensitive information."),
        ("CR 3.8", "FR3", "Session integrity", "Protect session integrity."),
        ("CR 3.9", "FR3", "Protection of audit information", "Protect audit information from tampering."),
        ("CR 3.10", "FR3", "Support for updates", "Support authenticated, integrity-verified updates."),
        ("CR 3.11", "FR3", "Physical tamper resistance and detection", "Support tamper resistance/detection."),
        ("CR 3.12", "FR3", "Provisioning product supplier roots of trust", "Support supplier-provisioned roots of trust."),
        ("CR 3.13", "FR3", "Provisioning asset owner roots of trust", "Support owner-provisioned roots of trust."),
        ("CR 3.14", "FR3", "Integrity of the boot process", "Verify integrity/authenticity of the boot process (secure boot)."),
        ("CR 4.1", "FR4", "Information confidentiality", "Protect confidentiality of data at rest/in transit; protect secrets."),
        ("CR 4.2", "FR4", "Information persistence", "Erase sensitive data when no longer needed / on decommission."),
        ("CR 4.3", "FR4", "Use of cryptography", "Use validated cryptography with proper key management."),
        ("CR 5.1", "FR5", "Network segmentation", "Support network segmentation for the component."),
        ("CR 5.2", "FR5", "Zone boundary protection", "Support boundary protection features (deny by default)."),
        ("CR 5.3", "FR5", "General purpose person-to-person communication restrictions", "Restrict general-purpose comms."),
        ("CR 6.1", "FR6", "Audit log accessibility", "Provide access to audit logs."),
        ("CR 6.2", "FR6", "Continuous monitoring", "Support continuous security monitoring/alerting."),
        ("CR 7.1", "FR7", "Denial of service protection", "Maintain essential functions under DoS."),
        ("CR 7.2", "FR7", "Resource management", "Manage/limit resource consumption."),
        ("CR 7.3", "FR7", "Control system backup", "Support backup of component config/data."),
        ("CR 7.4", "FR7", "Control system recovery and reconstitution", "Support recovery to a known secure state."),
        ("CR 7.6", "FR7", "Network and security configuration settings", "Support secure, verifiable configuration."),
        ("CR 7.7", "FR7", "Least functionality", "Restrict to least functionality (disable unused ports/services)."),
        ("CR 7.8", "FR7", "Control system component inventory", "Report component inventory/identification."),
    ],
    # Component-type-specific requirements, keyed by code.
    "EDR": [
        ("EDR 2.13", "FR2", "Use of physical diagnostic and test interfaces", "Protect physical debug/test interfaces (JTAG/UART)."),
        ("EDR 3.2", "FR3", "Protection from malicious code", "Memory-corruption and code-injection protections."),
        ("EDR 3.10", "FR3", "Support for updates", "Authenticated, verified firmware update."),
        ("EDR 3.11", "FR3", "Physical tamper resistance and detection", "Resist/detect physical tampering."),
        ("EDR 3.12", "FR3", "Provisioning product supplier roots of trust", "Hardware root of trust / key provisioning by supplier."),
        ("EDR 3.13", "FR3", "Provisioning asset owner roots of trust", "Owner-provisioned roots of trust."),
        ("EDR 3.14", "FR3", "Integrity of the boot process", "Verify integrity/authenticity of the boot process."),
    ],
    "HDR": [
        ("HDR 2.4", "FR2", "Mobile code", "Control mobile code on host devices."),
        ("HDR 3.2", "FR3", "Protection from malicious code", "Anti-malware/allowlisting support."),
        ("HDR 3.10", "FR3", "Support for updates", "Authenticated, verified updates."),
        ("HDR 3.11", "FR3", "Physical tamper resistance and detection", "Tamper resistance/detection."),
        ("HDR 3.12", "FR3", "Provisioning product supplier roots of trust", "Supplier roots of trust."),
        ("HDR 3.13", "FR3", "Provisioning asset owner roots of trust", "Owner roots of trust."),
        ("HDR 3.14", "FR3", "Integrity of the boot process", "Secure/verified boot."),
    ],
    "NDR": [
        ("NDR 1.6", "FR1", "Wireless access management", "Manage wireless access."),
        ("NDR 1.13", "FR1", "Access via untrusted networks", "Control access from untrusted networks."),
        ("NDR 2.4", "FR2", "Mobile code", "Control mobile code."),
        ("NDR 3.2", "FR3", "Protection from malicious code", "Malicious code protections."),
        ("NDR 3.10", "FR3", "Support for updates", "Authenticated, verified updates."),
        ("NDR 3.11", "FR3", "Physical tamper resistance and detection", "Tamper resistance/detection."),
        ("NDR 3.12", "FR3", "Provisioning product supplier roots of trust", "Supplier roots of trust."),
        ("NDR 3.13", "FR3", "Provisioning asset owner roots of trust", "Owner roots of trust."),
        ("NDR 3.14", "FR3", "Integrity of the boot process", "Secure/verified boot."),
        ("NDR 5.2", "FR5", "Zone boundary protection", "Enforce boundary protection / deny by default."),
        ("NDR 5.3", "FR5", "General purpose person-to-person communication restrictions", "Restrict general-purpose comms."),
    ],
    "SAR": [
        ("SAR 2.4", "FR2", "Mobile code", "Control mobile code in the application."),
        ("SAR 3.2", "FR3", "Protection from malicious code", "Protections against malicious code/memory corruption."),
    ],
}


def requirements_for(codes):
    """Return the ordered requirement catalog (SR + CR + component-specific rows)
    that a cheat sheet for the given component-type codes must cover. Each item is
    (req_id_label, fr, name, summary) where req_id_label collapses matching SR+CR
    into the sheet's 'SR/CR x.y' style when the numbers align."""
    codes = [c for c in (codes or []) if c in COMPONENT_TYPES]
    sr = {i: (i, fr, n, s) for i, fr, n, s in IEC62443["part_3_3"]}
    cr = {i: (i, fr, n, s) for i, fr, n, s in IEC62443["part_4_2_cr"]}
    rows = []
    seen = set()
    # Pair SR x.y with CR x.y -> "SR/CR x.y"; otherwise emit individually.
    def num(i):
        return i.split(" ", 1)[1]
    sr_nums = {num(i): v for i, v in sr.items()}
    cr_nums = {num(i): v for i, v in cr.items()}
    all_nums = sorted(set(sr_nums) | set(cr_nums), key=lambda x: [int(p) for p in x.split(".")])
    for nmbr in all_nums:
        in_sr = nmbr in sr_nums
        in_cr = nmbr in cr_nums
        base = sr_nums.get(nmbr) or cr_nums.get(nmbr)
        _, fr, name, summ = base
        if in_sr and in_cr:
            label = f"SR/CR {nmbr}"
        elif in_sr:
            label = f"SR {nmbr}"
        else:
            label = f"CR {nmbr}"
        rows.append((label, fr, name, summ))
        seen.add(label)
    # Append component-type-specific requirement rows (EDR/HDR/NDR/SAR).
    for c in codes:
        for i, fr, n, s in IEC62443.get(c, []):
            rows.append((i, fr, n, s))
    return rows


def rows_by_fr(codes):
    cat = requirements_for(codes)
    out = {fr: [] for fr in FR_ORDER}
    for label, fr, name, summ in cat:
        out.setdefault(fr, []).append((label, name, summ))
    return out


def catalog_stats():
    return {
        "62443-3-3 SR": len(IEC62443["part_3_3"]),
        "62443-4-2 CR": len(IEC62443["part_4_2_cr"]),
        "EDR": len(IEC62443["EDR"]), "HDR": len(IEC62443["HDR"]),
        "NDR": len(IEC62443["NDR"]), "SAR": len(IEC62443["SAR"]),
    }


# =============================================================================
#  SECTION 2 — AI PROVIDERS + WEB-SEARCH PROVIDERS
# =============================================================================
PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude)", "kind": "anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "env": "ANTHROPIC_API_KEY", "vision": True,
        "models": [["claude-opus-4-8", "Claude Opus 4.8"], ["claude-sonnet-4-6", "Claude Sonnet 4.6"],
                   ["claude-haiku-4-5", "Claude Haiku 4.5"], ["claude-opus-4-1-20250805", "Claude Opus 4.1"]],
        "notes": "Get a key at https://console.anthropic.com/",
    },
    "openai": {
        "label": "OpenAI", "kind": "openai", "base_url": "https://api.openai.com/v1",
        "env": "OPENAI_API_KEY", "vision": True,
        "models": [["gpt-5.2", "GPT-5.2"], ["gpt-5", "GPT-5"], ["gpt-4.1", "GPT-4.1"],
                   ["gpt-4o", "GPT-4o"], ["o3", "OpenAI o3"]],
        "notes": "Get a key at https://platform.openai.com/",
    },
    "google": {
        "label": "Google Gemini", "kind": "google",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "env": "GOOGLE_API_KEY", "vision": True,
        "models": [["gemini-3-pro-preview", "Gemini 3 Pro"], ["gemini-2.5-pro", "Gemini 2.5 Pro"],
                   ["gemini-2.5-flash", "Gemini 2.5 Flash"]],
        "notes": "Get a key at https://aistudio.google.com/",
    },
    "deepseek": {
        "label": "DeepSeek", "kind": "openai", "base_url": "https://api.deepseek.com/v1",
        "env": "DEEPSEEK_API_KEY", "vision": False,
        "models": [["deepseek-chat", "DeepSeek Chat (V3)"], ["deepseek-reasoner", "DeepSeek Reasoner (R1)"]],
        "notes": "OpenAI-compatible. Get a key at https://platform.deepseek.com/",
    },
    "moonshot": {
        "label": "Kimi (Moonshot)", "kind": "openai", "base_url": "https://api.moonshot.ai/v1",
        "env": "MOONSHOT_API_KEY", "vision": False,
        "models": [["kimi-k2-0711-preview", "Kimi K2"], ["moonshot-v1-128k", "Moonshot v1 128k"],
                   ["moonshot-v1-32k", "Moonshot v1 32k"]],
        "notes": "OpenAI-compatible. Intl base https://api.moonshot.ai/v1 ; CN https://api.moonshot.cn/v1",
    },
    "local": {
        "label": "Local / OpenAI-compatible", "kind": "openai",
        "base_url": os.environ.get("LOCAL_OPENAI_BASE_URL", "http://localhost:11434/v1"),
        "env": "LOCAL_OPENAI_API_KEY", "vision": False,
        "models": [[os.environ.get("LOCAL_OPENAI_MODEL", "llama3.1"), "Local default"]],
        "notes": "Ollama, LM Studio, vLLM, OpenRouter. Set the Base URL in the UI.",
    },
}

# Which providers can search the web LIVE using their OWN model API key (native
# server-side web-search / grounding tools). No separate search key is ever needed —
# the selected model's key does all the work. Providers without a native tool still
# work: they use their trained knowledge plus any URLs/files the user supplies.
PROVIDER_WEB_SEARCH = {"anthropic": True, "openai": True, "google": True,
                       "deepseek": False, "moonshot": False, "local": False}


def provider_catalog():
    out = []
    for pid, p in PROVIDERS.items():
        out.append({
            "id": pid, "label": p["label"], "kind": p["kind"], "base_url": p["base_url"],
            "vision": p["vision"], "notes": p["notes"],
            "web_search": PROVIDER_WEB_SEARCH.get(pid, False),
            "server_key": bool(os.environ.get(p["env"], "")),
            "models": [{"id": m[0], "label": m[1]} for m in p["models"]],
        })
    return out


# =============================================================================
#  SECTION 3 — MODEL ROUTER (stdlib urllib; non-stream + streaming; structured)
# =============================================================================
class ProviderError(Exception):
    pass


def _resolve(provider, api_key, base_url):
    p = PROVIDERS.get(provider)
    if not p:
        raise ProviderError(f"Unknown provider '{provider}'")
    kind = p["kind"]
    base = (base_url or p["base_url"]).rstrip("/")
    key = api_key or os.environ.get(p["env"], "")
    if not key and provider != "local":
        raise ProviderError(f"No API key for '{provider}'. Enter one in the UI or set {p['env']}.")
    return kind, base, key


def _build_request(kind, base, key, model, system, user, images, stream, max_tokens,
                   temperature, provider="", tool=None):
    """Build (url, headers, body). If `tool` = {name, description, schema} is given,
    force guaranteed structured JSON output via each provider's native mechanism."""
    images = images or []
    structured = bool(tool)
    if kind == "anthropic":
        content = [{"type": "text", "text": user}]
        for im in images:
            content.append({"type": "image", "source": {"type": "base64",
                            "media_type": im.get("media_type", "image/png"), "data": im["b64"]}})
        body = {"model": model, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": content}], "stream": stream}
        if structured:
            body["tools"] = [{"name": tool["name"], "description": tool["description"],
                              "input_schema": tool["schema"]}]
            body["tool_choice"] = {"type": "tool", "name": tool["name"]}
        url = f"{base}/messages"
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    elif kind == "google":
        parts = [{"text": user}]
        for im in images:
            parts.append({"inline_data": {"mime_type": im.get("media_type", "image/png"), "data": im["b64"]}})
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": parts}],
                "generationConfig": {"maxOutputTokens": max_tokens}}
        if structured:
            body["generationConfig"]["responseMimeType"] = "application/json"
        verb = "streamGenerateContent" if stream else "generateContent"
        q = f"?alt=sse&key={key}" if stream else f"?key={key}"
        url = f"{base}/models/{model}:{verb}{q}"
        headers = {"content-type": "application/json"}
    else:  # openai-compatible
        if images:
            uc = [{"type": "text", "text": user}]
            for im in images:
                uc.append({"type": "image_url", "image_url": {"url": f"data:{im.get('media_type','image/png')};base64,{im['b64']}"}})
            user_content = uc
        else:
            user_content = user
        tok_key = "max_completion_tokens" if provider == "openai" else "max_tokens"
        body = {"model": model, "messages": [{"role": "system", "content": system},
                {"role": "user", "content": user_content}], tok_key: max_tokens, "stream": stream}
        if structured and provider in ("openai", "deepseek", "moonshot"):
            body["response_format"] = {"type": "json_object"}
        url = f"{base}/chat/completions"
        headers = {"content-type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
    if temperature is not None:
        if kind == "google":
            body["generationConfig"]["temperature"] = temperature
        else:
            body["temperature"] = temperature
    return url, headers, body


def _extract_text(kind, data):
    try:
        if kind == "anthropic":
            return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        if kind == "google":
            cands = data.get("candidates", [])
            if not cands:
                return ""
            return "".join(p.get("text", "") for p in cands[0].get("content", {}).get("parts", []))
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as e:
        raise ProviderError(f"Unexpected response shape: {e}; raw={json.dumps(data)[:400]}")


def call_model(provider, model, system, user, images=None, api_key=None, base_url=None,
               max_tokens=8000, temperature=None):
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, False,
                                        max_tokens, temperature, provider)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:600]
        raise ProviderError(f"{provider} error {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ProviderError(f"{provider} connection error: {e}")
    return _extract_text(kind, raw)


def call_model_json(provider, model, system, user, tool, images=None, api_key=None,
                    base_url=None, max_tokens=16000):
    """Return parsed JSON (dict) using each provider's guaranteed structured-output
    mode, with a tolerant parser as a final safety net."""
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, False,
                                        max_tokens, None, provider, tool=tool)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:600]
        raise ProviderError(f"{provider} error {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ProviderError(f"{provider} connection error: {e}")
    if kind == "anthropic":
        for blk in raw.get("content", []):
            if blk.get("type") == "tool_use" and isinstance(blk.get("input"), dict):
                return blk["input"]
        txt = "".join(b.get("text", "") for b in raw.get("content", []) if b.get("type") == "text")
        return parse_model_json(txt)
    return parse_model_json(_extract_text(kind, raw))


def _is_image_error(exc):
    m = str(exc).lower()
    return ("image" in m) and ("could not process" in m or "400" in m or "invalid" in m
                               or "unsupported" in m or "media type" in m or "decode" in m)


def stream_model(provider, model, system, user, images=None, api_key=None, base_url=None,
                 max_tokens=8000, temperature=None):
    """Generator yielding text deltas."""
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, True,
                                        max_tokens, temperature, provider)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=600)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:600]
        raise ProviderError(f"{provider} error {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ProviderError(f"{provider} connection error: {e}")
    for raw_line in resp:
        line = raw_line.decode("utf-8", "replace").strip()
        if not line or not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if payload == "[DONE]" or not payload:
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if kind == "anthropic":
            if obj.get("type") == "content_block_delta":
                d = obj.get("delta", {})
                if d.get("type") == "text_delta" and d.get("text"):
                    yield d["text"]
        elif kind == "google":
            for cand in obj.get("candidates", []):
                for p in cand.get("content", {}).get("parts", []):
                    if p.get("text"):
                        yield p["text"]
        else:
            for ch in obj.get("choices", []):
                delta = ch.get("delta", {}).get("content")
                if delta:
                    yield delta


def validate_key(provider, api_key=None, base_url=None):
    """Cheaply verify a provider credential by listing models. Never raises."""
    p = PROVIDERS.get(provider)
    if not p:
        return {"ok": False, "message": f"Unknown provider '{provider}'."}
    kind = p["kind"]
    base = (base_url or p["base_url"]).rstrip("/")
    key = (api_key or os.environ.get(p["env"], "") or "").strip()
    if not key and provider != "local":
        return {"ok": False, "message": "Enter an API key to continue."}
    if kind == "anthropic":
        url = f"{base}/models"; headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    elif kind == "google":
        url = f"{base}/models?key={key}"; headers = {}
    else:
        url = f"{base}/models"; headers = {"Authorization": f"Bearer {key}"} if key else {}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        ids = []
        try:
            items = data.get("data") or data.get("models") or []
            for it in items:
                mid = it.get("id") or it.get("name") or ""
                if mid:
                    ids.append(mid.split("/")[-1])
        except Exception:
            ids = []
        return {"ok": True, "message": "Key verified.", "models": ids[:60]}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        if e.code in (401, 403):
            msg = ("Your API key was rejected. Paste the FULL key (Anthropic keys start with "
                   "sk-ant-) with no extra spaces, and make sure it is active.")
        elif e.code == 404:
            msg = "Endpoint not found — check the Base URL for this provider."
        elif e.code == 429:
            msg = "Rate limited while checking the key — wait a moment and try again."
        else:
            msg = f"Provider returned {e.code}: {body}"
        return {"ok": False, "message": msg, "status": e.code}
    except urllib.error.URLError as e:
        return {"ok": False, "message": f"Could not reach the provider ({e.reason})."}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"Key check failed: {e}"}


# --- tolerant JSON parsing (safety net for models without a JSON mode) ---
def _json_repair(s):
    t = re.sub(r",(\s*[}\]])", r"\1", s)
    quotes = len(re.findall(r'(?<!\\)"', t))
    if quotes % 2 == 1:
        t += '"'
    stack, in_str, esc = [], False, False
    for ch in t:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
    for opener in reversed(stack):
        t += "}" if opener == "{" else "]"
    return t


def parse_model_json(raw):
    if not raw:
        raise ValueError("Empty model response")
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    a, b = s.find("{"), s.rfind("}")
    frag = s[a:b + 1] if (a != -1 and b > a) else s
    try:
        return json.loads(frag)
    except json.JSONDecodeError:
        pass
    for candidate in (_json_repair(frag), _json_repair(s)):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError("Could not parse JSON from model response")


def _g(d, *keys, default=""):
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return default


# =============================================================================
#  SECTION 4 — ARTIFACT INGESTION + LARGE-DOCUMENT DISTILLATION (stdlib only)
# =============================================================================
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"}
KIND_HINTS = {
    "datasheet": ["datasheet", "data sheet", "spec sheet", "specification"],
    "manual": ["manual", "guide", "handbook", "instruction", "operating", "user"],
    "security": ["security", "hardening", "cyber", "62443", "cert"],
    "config": ["config", "configuration", "settings", "parameter"],
    "network": ["network", "topology", "architecture", "comms"],
}
MAX_TEXT = 5_000_000        # retain full document text (400+ pages); distilled at analysis time
MAX_PDF_IMAGES = 10
MIN_PDF_IMAGE_BYTES = 12000


def _classify(fn):
    low = fn.lower()
    for k, hints in KIND_HINTS.items():
        if any(h in low for h in hints):
            return k
    ext = os.path.splitext(low)[1]
    if ext in IMAGE_EXTS:
        return "image"
    if ext == ".pdf":
        return "document"
    return "other"


def _pdf_text_stdlib(data):
    """Best-effort PDF text extraction using ONLY the standard library (zlib)."""
    def _unescape(t):
        out, i = [], 0
        while i < len(t):
            c = t[i]
            if c == "\\" and i + 1 < len(t):
                n = t[i + 1]
                mp = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
                      "(": "(", ")": ")", "\\": "\\"}
                if n in mp:
                    out.append(mp[n]); i += 2; continue
                if n.isdigit():
                    oct_ = t[i + 1:i + 4]
                    m = re.match(r"[0-7]{1,3}", oct_)
                    if m:
                        try:
                            out.append(chr(int(m.group(0), 8)))
                        except ValueError:
                            pass
                        i += 1 + len(m.group(0)); continue
                out.append(n); i += 2; continue
            out.append(c); i += 1
        return "".join(out)

    def _ops_to_text(content):
        try:
            s = content.decode("latin-1")
        except Exception:
            return ""
        lines = []
        for m in re.finditer(r"\[(?P<arr>(?:[^\[\]]|\\\]|\\\[)*)\]\s*TJ|"
                             r"\((?P<str>(?:\\.|[^\\()])*)\)\s*Tj", s, re.DOTALL):
            if m.group("str") is not None:
                lines.append(_unescape(m.group("str")))
            else:
                parts = re.findall(r"\((?:\\.|[^\\()])*\)", m.group("arr"))
                lines.append("".join(_unescape(p[1:-1]) for p in parts))
        return "\n".join(x for x in lines if x.strip())

    def _decode_stream(raw):
        raw2 = raw.rstrip(b"\r\n ")
        for attempt in (raw2, raw):
            try:
                return zlib.decompress(attempt)
            except Exception:
                pass
        try:
            a = base64.a85decode(raw2, adobe=True)
        except Exception:
            try:
                a = base64.a85decode(raw2.split(b"~>")[0], adobe=False)
            except Exception:
                a = None
        if a is not None:
            try:
                return zlib.decompress(a)
            except Exception:
                return a
        try:
            hx = re.sub(rb"[^0-9A-Fa-f]", b"", raw2.split(b">")[0])
            if hx:
                if len(hx) % 2:
                    hx += b"0"
                b = bytes.fromhex(hx.decode())
                try:
                    return zlib.decompress(b)
                except Exception:
                    return b
        except Exception:
            pass
        if b"Tj" in raw or b"TJ" in raw:
            return raw
        return None

    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.DOTALL):
        content = _decode_stream(m.group(1))
        if not content:
            continue
        if b"Tj" not in content and b"TJ" not in content:
            continue
        t = _ops_to_text(content)
        if t.strip():
            out.append(t)
    return "\n".join(out)


def _docx_text_stdlib(data):
    import zipfile
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return ""
    chunks = []
    for name in ("word/document.xml",) + tuple(
            n for n in z.namelist() if n.startswith("word/") and n.endswith(".xml")
            and ("header" in n or "footer" in n)):
        try:
            xml = z.read(name).decode("utf-8", "replace")
        except Exception:
            continue
        xml = re.sub(r"</w:p>", "\n", xml)
        xml = re.sub(r"<w:tab[^>]*/>", "\t", xml)
        xml = re.sub(r"<w:br[^>]*/>", "\n", xml)
        texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
        chunks.append(_htmlmod.unescape("".join(texts)))
    return "\n".join(c for c in chunks if c.strip())


SUPPORTED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_IMAGE_DIM = 8000
MAX_IMAGE_BYTES = 4_800_000


def _scan_jpeg(data, start):
    n = len(data)
    if start + 2 > n or data[start] != 0xFF or data[start + 1] != 0xD8:
        return None
    pos = start + 2
    w = h = comps = None
    while pos + 1 < n:
        if data[pos] != 0xFF:
            pos += 1; continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]; pos += 1
        if marker == 0xD9:
            return (pos, w, h, comps)
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > n:
            return None
        seg_len = (data[pos] << 8) | data[pos + 1]
        if seg_len < 2 or pos + seg_len > n:
            return None
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if seg_len >= 8:
                h = (data[pos + 3] << 8) | data[pos + 4]
                w = (data[pos + 5] << 8) | data[pos + 6]
                comps = data[pos + 7]
        if marker == 0xDA:
            pos += seg_len
            while pos + 1 < n:
                if data[pos] == 0xFF:
                    b = data[pos + 1]
                    if b == 0xD9:
                        return (pos + 2, w, h, comps)
                    if b == 0x00 or (0xD0 <= b <= 0xD7):
                        pos += 2; continue
                pos += 1
            return (n, w, h, comps)
        pos += seg_len
    return None


def _jpeg_ok(blob):
    info = _scan_jpeg(blob, 0)
    if not info:
        return False
    _end, w, h, comps = info
    if comps == 4:
        return False
    if w and h and (w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM):
        return False
    if len(blob) > MAX_IMAGE_BYTES:
        return False
    return True


def _pdf_extract_jpegs(data, cap=MAX_PDF_IMAGES, min_bytes=MIN_PDF_IMAGE_BYTES):
    out = []
    i, n = 0, len(data)
    while len(out) < cap:
        s = data.find(b"\xff\xd8\xff", i)
        if s == -1:
            break
        info = _scan_jpeg(data, s)
        if not info:
            i = s + 3; continue
        end, w, h, comps = info
        blob = data[s:end]; i = end
        if len(blob) < min_bytes:
            continue
        if comps == 4:
            continue
        if w and h and (w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM):
            continue
        if len(blob) > MAX_IMAGE_BYTES:
            continue
        out.append({"b64": base64.b64encode(blob).decode(), "media_type": "image/jpeg"})
    return out


def _png_dims(blob):
    if len(blob) >= 24 and blob[:8] == b"\x89PNG\r\n\x1a\n" and blob[12:16] == b"IHDR":
        w = int.from_bytes(blob[16:20], "big"); h = int.from_bytes(blob[20:24], "big")
        return (w, h)
    return None


def sanitize_images(images):
    clean, dropped = [], 0
    for im in images or []:
        mt = (im.get("media_type") or "").lower()
        b64 = im.get("b64") or ""
        if mt not in SUPPORTED_IMAGE_TYPES or not b64:
            dropped += 1; continue
        try:
            raw = base64.b64decode(b64, validate=False)
        except Exception:
            dropped += 1; continue
        if len(raw) > MAX_IMAGE_BYTES:
            dropped += 1; continue
        if mt == "image/jpeg" and not _jpeg_ok(raw):
            dropped += 1; continue
        if mt == "image/png":
            d = _png_dims(raw)
            if d and (d[0] > MAX_IMAGE_DIM or d[1] > MAX_IMAGE_DIM):
                dropped += 1; continue
        clean.append({"b64": b64, "media_type": mt})
    return clean, dropped


def ingest_artifact(filename, b64data):
    ext = os.path.splitext(filename.lower())[1]
    kind = _classify(filename)
    warnings, extra_images = [], []
    try:
        data = base64.b64decode(b64data)
    except Exception:
        return {"filename": filename, "kind": kind, "is_image": False, "text_excerpt": "",
                "image_b64": "", "media_type": "", "extra_images": [], "text_len": 0,
                "warnings": ["Could not decode upload"]}
    if ext in IMAGE_EXTS:
        media = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
                 ".bmp": "image/bmp", ".webp": "image/webp", ".svg": "image/svg+xml"}.get(ext, "image/png")
        if media not in SUPPORTED_IMAGE_TYPES:
            warnings.append(f"{ext} images can't be read by vision models — re-save as PNG or JPG.")
        return {"filename": filename, "kind": kind if kind != "other" else "image", "is_image": True,
                "text_excerpt": "", "image_b64": b64data, "media_type": media,
                "extra_images": [], "text_len": 0, "warnings": warnings}
    text = ""
    if ext == ".pdf":
        text = _pdf_text_stdlib(data)
        try:
            extra_images = _pdf_extract_jpegs(data)
        except Exception:
            extra_images = []
        if not text.strip() and not extra_images:
            warnings.append("No embedded text or images found (likely a vector/scanned PDF). "
                            "Export pages as PNG/JPG and upload them, or paste the online-manual URL instead.")
        elif extra_images:
            warnings.append(f"{len(extra_images)} embedded image(s) extracted for vision analysis.")
    elif ext == ".docx":
        text = _docx_text_stdlib(data)
        if not text.strip():
            warnings.append("Could not extract .docx text.")
    elif ext == ".doc":
        warnings.append("Legacy .doc not supported; save as .docx or PDF.")
    else:
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            warnings.append("Unsupported binary; not parsed.")
    full = text[:MAX_TEXT]
    return {"filename": filename, "kind": kind, "is_image": False, "text_excerpt": full,
            "image_b64": "", "media_type": "", "extra_images": extra_images,
            "text_len": len(full), "warnings": warnings}


# --- Large-document distillation (map-reduce) so nothing is dropped ---
DISTILL_SMALL = 16000
DISTILL_CHUNK = 14000
DISTILL_MAX_CHUNKS = 120        # supports very large (400+ page) manuals
DISTILL_PER_DOC_CAP = 60000
DISTILL_TOTAL_CAP = 180000

EXTRACT_SYSTEM = ("You are an ICS/OT security assessor extracting configuration- and security-relevant "
                  "facts from product documentation (manuals, datasheets, hardening guides) to build an "
                  "ISA/IEC 62443-3-3/4-2 SL-3 testing checklist. Be terse and factual; preserve exact "
                  "menu paths, port numbers, protocol names, service names, and feature names.")

EXTRACT_INSTRUCTIONS = (
    "Extract ALL configuration/security facts from this excerpt of {name} (part {i} of {n}). Include, when "
    "present: product/model & firmware/software versions; management interfaces & exact menu paths (web UI, "
    "engineering tool, CLI, config files, log locations); network interfaces, protocols and PORT NUMBERS "
    "(EtherNet/IP, PROFINET, Modbus, DNP3, IEC 61850, OPC UA, HART, SNMP, HTTPS, SSH, syslog, etc.); "
    "authentication/RBAC (accounts, roles, default/hardcoded credentials, password policy, lockout, MFA, "
    "certificate/PKI support); secure-comms/crypto (TLS/DTLS, signed firmware, secure boot, tamper); logging/"
    "audit/timestamp/NTP; backup/restore/firmware-update mechanism; physical/diagnostic ports (USB/SD/JTAG/"
    "UART); hardening/least-functionality options (disable services/ports); and any CVEs or vendor security "
    "notes. Output terse bullet lines only. If nothing relevant, output exactly: NONE.\n\nEXCERPT:\n")


def _chunk_text(text, target=DISTILL_CHUNK, max_chunks=DISTILL_MAX_CHUNKS):
    n = len(text)
    size = max(target, -(-n // max_chunks))
    return [text[i:i + size] for i in range(0, n, size)]


def distill_document(text, filename, provider, model, api_key, base_url, progress):
    chunks = _chunk_text(text)
    facts = []
    for idx, ch in enumerate(chunks):
        progress(f"Reading {filename}: section {idx + 1} of {len(chunks)}…")
        prompt = EXTRACT_INSTRUCTIONS.format(name=filename, i=idx + 1, n=len(chunks)) + ch
        out = call_model(provider, model, EXTRACT_SYSTEM, prompt, None, api_key, base_url, max_tokens=1600)
        out = (out or "").strip()
        if out and out.upper() != "NONE":
            facts.append(out)
    return "\n".join(facts)[:DISTILL_PER_DOC_CAP]


def build_analysis_context(artifacts, provider, model, api_key, base_url, vision, progress):
    blocks, images, notes = [], [], []
    total = 0
    for a in (artifacts or []):
        if a.get("is_image"):
            if vision and a.get("image_b64"):
                images.append({"b64": a["image_b64"], "media_type": a.get("media_type", "image/png")})
            else:
                notes.append(f"{a['filename']} (image) not sent — current model is not vision-capable.")
            continue
        for im in (a.get("extra_images") or []):
            if vision and len(images) < 24:
                images.append(im)
        t = (a.get("text_excerpt") or "").strip()
        if not t:
            continue
        if len(t) <= DISTILL_SMALL:
            block = t
        else:
            progress(f"Distilling {a['filename']} ({len(t):,} chars)…")
            block = distill_document(t, a["filename"], provider, model, api_key, base_url, progress)
            notes.append(f"{a['filename']}: full document processed via {len(_chunk_text(t))} sections (distilled).")
        if total + len(block) > DISTILL_TOTAL_CAP:
            block = block[:max(0, DISTILL_TOTAL_CAP - total)]
            notes.append(f"{a['filename']}: distilled context truncated to fit the model budget.")
        blocks.append(f"--- Artifact: {a['filename']} (type: {a.get('kind')}) ---\n{block}")
        total += len(block)
        if total >= DISTILL_TOTAL_CAP:
            break
    return "\n\n".join(blocks), images, notes


# =============================================================================
#  SECTION 5 — WEB RESEARCH (URL scrape + web search + distillation)
# =============================================================================
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
FETCH_MAX_BYTES = 8_000_000
FETCH_TIMEOUT = 45


def _ssl_ctx():
    ctx = ssl.create_default_context()
    return ctx


def _html_to_text(html):
    """Strip a web page to readable text using only the standard library."""
    h = html
    h = re.sub(r"(?is)<script.*?</script>", " ", h)
    h = re.sub(r"(?is)<style.*?</style>", " ", h)
    h = re.sub(r"(?is)<noscript.*?</noscript>", " ", h)
    h = re.sub(r"(?is)<head.*?</head>", " ", h)
    h = re.sub(r"(?is)<!--.*?-->", " ", h)
    h = re.sub(r"(?i)<(br|/p|/div|/li|/tr|/h[1-6])\s*>", "\n", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    h = _htmlmod.unescape(h)
    h = re.sub(r"[ \t\f\v]+", " ", h)
    h = re.sub(r"\n\s*\n\s*\n+", "\n\n", h)
    return h.strip()


def fetch_url(url, progress=None):
    """Fetch a URL and return extracted text. Handles HTML and PDF (stdlib).
    Returns {"url","title","text","bytes","error"}."""
    progress = progress or (lambda _m: None)
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    progress(f"Fetching {url} …")
    req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                 "Accept": "text/html,application/pdf,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT, context=_ssl_ctx()) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            raw = resp.read(FETCH_MAX_BYTES)
    except urllib.error.HTTPError as e:
        return {"url": url, "title": "", "text": "", "bytes": 0, "error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "title": "", "text": "", "bytes": 0, "error": str(e)[:160]}
    title = ""
    if "application/pdf" in ctype or url.lower().endswith(".pdf") or raw[:5] == b"%PDF-":
        text = _pdf_text_stdlib(raw)
        title = os.path.basename(urllib.parse.urlparse(url).path) or url
    else:
        try:
            html = raw.decode("utf-8", "replace")
        except Exception:
            html = raw.decode("latin-1", "replace")
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
        title = _htmlmod.unescape(m.group(1)).strip() if m else url
        text = _html_to_text(html)
    return {"url": url, "title": title[:160], "text": text[:MAX_TEXT], "bytes": len(raw), "error": ""}


WEB_RESEARCH_PROMPT = (
    "Search the web and research the product \"{q}\" for an ISA/IEC 62443-3-3 / 4-2 SL-3 security "
    "assessment. Find the vendor's official user manuals, datasheets, configuration/programming guides, and "
    "security/hardening guides, plus any security advisories. Summarize the SECURITY-RELEVANT facts as terse bullet "
    "lines: exact product/model & firmware/software versions; management interfaces & exact menu paths (web UI, "
    "engineering tool, CLI, config files, log locations); network interfaces, protocols and PORT NUMBERS; "
    "authentication/RBAC (accounts, default/hardcoded credentials, password policy, lockout, MFA, certificate/PKI); "
    "secure comms/crypto (TLS/DTLS, signed firmware, secure boot, tamper); logging/audit/NTP; backup/restore/"
    "firmware-update mechanisms; physical/diagnostic ports (USB/SD/JTAG/UART); hardening/least-functionality "
    "options; the vendor's OWN security/config tools; and any CVEs / vendor security notes. Cite the source URLs "
    "you used. Prefer official vendor documentation. If you cannot find something, say so rather than guessing.")


def _anthropic_web_research(base, key, model, query, progress):
    body = {"model": model, "max_tokens": 3500,
            "messages": [{"role": "user", "content": WEB_RESEARCH_PROMPT.format(q=query)}],
            "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 6}]}
    req = urllib.request.Request(f"{base}/messages", data=json.dumps(body).encode(),
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                                          "content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180, context=_ssl_ctx()) as r:
        d = json.loads(r.read().decode("utf-8", "replace"))
    text, sources = [], []
    for blk in d.get("content", []):
        t = blk.get("type")
        if t == "text" and blk.get("text"):
            text.append(blk["text"])
        elif t == "web_search_tool_result":
            for item in (blk.get("content") or []):
                if item.get("type") == "web_search_result" and item.get("url"):
                    sources.append({"title": item.get("title", ""), "url": item["url"], "via": "ai-search"})
    return "\n".join(text), sources


def _google_web_research(base, key, model, query, progress):
    body = {"contents": [{"role": "user", "parts": [{"text": WEB_RESEARCH_PROMPT.format(q=query)}]}],
            "tools": [{"google_search": {}}]}
    req = urllib.request.Request(f"{base}/models/{model}:generateContent?key={key}",
                                 data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180, context=_ssl_ctx()) as r:
        d = json.loads(r.read().decode("utf-8", "replace"))
    cands = d.get("candidates", [])
    if not cands:
        return "", []
    c0 = cands[0]
    text = "".join(p.get("text", "") for p in c0.get("content", {}).get("parts", []))
    sources = []
    for ch in (c0.get("groundingMetadata", {}) or {}).get("groundingChunks", []) or []:
        w = ch.get("web") or {}
        if w.get("uri"):
            sources.append({"title": w.get("title", ""), "url": w["uri"], "via": "ai-search"})
    return text, sources


def _openai_web_research(base, key, model, query, progress):
    for tool_type in ("web_search", "web_search_preview"):
        body = {"model": model, "tools": [{"type": tool_type}],
                "input": WEB_RESEARCH_PROMPT.format(q=query), "max_output_tokens": 3500}
        req = urllib.request.Request(f"{base}/responses", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {key}",
                                              "content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=180, context=_ssl_ctx()) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (400, 404):   # tool type / endpoint not supported — try the other variant
                continue
            raise
        text, sources = [], []
        if isinstance(d.get("output_text"), str) and d["output_text"].strip():
            text.append(d["output_text"])
        for item in (d.get("output") or []):
            if item.get("type") == "message":
                for c in (item.get("content") or []):
                    if c.get("type") in ("output_text", "text") and c.get("text"):
                        if c["text"] not in text:
                            text.append(c["text"])
                        for ann in (c.get("annotations") or []):
                            if ann.get("type") == "url_citation" and ann.get("url"):
                                sources.append({"title": ann.get("title", ""), "url": ann["url"], "via": "ai-search"})
        return "\n".join(text), sources
    return "", []


def ai_web_research(provider, model, api_key, base_url, query, progress):
    """Have the SELECTED AI model search the web itself, using ONLY its own API key
    (native web-search / grounding tools). Returns (findings_text, sources, note)."""
    progress = progress or (lambda _m: None)
    if not PROVIDER_WEB_SEARCH.get(provider):
        return "", [], (f"Live web search isn't available for the {provider} API; using the model's built-in "
                        "knowledge plus any URLs/files you provided.")
    try:
        kind, base, key = _resolve(provider, api_key, base_url)
    except ProviderError as e:
        return "", [], str(e)
    progress(f"The AI is searching the web about: {query}")
    try:
        if provider == "anthropic":
            text, sources = _anthropic_web_research(base, key, model, query, progress)
        elif provider == "google":
            text, sources = _google_web_research(base, key, model, query, progress)
        elif provider == "openai":
            text, sources = _openai_web_research(base, key, model, query, progress)
        else:
            return "", [], ""
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        return "", [], f"Web search via {provider} failed ({e.code}): {detail}. Continuing with model knowledge + your sources."
    except Exception as e:  # noqa: BLE001
        return "", [], f"Web search via {provider} could not run ({e}). Continuing with model knowledge + your sources."
    if not text.strip():
        return "", sources, "The model's web search returned no usable findings; using its knowledge + your sources."
    progress(f"AI web research complete ({len(sources)} source(s)).")
    return text.strip()[:DISTILL_PER_DOC_CAP], sources, ""


def gather_web_context(urls, do_search, research_query, provider, model, api_key, base_url, progress):
    """Fetch any pasted URLs AND (when enabled) let the AI model search the web itself
    with its own key. Distills large pages. Returns (context, notes, sources)."""
    progress = progress or (lambda _m: None)
    sources, fetched, blocks, notes, total = [], [], [], [], 0
    urls = [u.strip() for u in (urls or []) if u.strip()]

    # 1) The AI searches the web on its own (single model key does the work).
    if do_search and (research_query or "").strip():
        findings, ai_sources, note = ai_web_research(provider, model, api_key, base_url,
                                                     research_query.strip(), progress)
        if note:
            notes.append(note)
        for s in ai_sources:
            sources.append(s)
        if findings:
            blocks.append("--- AI web research (model searched the web) ---\n" + findings)
            total += len(findings)

    # 2) Fetch/scrape any URLs the user pasted (no key needed).
    for u in urls[:10]:
        r = fetch_url(u, progress)
        if r.get("error"):
            progress(f"Could not fetch {u}: {r['error']}")
            sources.append({"title": u, "url": u, "via": "url", "error": r["error"]})
            continue
        if not r.get("text", "").strip():
            progress(f"No readable text at {u}")
            continue
        sources.append({"title": r.get("title") or u, "url": u, "via": "url"})
        fetched.append(r)
    for r in fetched:
        t = r["text"]
        label = f"{r.get('title') or r['url']} <{r['url']}>"
        if len(t) <= DISTILL_SMALL:
            block = t
        else:
            progress(f"Distilling web page {r['url']} ({len(t):,} chars)…")
            block = distill_document(t, r.get("title") or r["url"], provider, model, api_key, base_url, progress)
            notes.append(f"{r['url']}: full page processed via {len(_chunk_text(t))} sections (distilled).")
        if total + len(block) > DISTILL_TOTAL_CAP:
            block = block[:max(0, DISTILL_TOTAL_CAP - total)]
        blocks.append(f"--- Web source: {label} ---\n{block}")
        total += len(block)
        if total >= DISTILL_TOTAL_CAP:
            break
    return "\n\n".join(blocks), notes, sources


# =============================================================================
#  SECTION 6 — PROMPTS + STRUCTURED SCHEMAS (classify + generate)
# =============================================================================
_ARR = {"type": "array", "items": {"type": "object"}}
_STRARR = {"type": "array", "items": {"type": "string"}}

# ---- Phase 1: component identification / type classification ----
CLASSIFY_SYSTEM = (
    "You are a Systems Security Engineer specializing in ISA/IEC 62443 assessments of ICS/OT/IoT "
    "products (PLC/PAC, RTU, IED/protective relay, DCS controller, VFD/drive, field instrument/sensor, "
    "power/energy meter, gateway, managed switch/firewall, SCADA/HMI software, historian, OPC server, "
    "OS/host). Given a component description plus any provided manuals/datasheets/web sources, identify "
    "the exact product and determine its ISA/IEC 62443-4-2 component type(s). The four component types are: "
    "EDR = Embedded Device (firmware-based device: PLC, IED, drive, meter, instrument, RTU); "
    "HDR = Host Device (general-purpose OS host: Windows/Linux server or workstation, appliance running a full OS); "
    "NDR = Network Device (switch, router, firewall, gateway, wireless AP, protocol converter); "
    "SAR = Software Application (software installed on a host: SCADA/HMI, historian, OPC server, engineering tool). "
    "A product can map to MORE THAN ONE type (e.g. a gateway that is both EDR and NDR). Base the determination "
    "on the product's actual nature and the evidence provided; never invent facts — mark unknowns as assumptions."
)

SCHEMA_CLASSIFY = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "vendor": {"type": "string"},
        "component_type_codes": {"type": "array", "items": {"type": "string", "enum": ["EDR", "HDR", "NDR", "SAR"]}},
        "component_type_label": {"type": "string"},
        "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
        "reasoning": {"type": "string"},
        "key_facts": _STRARR,
        "interfaces_ports": {"type": "string"},
        "firmware_or_version_note": {"type": "string"},
        "where_to_work": {"type": "string"},
        "suggested_sources": _STRARR,
        "assumptions": _STRARR,
    },
    "required": ["product", "component_type_codes", "component_type_label", "confidence", "reasoning", "key_facts"],
}
TOOL_CLASSIFY = {"name": "emit_component_classification",
                 "description": "Identify the product and its ISA/IEC 62443-4-2 component type(s).",
                 "schema": SCHEMA_CLASSIFY}


def build_classify_prompt(target, scope, artifact_ctx, web_ctx):
    parts = [f"# COMPONENT DESCRIPTION\n{target}"]
    if scope:
        parts.append(f"\n# SCOPE / NOTES\n{scope}")
    if artifact_ctx:
        parts.append(f"\n# UPLOADED DOCUMENTATION (extracted)\n{artifact_ctx}")
    if web_ctx:
        parts.append(f"\n# WEB SOURCES (scraped)\n{web_ctx}")
    parts.append(
        "\n# TASK\nIdentify the exact product (vendor, model, family, firmware/software version if known) and "
        "determine its ISA/IEC 62443-4-2 component type code(s): EDR, HDR, NDR, and/or SAR. Give a one-to-three "
        "sentence justification, list the concrete key facts you will build the checklist from (interfaces, ports, "
        "protocols, management tools, firmware/versions, auth model), a 'where_to_work' summary of the tools/UIs an "
        "assessor uses, and, if you are not confident, list suggested manual/datasheet URLs to add. Return ONLY the "
        "structured object.")
    return "\n".join(parts)


# ---- Phase 2: full SL-3 cheat sheet generation ----
CHECKLIST_SYSTEM = (
    "You are an independent ICS/OT assessment authority producing a product-specific ISA/IEC 62443-3-3 / 4-2 "
    "SL-3 TESTING CHEAT SHEET. Your output is a dense, practical, bench-usable field checklist. For EVERY "
    "foundational requirement (FR1–FR7), every applicable system requirement (SR) and component requirement (CR), "
    "and the component-type-specific requirements (EDR/HDR/NDR/SAR), you give (a) DETAILED step-by-step NATIVE "
    "configuration/verification steps in the product's own tools/menus, (b) the SPECIFIC EXTERNAL validation tools "
    "chosen for THIS product and THIS requirement, each with step-by-step usage, (c) the PASS criteria / evidence, "
    "and (d) product/firmware notes. Match SL-3 (protection against intentional misuse by skilled attackers with "
    "moderate resources).\n\n"
    "TOOL SELECTION — THINK, DON'T PARROT. This is the heart of the job. For each requirement you must REASON about "
    "which tools actually validate THAT control on THIS specific product, and select from the full landscape: (1) the "
    "vendor's OWN native tools/consoles/CLIs/config files/logs; (2) OPEN-SOURCE tools; (3) COMMERCIAL tools; and "
    "(4) any product- or protocol-specific tooling. Do NOT default every row to 'Nmap + Wireshark'. Pick the RIGHT "
    "tool for the RIGHT requirement — e.g. certificate/crypto checks -> openssl/testssl.sh/sslyze; protocol "
    "auth/read tests -> the correct protocol client (pycomm3/pylogix for CIP, python-snap7 for S7, pymodbus for "
    "Modbus, opcua/open62541 for OPC UA, libiec61850/GOOSE tools for IEC 61850, dnp3 tools for DNP3); lockout/"
    "brute-force -> Hydra/Medusa in an ISOLATED lab; fuzzing/input-validation -> boofuzz/Defensics/aegis (isolated); "
    "config/hardening baselines -> CIS-CAT/OpenSCAP/Lynis/Microsoft SCT; passive OT monitoring/inventory -> Claroty/"
    "Nozomi/Dragos/Forescout/Tenable.ot; read-only host/interface enumeration -> the asset owner's ReadOnlyEnum.py. "
    "The embedded TOOL PALETTE in the prompt is a SEED, not a limit — you are EXPECTED to add other appropriate open-"
    "source/commercial/vendor tools, INCLUDING ones you find by researching this product's documentation and the web. "
    "For every external tool you name, give the actual command/flags or the click-path to run it.\n\n"
    "WRITING STYLE — MATCH THE HAND-AUTHORED SAMPLES (concise + bold, NOT verbose). The 'verify' cell is a tight, "
    "scannable how-to like the sample cheat sheets: 1-3 sentences giving the exact native menu path and the setting/"
    "action (optionally a short '**Test:**' action), then '**Ext. tools:**' on its own naming the specific tool(s) "
    "with a brief command/flag or click-path. Do NOT write long 'Native steps: 1) 2) 3) 4)' paragraphs — write dense "
    "prose exactly like the samples. Use **double-asterisk bold** for the key UI terms, settings, menu paths, "
    "protocol/port names, and the '**Test:**' and '**Ext. tools:**' leads, so cells read with clear visual hierarchy. "
    "Reference real ports, protocols, tool names, and versions.\n\n"
    "OTHER STYLE RULES — mirror the sample sheets:\n"
    "• 'pass' = the crisp, testable pass criterion / evidence to capture.\n"
    "• 'notes' = product/firmware/version caveat, or 'Compensating', 'Partial + compensating', 'EDR-specific', etc.\n"
    "• Where the product cannot meet a control itself, give the compensating control step-by-step (enforce at host/"
    "EWS, network segmentation, upstream IdP/AD) and mark it Partial/Compensating — never merely 'not supported'.\n"
    "• Non-applicable requirements (e.g. Wireless 1.6/2.2 on a wired-only device; person-to-person 5.3; application "
    "partitioning 5.4 on a single-purpose device; emergency power 7.5 at facility level): verify = one-line "
    "justification, pass = 'N/A - justification recorded (not assessed as a control)', notes = 'N/A'.\n"
    "• Req id labels: 'SR/CR x.y' when both apply; else 'SR x.y' / 'CR x.y'; component rows 'EDR/HDR/NDR/SAR x.y'; "
    "an augmenting component row may read e.g. 'SR/CR 1.13 (+ NDR 1.13)'.\n"
    "• Ground EVERYTHING in the real product (real tool names — Studio 5000, DIGSI 5, EcoStruxure, TIA Portal, SEL "
    "AcSELerator, Gateway web UI — real ports, protocols, firmware requirements). Never fabricate a datasheet fact; "
    "state assumptions explicitly in notes.\n\n"
    "EXTERNAL TEST TOOLS TABLE. Build it from the tools you actually used across the rows: for each, give what it "
    "verifies (with the requirement numbers), step-by-step how-to (real commands/flags/click-paths), and its "
    "constraints (e.g. 'ISOLATED/lab only', 'passive SPAN/tap', 'read-only', 'authorized maintenance window'). "
    "Include the vendor-native tools, the open-source and commercial tools you chose, and ReadOnlyEnum.py when host/"
    "interface enumeration applies. Add any product-specific tools you identified from the documentation or research."
)

# Compressed style exemplar (drawn from a real EDR cheat sheet) so the model matches voice/structure.
STYLE_EXEMPLAR = """EXAMPLE STYLE (an EDR PLC — match this density, voice, and column usage):
product: "Rockwell Automation Allen-Bradley ControlLogix 5580 (1756-L8x)"
component_type_label: "Embedded Device (EDR) - PLC/PAC"
preamble:
  - Where to work: "Studio 5000 Logix Designer (project .ACD; Controller Properties › Security). FactoryTalk Administration Console & Security. FactoryTalk Policy Manager + System Services (CIP Security CA). Controller keyswitch RUN/REM/PROG; SD card; embedded Ethernet web page."
  - Interfaces / ports: "EtherNet/IP explicit TCP 44818; CIP class-1 I/O UDP 2222; CIP Security 2221 (DTLS); embedded web 80/443; SNMP 161."
  - Firmware note: "CIP Security requires controller firmware v31/32+, Studio 5000 v32+, FactoryTalk System Services (CA) + Policy Manager."
  - How to read: "Default read-only. Each row = native how-to + external-tool validation + pass criteria. Write/exploit tools = isolated/representative env + written authorization."
row SR/CR 1.1 (Human user I&A): verify="In **Studio 5000 › Controller Properties › Security** set **Security Authority** to the FactoryTalk Security server (with **SNN**, 'bind to authority') and require authentication; assign **Permission Sets** so only authorized FT users can go online/download/edit. In **FactoryTalk Administration Console** confirm named/Windows-linked accounts (no shared). **Test:** attempt online/download as an unauthorized FT user -> denied. **Ext. tools:** FactoryTalk Admin Console (user/policy review); RSLinx/FactoryTalk Linx **Who Active** (enumerate access paths); **ReadOnlyEnum.py** (confirm no anonymous CIP)." pass="All engineering access requires FT authentication; unauthorized users denied; no anonymous CIP path." notes="Needs FactoryTalk Security bound. Controller-local only = **Partial + compensating** (segmentation + CIP Security)."
row SR/CR 1.9 (Strength of public key auth): verify="In **FactoryTalk Policy Manager** confirm the CIP Security device cert uses strong keys (**ECC / RSA>=2048**) and is in-date. **Ext. tools:** **openssl** ('openssl s_client -connect <plc>:2221 -dtls1_2 | openssl x509 -noout -dates -issuer') or **testssl.sh** to confirm suite/expiry; **sslyze --certinfo <plc>:2221**." pass="Strong certificate crypto; weak/expired certs absent (openssl/testssl output attached)." notes="**FW v32+** / CIP Security."
row SR/CR 1.6 (Wireless access mgmt): verify="**N/A.** No wireless interface on this device; wireless access is managed at the network layer." pass="N/A - justification recorded (not assessed as a control)." notes="N/A"
row EDR 3.11 (Physical tamper resistance/detection): verify="Set the **keyswitch to RUN** in production (blocks remote program/mode change); keep the controller in a **locked, sealed enclosure**; secure/remove the **SD card**. The **Controller Log** records keyswitch/mode changes as tamper evidence. **Ext. tools:** physical inspection/photos; **Controller Log** export (keyswitch/mode events)." pass="Keyswitch in RUN; enclosure locked/sealed; SD secured; changes logged." notes="EDR-specific."
external tool row: tool="Nmap (EtherNet/IP NSE)" verifies="Port/service exposure & segmentation (1.13, 5.1, 5.2, 7.7)" how="1) nmap -sT -p 44818,2222,80,443,161 -T2 <plc>; 2) nmap --script enip-info -p 44818 <plc>; 3) repeat FROM each zone/VLAN to prove segmentation (a blocked port = pass from an untrusted zone)." constraints="Tune timing (-T2) on production; authorized."
external tool row: tool="openssl / testssl.sh" verifies="CIP Security certificate & cipher strength (1.5, 1.8, 1.9, 4.3)" how="1) openssl s_client -connect <plc>:2221 -dtls1_2; 2) pipe to 'openssl x509 -noout -dates -issuer -text' for key/algorithm/expiry; 3) testssl.sh --full <plc>:2221 for suite/protocol grading." constraints="Read-only."
external tool row: tool="ReadOnlyEnum.py" verifies="Read-only host/interface/service enumeration (2.13, 7.7, 7.8)" how="1) python3 ReadOnlyEnum.py --target <plc> to enumerate exposed services/ports/interfaces without writing; 2) export results into the component inventory and least-functionality evidence." constraints="Needs read access; strictly read-only."
external tool row: tool="pycomm3 / pylogix" verifies="Unauthenticated-CIP test (1.2, 3.1)" how="1) from an un-provisioned client run a pycomm3 LogixDriver read against the controller; 2) with CIP Security enforced the connection/read must be REFUSED (a success = finding)." constraints="ISOLATED/representative env; written authorization."
footer: "Controlled - Project Use · Independent Assurance Authority · ISA/IEC 62443-3-3 / 4-2 · Product-specific companion to the 62443 assessment tool; confirm exact menu paths / CLI against the deployed firmware and the project hardening baseline. ISOLATED tools run only in a representative/lab environment with written authorization."
"""

SCHEMA_CHECKLIST = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "component_type_label": {"type": "string"},
        "component_type_codes": {"type": "array", "items": {"type": "string"}},
        "target_sl": {"type": "string"},
        "col_verify_header": {"type": "string"},
        "col_notes_header": {"type": "string"},
        "preamble": {"type": "array", "items": {"type": "object", "properties": {
            "label": {"type": "string"}, "text": {"type": "string"}}, "required": ["label", "text"]}},
        "foundational_requirements": {"type": "array", "items": {"type": "object", "properties": {
            "fr": {"type": "string"}, "title": {"type": "string"},
            "rows": {"type": "array", "items": {"type": "object", "properties": {
                "req_id": {"type": "string"}, "requirement": {"type": "string"},
                "verify": {"type": "string"}, "pass": {"type": "string"}, "notes": {"type": "string"}},
                "required": ["req_id", "requirement", "verify", "pass"]}}},
            "required": ["fr", "title", "rows"]}},
        "external_tools": {"type": "array", "items": {"type": "object", "properties": {
            "tool": {"type": "string"}, "verifies": {"type": "string"},
            "how": {"type": "string"}, "constraints": {"type": "string"}},
            "required": ["tool", "verifies", "how"]}},
        "footer": {"type": "string"},
    },
    "required": ["product", "component_type_label", "component_type_codes", "target_sl",
                 "col_verify_header", "col_notes_header", "preamble",
                 "foundational_requirements", "external_tools"],
}
TOOL_CHECKLIST = {"name": "emit_sl3_checklist",
                  "description": "Return the COMPLETE ISA/IEC 62443-3-3/4-2 SL-3 testing cheat sheet. Every FR (FR1–FR7) present; every required SR/CR row and every component-specific row populated with native steps + Ext. tools, pass criteria, and notes.",
                  "schema": SCHEMA_CHECKLIST}

DEFAULT_FOOTER = ("Controlled - Project Use · Independent Assurance Authority · ISA/IEC 62443-3-3 / 4-2 · "
                  "Product-specific companion to the 62443 assessment tool; confirm exact menu paths / CLI against "
                  "the deployed firmware and the project hardening baseline. ISOLATED tools run only in a "
                  "representative/lab environment with written authorization.")


def build_requirement_skeleton(codes):
    """Explicit list of every requirement row the model MUST produce, grouped by FR,
    so no SR/CR or component-specific requirement is dropped."""
    by_fr = rows_by_fr(codes)
    L = []
    for fr in FR_ORDER:
        rows = by_fr.get(fr, [])
        if not rows:
            continue
        L.append(f"{fr} — {FR_TITLES[fr]}")
        for label, name, summ in rows:
            L.append(f"  {label} | {name} — {summ}")
    return "\n".join(L)


TOOL_PALETTE = """SEED TOOL PALETTE — NON-EXHAUSTIVE. Choose per product AND per requirement; add others you know or find by research. Do NOT limit yourself to this list, and do NOT default every row to Nmap/Wireshark.
[Vendor-native (examples — use the ones that fit the real product)] Rockwell Studio 5000 / FactoryTalk Admin Console / Policy Manager + System Services / AssetCentre / ControlFLASH Plus / RSLinx-FactoryTalk Linx (Who Active); Siemens TIA Portal / DIGSI 5 / SINEC / S7 web server; Schneider EcoStruxure Control Expert / EcoStruxure Security Admin / SoMachine; SEL AcSELerator QuickSet/RTAC; Emerson/GE tooling; Inductive Ignition Gateway web UI + Designer; OPC UA server config; device embedded web UI / CLI / SNMP agent / syslog config / config-file & log review.
[Network & exposure] Nmap + ICS NSE scripts (enip-info, s7-info, modicon-info, bacnet), PLCScan, Redpoint, s7scan; masscan; PortQry/TCPing; Wireshark/tcpdump/tshark, Zeek; SPAN/tap capture.
[Certificates & crypto] openssl (s_client, x509), testssl.sh, sslyze, nmap ssl-enum-ciphers.
[Protocol clients / auth & read tests] pycomm3 / pylogix (CIP/EtherNet-IP), python-snap7 (S7comm), pymodbus / modpoll (Modbus), opcua-client / open62541 / UaExpert (OPC UA), libiec61850 / IEDScout / GOOSE tools (IEC 61850 MMS/GOOSE/SV), dnp3 (opendnp3), HART/WirelessHART tools.
[Auth / lockout / brute — ISOLATED, authorized only] Hydra, Medusa, ncrack, CrackMapExec (for host/AD).
[Fuzzing / input validation — ISOLATED only] boofuzz, Sulley/Peach, aegis, Synopsys Defensics, ISASecure test suites, Wycheproof (crypto).
[Config / hardening baselines & audit] CIS-CAT Pro, OpenSCAP/SCAP, Lynis, Microsoft Security Compliance Toolkit / secpol / GPO, PowerShell/AuditPol, chkrootkit, osquery.
[Passive OT monitoring, inventory & vuln] Claroty, Nozomi Guardian, Dragos, Forescout/SilentDefense, Tenable.ot/Nessus, Industrial Defender, Microsoft Defender for IoT; SIEM/syslog (Splunk, Elastic, Wazuh), nc -lu 514.
[Read-only host/network/interface enumeration] ReadOnlyEnum.py (asset-owner tool) — run read-only to enumerate exposed services/ports/interfaces for inventory and least-functionality checks.
[Exploit validation as authorized] Kali / Metasploit ICS modules, vendor advisories/CVE cross-check (ICS-CERT, vendor PSIRT) — mirror/lab with written authorization only.
[Backup/DR & integrity] vendor DR (e.g. AssetCentre DR), sha256sum/hashing, config-diff/baseline-compare tools."""


def build_checklist_prompt(target, scope, classification, artifact_ctx, web_ctx, sources):
    codes = classification.get("component_type_codes") or ["EDR"]
    skeleton = build_requirement_skeleton(codes)
    parts = [f"# IN-SCOPE PRODUCT\n{classification.get('product') or target}"]
    parts.append(f"\n# CONFIRMED COMPONENT TYPE(S)\n{', '.join(codes)} — {classification.get('component_type_label','')}")
    if scope:
        parts.append(f"\n# SCOPE / NOTES\n{scope}")
    kf = classification.get("key_facts") or []
    if kf:
        parts.append("\n# KEY PRODUCT FACTS (from identification)\n" + "\n".join(f"- {k}" for k in kf))
    for fld, lbl in (("interfaces_ports", "Interfaces / ports"), ("firmware_or_version_note", "Firmware / version note"),
                     ("where_to_work", "Where to work")):
        if classification.get(fld):
            parts.append(f"\n# {lbl.upper()}\n{classification[fld]}")
    if artifact_ctx:
        parts.append(f"\n# UPLOADED DOCUMENTATION (extracted)\n{artifact_ctx}")
    if web_ctx:
        parts.append(f"\n# WEB SOURCES (scraped)\n{web_ctx}")
    parts.append("\n# REQUIREMENT COVERAGE — YOU MUST PRODUCE ONE ROW FOR EVERY LINE BELOW\n"
                 "(Use the sheet id convention: pair SR x.y + CR x.y as 'SR/CR x.y'; keep component rows as "
                 "EDR/HDR/NDR/SAR x.y. Group rows under their FR. Do not skip any line; use N/A justifications where "
                 "a control genuinely does not apply.)\n" + skeleton)
    parts.append("\n# PREAMBLE ROWS TO PRODUCE (adapt labels to the product)\n"
                 "Produce 3–4 preamble rows: 'Where to work' (the tools/UIs/consoles + key file/log locations), "
                 "'Interfaces / ports' (protocols + port numbers), a product-appropriate firmware/version row "
                 "(label it 'Firmware note' for devices or e.g. 'Version notes' / 'x.y vs a.b' for software), and "
                 "'How to read'.")
    parts.append("\n# COLUMN HEADERS\nSet col_verify_header to a product-appropriate phrasing of "
                 "'Where & how to verify (native steps + Ext. tools)' (e.g. 'Where & how to verify in <Product>'). "
                 "Set col_notes_header to 'Notes / firmware' for devices, or a version-specific label for software.")
    parts.append("\n# " + TOOL_PALETTE)
    parts.append("\n# TOOL RESEARCH\nBefore writing, use the product documentation and any web sources above to "
                 "identify the RIGHT validating tools for THIS product — vendor-native first, then the open-source/"
                 "commercial tools that actually apply to each requirement and this product's protocols. If the "
                 "sources mention product-specific utilities, protocol tools, or vendor security guides, prefer and "
                 "cite them. Map a DIFFERENT, appropriate toolset to each requirement — not the same one or two tools "
                 "everywhere.")
    parts.append(f"\n# FOOTER\nUse exactly this footer text unless the product demands a tweak:\n{DEFAULT_FOOTER}")
    parts.append("\n" + STYLE_EXEMPLAR)
    parts.append("\n# TASK\nProduce the COMPLETE SL-3 cheat sheet as the structured object. Every FR present; every "
                 "requirement line above becomes a row. Each 'verify' cell MUST contain NUMBERED step-by-step native "
                 "configuration/verification steps ('Native steps: 1) … 2) …' with real menu paths/settings) FOLLOWED "
                 "by 'Ext. tools:' with the SPECIFIC tools chosen for that requirement and the exact command/flags or "
                 "click-path to run each. Select tools per requirement (do not repeat Nmap/Wireshark everywhere). "
                 "Build the External Test Tools table from the tools you actually used (native + open-source + "
                 "commercial + ReadOnlyEnum.py where relevant), each with step-by-step usage and constraints. Match "
                 "the example's density and voice. Target SL = SL 3.")
    return "\n".join(parts)


# ---- Staged generation schemas (header, one FR at a time, tools) ----
SCHEMA_HEADER = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "component_type_label": {"type": "string"},
        "target_sl": {"type": "string"},
        "col_verify_header": {"type": "string"},
        "col_notes_header": {"type": "string"},
        "preamble": {"type": "array", "items": {"type": "object", "properties": {
            "label": {"type": "string"}, "text": {"type": "string"}}, "required": ["label", "text"]}},
        "footer": {"type": "string"},
    },
    "required": ["product", "preamble"],
}
TOOL_HEADER = {"name": "emit_sheet_header",
               "description": "Return the cheat-sheet header: product, component-type label, column headers, and the 3-4 preamble rows.",
               "schema": SCHEMA_HEADER}

_ROW_SCHEMA = {"type": "object", "properties": {
    "req_id": {"type": "string"}, "requirement": {"type": "string"},
    "verify": {"type": "string"}, "pass": {"type": "string"}, "notes": {"type": "string"}},
    "required": ["req_id", "requirement", "verify", "pass"]}
SCHEMA_FR_ROWS = {"type": "object", "properties": {"rows": {"type": "array", "items": _ROW_SCHEMA}},
                  "required": ["rows"]}
TOOL_FR = {"name": "emit_fr_rows",
           "description": "Return one row for EVERY listed requirement in this Foundational Requirement, each with numbered native steps + Ext. tools, pass criteria, and notes.",
           "schema": SCHEMA_FR_ROWS}

SCHEMA_TOOLS = {"type": "object", "properties": {"external_tools": {"type": "array", "items": {"type": "object",
    "properties": {"tool": {"type": "string"}, "verifies": {"type": "string"},
                   "how": {"type": "string"}, "constraints": {"type": "string"}},
    "required": ["tool", "verifies", "how"]}}}, "required": ["external_tools"]}
TOOL_TOOLS = {"name": "emit_external_tools",
              "description": "Return the External Test Tools table: each tool used across the rows with what it verifies (req numbers), step-by-step how-to, and constraints.",
              "schema": SCHEMA_TOOLS}


def build_shared_context(target, scope, classification, artifact_ctx, web_ctx, cap=55000):
    """Compact product/context block reused by every staged call."""
    parts = [f"PRODUCT: {classification.get('product') or target}"]
    codes = classification.get("component_type_codes") or ["EDR"]
    parts.append(f"COMPONENT TYPE(S): {', '.join(codes)} — {classification.get('component_type_label','')}")
    if scope:
        parts.append(f"SCOPE/NOTES: {scope}")
    kf = classification.get("key_facts") or []
    if kf:
        parts.append("KEY PRODUCT FACTS:\n" + "\n".join(f"- {k}" for k in kf))
    for fld, lbl in (("interfaces_ports", "Interfaces/ports"),
                     ("firmware_or_version_note", "Firmware/version note"),
                     ("where_to_work", "Where to work")):
        if classification.get(fld):
            parts.append(f"{lbl}: {classification[fld]}")
    doc = ""
    if artifact_ctx:
        doc += "\n# UPLOADED DOCUMENTATION (extracted)\n" + artifact_ctx
    if web_ctx:
        doc += "\n# WEB RESEARCH / SOURCES\n" + web_ctx
    if doc:
        parts.append(doc[:cap] + ("\n[context truncated to fit]" if len(doc) > cap else ""))
    return "\n".join(parts)


_COMPACT_STYLE = (
    "WRITING STYLE — match the hand-authored sample cheat sheets EXACTLY (concise, scannable, NOT verbose):\n"
    "• 'verify' = 1-3 TIGHT sentences of native how-to in the product's own tools — the exact menu path and the "
    "setting/action — optionally a short '**Test:**' action. Then, on its own, '**Ext. tools:**' naming the SPECIFIC "
    "tool(s) for THIS requirement with a brief command/flag or click-path. Do NOT write long 'Native steps: 1) 2) 3) "
    "4)' paragraphs — write it like the samples: dense prose, not a numbered essay.\n"
    "• Use **double-asterisk bold** for the key UI terms, settings, menu paths, protocol/port names, and the leads "
    "'**Test:**' and '**Ext. tools:**' (exactly like the samples bold their key terms). Keep each cell short.\n"
    "• Choose DIFFERENT tools per requirement (never default to Nmap/Wireshark everywhere): vendor-native first, then "
    "the right open-source/commercial tool — openssl/testssl.sh for certs; the matching protocol client (pymodbus, "
    "HART/WirelessHART DTM/handheld, pycomm3, python-snap7, OPC UA, IEC 61850, DNP3) for auth/read tests; Hydra/Medusa "
    "for lockout (isolated); fuzzers for input validation (isolated); CIS-CAT/OpenSCAP/Lynis for hardening; Claroty/"
    "Nozomi/Dragos/Tenable.ot for monitoring; ReadOnlyEnum.py for read-only enumeration.\n"
    "• 'pass' = one crisp testable criterion/evidence. 'notes' = firmware/version caveat or Compensating/Partial/N-A.\n"
    "• DECIDE APPLICABILITY FROM THE PRODUCT FACTS/MANUAL ABOVE. If the manual/datasheet shows a control does not "
    "apply to THIS product (e.g. no wireless on a wired-only device; no local user database; single-purpose device "
    "with no partitioning; power handled at facility level), set verify to a one-line '**N/A.** <why, referencing the "
    "product>' justification, pass = 'N/A - justification recorded (not assessed as a control)', notes = 'N/A'. Where "
    "the device itself can't meet a control but a gateway/host/EWS can, give that compensating control concisely and "
    "mark notes 'Compensating' or 'Partial + compensating'.\n"
    "• Req id convention: 'SR/CR x.y' when both apply; else 'SR x.y'/'CR x.y'; component rows 'EDR/HDR/NDR/SAR x.y'.")


def _rev_block(revision, current):
    if not revision:
        return ""
    b = "\n\n# REVISION — APPLY THIS CHANGE\n" + revision + ("\nPreserve correct existing content the change does "
         "not touch; keep the same style.")
    if current is not None:
        b += "\n# CURRENT CONTENT (revise this)\n" + json.dumps(current)[:14000]
    return b


def build_header_prompt(shared, revision=None, current=None):
    return (shared + "\n\n# TASK\nReturn the cheat-sheet HEADER only. Provide: product (full name/model), "
            "component_type_label, target_sl='SL 3', col_verify_header (e.g. 'Where & how to verify (native steps + "
            "Ext. tools)' or 'Where & how to verify in <Product>'), col_notes_header ('Notes / firmware' for devices; "
            "a version label for software), and 3-4 preamble rows: 'Where to work' (tools/UIs/consoles + key file/log "
            "locations), 'Interfaces / ports' (protocols + port numbers), a firmware/version row, and 'How to read'. "
            "Ground every value in the product facts above; state assumptions rather than inventing specifics."
            + _rev_block(revision, current))


def build_fr_prompt(fr_code, shared, codes, revision=None, current_rows=None):
    title = FR_TITLES[fr_code]
    by_fr = rows_by_fr(codes or ["EDR"])
    skel = by_fr.get(fr_code, [])
    lines = "\n".join(f"  {label} | {name} — {summ}" for label, name, summ in skel)
    return (shared + f"\n\n# FOUNDATIONAL REQUIREMENT TO PRODUCE NOW: {fr_code[:2]} {fr_code[2:]} — {title}\n"
            "Produce ONE row for EVERY requirement listed below (do not skip any):\n" + lines +
            "\n\n" + _COMPACT_STYLE + _rev_block(revision, current_rows) +
            "\n\n# TASK\nReturn ONLY the rows for this Foundational Requirement as {\"rows\":[...]}. Every listed "
            "requirement above must appear exactly once, in order, grounded in the product facts.")


def build_tools_prompt(shared, rows_digest, revision=None, current_tools=None):
    return (shared + "\n\n# TOOLS ACTUALLY REFERENCED ACROSS THE ROWS (build the table from these + any you used)\n"
            + rows_digest[:12000] +
            "\n\n" + TOOL_PALETTE + _rev_block(revision, current_tools) +
            "\n\n# TASK\nReturn the External Test Tools table as {\"external_tools\":[...]}: 8-16 entries covering the "
            "vendor-native tools, the open-source and commercial tools, and ReadOnlyEnum.py where host/interface "
            "enumeration applies. For each: 'tool' (name), 'verifies' (what + the requirement numbers, e.g. "
            "'(1.5, 4.3)'), 'how' (concise commands/flags or click-path), and 'constraints' "
            "(e.g. 'ISOLATED/lab only', 'passive SPAN/tap', 'read-only', 'authorized window'). Include only tools that "
            "actually apply to THIS product's interfaces/protocols.")


REFINE_SYSTEM = CHECKLIST_SYSTEM + (
    "\n\nYou are now REVISING an existing SL-3 cheat sheet. Apply the user's requested change and return the "
    "COMPLETE updated sheet (same structure, every FR and all required rows). Preserve correct existing content "
    "the change does not touch.")


def build_refine_prompt(current, instruction):
    parts = ["# CURRENT SL-3 CHEAT SHEET (JSON)\n" + json.dumps(current)[:70000]]
    parts.append("\n# REQUESTED CHANGE\n" + instruction)
    parts.append("\n# TASK\nReturn the COMPLETE updated cheat sheet reflecting the change, as the structured object.")
    return "\n".join(parts)


# ---- generation wrappers with graceful image + completeness retries ----
def _gen_structured(provider, model, system, user, tool, images, api_key, base_url, max_tokens):
    try:
        return call_model_json(provider, model, system, user, tool, images, api_key, base_url, max_tokens)
    except ProviderError as e:
        if images and _is_image_error(e):
            return call_model_json(provider, model, system, user, tool, None, api_key, base_url, max_tokens)
        raise


def generate_classification(provider, model, user, images, api_key, base_url, max_tokens=4000):
    data = _gen_structured(provider, model, CLASSIFY_SYSTEM, user, TOOL_CLASSIFY, images,
                           api_key, base_url, max_tokens)
    codes = [c for c in (data.get("component_type_codes") or []) if c in COMPONENT_TYPES]
    if not codes:
        codes = ["EDR"]
    data["component_type_codes"] = codes
    if not data.get("component_type_label"):
        data["component_type_label"] = " + ".join(COMPONENT_TYPES[c] for c in codes)
    return data


def _checklist_present_frs(rep):
    got = set()
    for fr in (rep.get("foundational_requirements") or []):
        key = (fr.get("fr") or "").upper().replace(" ", "")
        for f in FR_ORDER:
            if key.startswith(f):
                got.add(f)
    return got


def checklist_missing(rep):
    """Return list of problems: missing FRs or empty sections."""
    problems = []
    if not isinstance(rep, dict):
        return ["not-an-object"]
    if not rep.get("foundational_requirements"):
        return ["foundational_requirements"]
    got = _checklist_present_frs(rep)
    for f in FR_ORDER:
        if f not in got:
            problems.append(f)
    if not rep.get("external_tools"):
        problems.append("external_tools")
    if not rep.get("preamble"):
        problems.append("preamble")
    return problems


def generate_checklist(provider, model, user, images, api_key, base_url, max_tokens=20000):
    rep = _gen_structured(provider, model, CHECKLIST_SYSTEM, user, TOOL_CHECKLIST, images,
                          api_key, base_url, max_tokens)
    miss = checklist_missing(rep)
    if miss:
        aug = user + ("\n\n# COMPLETENESS FIX\nYour previous output was INCOMPLETE (missing/empty: "
                      + ", ".join(miss) + "). Regenerate the COMPLETE cheat sheet now: FR1 through FR7 all "
                      "present, every required SR/CR and component row populated, plus the External Test Tools "
                      "table and the preamble rows. Do not omit anything.")
        try:
            rep2 = _gen_structured(provider, model, CHECKLIST_SYSTEM, aug, TOOL_CHECKLIST, images,
                                   api_key, base_url, max_tokens)
            if len(checklist_missing(rep2)) < len(miss):
                rep = rep2
        except (ProviderError, ValueError):
            pass
    return normalize_checklist(rep)


def normalize_checklist(rep):
    """Fill defaults and order FRs so the PDF renderer always has clean input."""
    if not isinstance(rep, dict):
        rep = {}
    rep.setdefault("target_sl", "SL 3")
    rep.setdefault("col_verify_header", "Where & how to verify (native steps + Ext. tools)")
    rep.setdefault("col_notes_header", "Notes / firmware")
    rep.setdefault("footer", DEFAULT_FOOTER)
    rep.setdefault("preamble", [])
    rep.setdefault("external_tools", [])
    frs = rep.get("foundational_requirements") or []
    def frkey(fr):
        k = (fr.get("fr") or "").upper().replace(" ", "")
        for i, f in enumerate(FR_ORDER):
            if k.startswith(f):
                return i
        return 99
    rep["foundational_requirements"] = sorted(frs, key=frkey)
    return rep


# Provider errors that will affect EVERY call (billing/credits, auth, rate-limit):
# surface these immediately with their real message so the user can fix and Retry,
# instead of masking them as an empty result.
_FATAL_ERR_RE = re.compile(
    r"credit|billing|quota|insufficient|payment|too low|unauthorized|invalid.*api|api.*key|"
    r"permission|\b401\b|\b403\b|\b429\b|rate.?limit|overloaded|\b529\b|exceeded", re.I)


def _raise_if_fatal(e):
    if isinstance(e, ProviderError) and _FATAL_ERR_RE.search(str(e)):
        raise e


def _gen_fr_rows(provider, model, shared, fr_code, codes, api_key, base_url, progress,
                 revision=None, current_rows=None):
    """Generate rows for a single Foundational Requirement, with one retry.
    Fatal provider errors (billing/auth/rate-limit) propagate so the user sees the
    real reason and can retry after fixing it."""
    prompt = build_fr_prompt(fr_code, shared, codes, revision, current_rows)
    for attempt in (1, 2):
        try:
            out = _gen_structured(provider, model, CHECKLIST_SYSTEM, prompt, TOOL_FR, None,
                                  api_key, base_url, 7000)
            rows = out.get("rows") if isinstance(out, dict) else None
            if rows:
                return rows
        except (ProviderError, ValueError) as e:
            _raise_if_fatal(e)
            if attempt == 2:
                progress(f"  {fr_code[:2]} {fr_code[2:]}: could not generate ({str(e)[:80]}).")
        if attempt == 1:
            progress(f"  {fr_code[:2]} {fr_code[2:]}: retrying…")
    return []


def _covered_numbers(rows):
    nums = set()
    for r in (rows or []):
        for m in re.findall(r"\d+\.\d+", r.get("req_id", "") or ""):
            nums.add(m)
    return nums


def _missing_skeleton(skel, rows):
    """Skeleton entries whose x.y number appears in no returned row."""
    have = _covered_numbers(rows)
    out = []
    for label, name, summ in skel:
        m = re.search(r"\d+\.\d+", label)
        if m and m.group(0) not in have:
            out.append((label, name, summ))
    return out


def _backfill_missing(provider, model, shared, fr_code, missing, api_key, base_url, progress):
    """Ask once more for ONLY the requirement rows that were dropped, so coverage is complete."""
    lines = "\n".join(f"  {label} | {name} — {summ}" for label, name, summ in missing)
    prompt = (shared + f"\n\n# FILL MISSING ROWS for {fr_code[:2]} {fr_code[2:]} — {FR_TITLES[fr_code]}\n"
              "Your previous output SKIPPED these requirements. Produce ONE row for EACH, same format:\n" + lines +
              "\n\n" + _COMPACT_STYLE +
              "\n\n# TASK\nReturn ONLY {\"rows\":[...]} for the missing requirements above, grounded in the product facts.")
    try:
        out = _gen_structured(provider, model, CHECKLIST_SYSTEM, prompt, TOOL_FR, None, api_key, base_url, 5000)
        return out.get("rows") or [] if isinstance(out, dict) else []
    except (ProviderError, ValueError) as e:
        _raise_if_fatal(e)
        return []


def _cur_fr_rows(current, fr_code):
    if not current:
        return None
    for fr in (current.get("foundational_requirements") or []):
        if (fr.get("fr") or "").upper().replace(" ", "").startswith(fr_code):
            return fr.get("rows")
    return None


def generate_checklist_streamed(provider, model, classification, target, scope,
                                artifact_ctx, web_ctx, api_key, base_url, progress,
                                revision=None, current=None):
    """Generate (or REVISE, when revision is set) the sheet in stages (header -> each
    FR -> tools), emitting progress for each stage. Robust and streamed. Returns
    (rep, total_rows)."""
    progress = progress or (lambda _m: None)
    codes = classification.get("component_type_codes") or ["EDR"]
    shared = build_shared_context(target, scope, classification, artifact_ctx, web_ctx)
    verb = "Revising" if revision else "Setting up"

    # 1) Header + preamble
    progress(f"{verb} the sheet header, columns, and preamble…")
    rep = {}
    try:
        rep = _gen_structured(provider, model, CHECKLIST_SYSTEM,
                              build_header_prompt(shared, revision,
                                                  {k: current.get(k) for k in ("product", "component_type_label",
                                                   "target_sl", "col_verify_header", "col_notes_header", "preamble")}
                                                  if current else None),
                              TOOL_HEADER, None, api_key, base_url, 3500) or {}
    except (ProviderError, ValueError) as e:
        _raise_if_fatal(e)   # billing/auth/rate-limit -> surface the real reason now
        progress(f"Header step fell back to defaults ({str(e)[:60]}).")
        rep = {}
    rep["product"] = rep.get("product") or classification.get("product") or target
    rep["component_type_label"] = classification.get("component_type_label") or rep.get("component_type_label", "")
    rep["component_type_codes"] = codes
    rep.setdefault("target_sl", "SL 3")
    rep.setdefault("col_verify_header", "Where & how to verify (native steps + Ext. tools)")
    rep.setdefault("col_notes_header", "Notes / firmware")
    rep.setdefault("footer", DEFAULT_FOOTER)
    rep.setdefault("preamble", [])

    # 2) One Foundational Requirement at a time
    by_fr = rows_by_fr(codes)
    active = [fr for fr in FR_ORDER if by_fr.get(fr)]
    frs, real_rows, digest = [], 0, []
    for i, fr_code in enumerate(active, start=1):
        n = len(by_fr[fr_code])
        verb2 = "Revising" if revision else "Mapping"
        progress(f"[{i}/{len(active)}] {verb2} {fr_code[:2]} {fr_code[2:]} — {FR_TITLES[fr_code]} ({n} requirements)…")
        rows = _gen_fr_rows(provider, model, shared, fr_code, codes, api_key, base_url, progress,
                            revision, _cur_fr_rows(current, fr_code))
        if rows:
            # Coverage backfill: if the model dropped any requirements, fetch just those.
            missing = _missing_skeleton(by_fr[fr_code], rows)
            if missing:
                progress(f"    {fr_code[:2]} {fr_code[2:]}: filling {len(missing)} missing requirement(s)…")
                rows = rows + _backfill_missing(provider, model, shared, fr_code, missing,
                                                api_key, base_url, progress)
            real_rows += len(rows)
            for r in rows:
                digest.append(f"{r.get('req_id','')}: {r.get('verify','')[:220]}")
        else:
            # Safety net: keep the requirement ids visible so nothing silently vanishes.
            rows = [{"req_id": label, "requirement": name,
                     "verify": "(not generated — use Refine to regenerate this requirement)",
                     "pass": "", "notes": "regenerate"} for label, name, _s in by_fr[fr_code]]
            progress(f"    {fr_code[:2]} {fr_code[2:]}: placeholder rows inserted (model returned none).")
        frs.append({"fr": f"{fr_code[:2]} {fr_code[2:]}", "title": FR_TITLES[fr_code], "rows": rows})
        progress(f"    {fr_code[:2]} {fr_code[2:]} done — {len(rows)} rows (real total so far: {real_rows}).")
    rep["foundational_requirements"] = frs

    # 3) External Test Tools table
    progress(("Revising" if revision else "Building") + " the External Test Tools table…")
    try:
        t = _gen_structured(provider, model, CHECKLIST_SYSTEM,
                            build_tools_prompt(shared, "\n".join(digest), revision,
                                               (current or {}).get("external_tools")), TOOL_TOOLS, None,
                            api_key, base_url, 6000) or {}
        rep["external_tools"] = t.get("external_tools") or []
    except (ProviderError, ValueError) as e:
        _raise_if_fatal(e)
        progress(f"External Test Tools step could not complete ({str(e)[:60]}).")
        rep["external_tools"] = []
    progress(f"External Test Tools: {len(rep['external_tools'])} tool(s). Finalizing…")
    return normalize_checklist(rep), real_rows


# =============================================================================
#  SECTION 7 — NATIVE PDF ENGINE (pure standard library — NO dependencies)
# =============================================================================
# Standard-14 Helvetica advance-width tables (units/1000), char codes 32..255.
_W_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500]
_W_HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278, 611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556]
_UNI_MAP = {"–": "-", "—": "-", "‘": "'", "’": "'", "“": '"',
            "”": '"', "…": "...", "•": "-", "→": "->", "←": "<-",
            "·": "-", "✓": "v", "✗": "x", "≤": "<=", "≥": ">=",
            " ": " ", "‑": "-", "−": "-", "®": "(R)", "™": "(TM)",
            "›": ">", "‹": "<", "‘": "'", "▸": ">"}


def _pdf_norm(s):
    if s is None:
        return ""
    s = str(s)
    for k, v in _UNI_MAP.items():
        if k in s:
            s = s.replace(k, v)
    return "".join(ch if ord(ch) < 256 else "?" for ch in s)


def _pdf_cw(ch, bold):
    o = ord(ch)
    tbl = _W_HELVB if bold else _W_HELV
    if 32 <= o <= 255:
        return tbl[o - 32]
    return 500


def pdf_text_width(s, size, bold=False):
    s = _pdf_norm(s)
    return sum(_pdf_cw(c, bold) for c in s) * size / 1000.0


def pdf_wrap(s, size, maxw, bold=False):
    s = _pdf_norm(s).replace("\r", "")
    out = []
    for para in s.split("\n"):
        if para == "":
            out.append("")
            continue
        line = ""
        for word in para.split(" "):
            trial = word if not line else line + " " + word
            if pdf_text_width(trial, size, bold) <= maxw or not line:
                if pdf_text_width(word, size, bold) > maxw and not line:
                    cur = ""
                    for ch in word:
                        if pdf_text_width(cur + ch, size, bold) <= maxw:
                            cur += ch
                        else:
                            out.append(cur); cur = ch
                    line = cur
                else:
                    line = trial
            else:
                out.append(line); line = word
        out.append(line)
    return out


def _pdf_esc(s):
    return _pdf_norm(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


# Inline-bold keyword leads rendered bold inside a wrapped cell.
_KW_RE = re.compile(r"(Ext\. tools:|Native:|Test:|Pass:|Evidence:|Tools:|Example:|N/A\.?|"
                    r"Native config:|Native steps:)")


def _kw_runs(s):
    """Split a plain string into (text, bold) runs, bolding keyword leads."""
    out, last = [], 0
    for mm in _KW_RE.finditer(s):
        if mm.start() > last:
            out.append((s[last:mm.start()], False))
        out.append((mm.group(0), True))
        last = mm.end()
    if last < len(s):
        out.append((s[last:], False))
    return out


def _markup_runs(text):
    """Parse **bold** markdown + keyword leads into (text, bold) runs, and put
    'Ext. tools:' on its own line — so cells read like the sample cheat sheets."""
    text = _pdf_norm(text)
    # Put 'Ext. tools:' on its own line and normalize any asterisks around the lead
    # so the bold markers stay paired on one line.
    text = re.sub(r"\s*\*{0,2}\s*(Ext\.?\s*tools:)\s*\*{0,2}", r"\n**\1**", text)
    runs, pos = [], 0
    for mm in re.finditer(r"\*\*(.+?)\*\*", text):
        if mm.start() > pos:
            runs += _kw_runs(text[pos:mm.start()])
        runs.append((mm.group(1), True))
        pos = mm.end()
    if pos < len(text):
        runs += _kw_runs(text[pos:])
    # strip any residual unmatched markdown asterisks
    return [(seg.replace("**", ""), bold) for seg, bold in runs]


def pdf_wrap_runs(runs, size, maxw):
    """Word-wrap a list of (text, bold) runs to maxw, honoring hard newlines and
    per-word bold. Returns a list of lines; each line is a list of (segment, bold)."""
    toks = []
    for seg, bold in runs:
        for pi, ptext in enumerate(seg.split("\n")):
            if pi > 0:
                toks.append(("", bold, "nl"))
            for wi, w in enumerate(ptext.split(" ")):
                if wi > 0:
                    toks.append((" ", bold, "sp"))
                if w:
                    toks.append((w, bold, "w"))
    lines, cur, curw = [], [], 0.0
    for t, bold, kind in toks:
        if kind == "nl":
            lines.append(cur); cur, curw = [], 0.0; continue
        if kind == "sp":
            if cur:
                cur.append((" ", bold)); curw += pdf_text_width(" ", size, bold)
            continue
        w = pdf_text_width(t, size, bold)
        if curw + w > maxw and cur:
            lines.append(cur); cur, curw = [], 0.0
        cur.append((t, bold)); curw += w
    if cur or not lines:
        lines.append(cur)
    return lines


class SheetPDF:
    """Dependency-free landscape PDF generator for the 62443 SL-3 cheat sheets."""
    PW, PH = 792.0, 612.0            # US Letter, landscape
    ML, MR, MT, MB = 24, 24, 24, 30

    NAVY = (0.043, 0.239, 0.388)
    INK = (0.11, 0.14, 0.18)
    MUT = (0.36, 0.42, 0.50)
    LINE = (0.60, 0.66, 0.74)
    HEADBG = (0.905, 0.93, 0.957)
    NABG = (0.955, 0.965, 0.976)
    PREBG = (0.955, 0.965, 0.976)
    ACC = (0.043, 0.239, 0.388)
    SUB = (0.86, 0.90, 0.95)

    def __init__(self, title="62443 SL-3 Cheat Sheet", footer_left=""):
        self.title = _pdf_norm(title)
        self.footer_left = _pdf_norm(footer_left)[:96]
        self.pages = []
        self.buf = []
        self.y = self.PH - self.MT
        self._page_started = False
        self._start_page()

    @property
    def cw(self):
        return self.PW - self.ML - self.MR

    def _start_page(self):
        self.buf = []
        self.y = self.PH - self.MT
        self._page_started = True

    def _flush(self):
        if self._page_started:
            self.pages.append("".join(self.buf))
            self._page_started = False

    def new_page(self):
        self._flush()
        self._start_page()

    def ensure(self, space):
        if self.y - space < self.MB:
            self.new_page()

    def _rgb(self, c, stroke=False):
        op = "RG" if stroke else "rg"
        self.buf.append(f"{c[0]:.3f} {c[1]:.3f} {c[2]:.3f} {op}\n")

    def rect(self, x, y, w, h, fill=None, stroke=None, lw=0.6):
        if fill:
            self._rgb(fill)
            self.buf.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re f\n")
        if stroke:
            self._rgb(stroke, True)
            self.buf.append(f"{lw:.2f} w {x:.2f} {y:.2f} {w:.2f} {h:.2f} re S\n")

    def line(self, x1, y1, x2, y2, stroke=(0, 0, 0), lw=0.6):
        self._rgb(stroke, True)
        self.buf.append(f"{lw:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S\n")

    def text(self, x, y, s, size=9.5, bold=False, color=None, align="l", maxw=None):
        s = _pdf_norm(s)
        if color is None:
            color = self.INK
        if align in ("c", "r") and maxw is not None:
            w = pdf_text_width(s, size, bold)
            x = x + (maxw - w) / 2.0 if align == "c" else x + (maxw - w)
        f = "F2" if bold else "F1"
        self._rgb(color)
        self.buf.append(f"BT /{f} {size:.1f} Tf {x:.2f} {y:.2f} Td ({_pdf_esc(s)}) Tj ET\n")

    def _draw_runs_line(self, x, y, segs, size, color):
        cx = x
        for seg, bold in segs:
            if seg:
                self.text(cx, y, seg, size=size, bold=bold, color=color)
                cx += pdf_text_width(seg, size, bold)

    def _draw_rich_line(self, x, y, line, size, base_bold=False):
        """Draw one already-wrapped line, bolding inline keyword tokens."""
        cx = x
        for part in _KW_RE.split(line):
            if not part:
                continue
            b = base_bold or bool(_KW_RE.fullmatch(part))
            self.text(cx, y, part, size=size, bold=b)
            cx += pdf_text_width(part, size, b)

    def gap(self, h):
        self.y -= h

    # ---- cheat-sheet building blocks ----
    def title_band(self, product, type_label, target_sl):
        pad = 9
        tsize, ssize = 15.0, 8.0
        sub = f"{product}  -  Component type: {type_label}  -  Target SL = {target_sl}"
        subl = pdf_wrap(sub, ssize, self.cw - 2 * pad, bold=False)
        h = pad + tsize + 5 + len(subl) * (ssize + 2) + pad
        self.ensure(h + 6)
        top = self.y
        self.rect(self.ML, top - h, self.cw, h, fill=self.NAVY)
        ty = top - pad - tsize
        self.text(self.ML + pad, ty, "ISA/IEC 62443-3-3 / 4-2  -  SL-3 TESTING CHEAT SHEET",
                  size=tsize, bold=True, color=(1, 1, 1))
        ty -= 5
        for i, ln in enumerate(subl):
            ty -= (ssize + 2)
            self.text(self.ML + pad, ty, ln, size=ssize, bold=False, color=self.SUB)
        self.y = top - h - 8

    def section_band(self, text):
        size = 9.2
        pad = 4
        h = size + 2 * pad
        self.ensure(h + 24)   # keep band with at least the header of its table
        top = self.y
        self.rect(self.ML, top - h, self.cw, h, fill=self.NAVY)
        self.text(self.ML + 6, top - pad - size + 1.5, text, size=size, bold=True, color=(1, 1, 1))
        self.y = top - h

    def preamble(self, rows):
        if not rows:
            return
        size = 7.4
        pad = 4
        lblw = 118.0
        txtw = self.cw - lblw
        line_h = size + 2.2
        for r in rows:
            lbl = (r.get("label", "") or "").replace("**", "")
            llines = pdf_wrap(lbl, size, lblw - 2 * pad, bold=True)
            tlines = pdf_wrap_runs(_markup_runs(r.get("text", "")), size, txtw - 2 * pad)
            hh = max(len(llines), len(tlines)) * line_h + 2 * pad
            if self.y - hh < self.MB:
                self.new_page()
            top = self.y
            self.rect(self.ML, top - hh, lblw, hh, fill=self.PREBG)
            ty = top - pad
            for ln in llines:
                ty -= line_h
                self.text(self.ML + pad, ty + 1.5, ln, size=size, bold=True, color=self.ACC)
            ty = top - pad
            for segs in tlines:
                ty -= line_h
                self._draw_runs_line(self.ML + lblw + pad, ty + 1.5, segs, size, self.INK)
            self.line(self.ML, top - hh, self.ML + self.cw, top - hh, stroke=(0.84, 0.87, 0.91), lw=0.4)
            self.y = top - hh
        self.y -= 8

    def data_table(self, headers, rows, colw, na_flags=None, bold_col0=True,
                   rich_cols=(), size=7.4, header_size=7.4):
        n = len(headers)
        na_flags = na_flags or [False] * len(rows)
        pad = 3.4
        line_h = size + 2.2

        def wrap_cell(c, csize, maxw, bold0, rich):
            # Return a list of "runs-lines": each line is a list of (segment, bold).
            if rich:
                return pdf_wrap_runs(_markup_runs(c), csize, maxw)
            c = c.replace("**", "")   # strip stray markdown in plain cells
            return [[(ln, bold0)] for ln in pdf_wrap(c, csize, maxw, bold0)]

        def draw_header():
            hh = max(len(pdf_wrap(str(c), header_size, colw[i] - 2 * pad, True))
                     for i, c in enumerate(headers)) * line_h + 2 * pad
            self.ensure(hh)
            top = self.y
            self.rect(self.ML, top - hh, self.cw, hh, fill=self.NAVY)
            x = self.ML
            for i, c in enumerate(headers):
                ty = top - pad
                for ln in pdf_wrap(str(c), header_size, colw[i] - 2 * pad, True):
                    ty -= line_h
                    self.text(x + pad, ty + 1.5, ln, size=header_size, bold=True, color=(1, 1, 1))
                x += colw[i]
            self.y = top - hh

        draw_header()
        for ridx, r in enumerate(rows):
            cells = [("" if c is None else str(c)) for c in r]
            collines = [wrap_cell(c, size, colw[i] - 2 * pad, (bold_col0 and i == 0), i in rich_cols)
                        for i, c in enumerate(cells)]
            hh = max((len(cl) for cl in collines), default=1) * line_h + 2 * pad
            if self.y - hh < self.MB:
                self.new_page()
                draw_header()
            top = self.y
            if na_flags[ridx]:
                self.rect(self.ML, top - hh, self.cw, hh, fill=self.NABG)
            color = self.MUT if na_flags[ridx] else self.INK
            x = self.ML
            for i, cl in enumerate(collines):
                ty = top - pad
                for segs in cl:
                    ty -= line_h
                    self._draw_runs_line(x + pad, ty + 1.5, segs, size, color)
                x += colw[i]
            # borders
            x = self.ML
            for i in range(n + 1):
                self.line(x, top, x, top - hh, stroke=self.LINE, lw=0.4)
                if i < n:
                    x += colw[i]
            self.line(self.ML, top, self.ML + self.cw, top, stroke=self.LINE, lw=0.4)
            self.line(self.ML, top - hh, self.ML + self.cw, top - hh, stroke=self.LINE, lw=0.4)
            self.y = top - hh
        self.y -= 8

    def disclaimer(self, text):
        size = 6.6
        self.ensure(30)
        self.y -= 6
        self.line(self.ML, self.y, self.ML + self.cw, self.y, stroke=(0.78, 0.82, 0.86), lw=0.5)
        self.y -= 3
        for ln in pdf_wrap(text, size, self.cw):
            self.ensure(size + 3)
            self.y -= (size + 2)
            self.text(self.ML, self.y, ln, size=size, color=self.MUT)

    def save_bytes(self):
        self._flush()
        npages = len(self.pages)
        font_objs = {
            "F1": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "F2": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        }
        content_objs = []
        page_objs = []
        obj_id = 5
        page_ids = []
        for idx, content in enumerate(self.pages):
            fl = _pdf_esc(self.footer_left or self.title)
            m = self.MUT
            footer = (f"{m[0]:.3f} {m[1]:.3f} {m[2]:.3f} rg 0.4 w "
                      f"{self.ML:.1f} {self.MB - 8:.1f} m {self.PW - self.MR:.1f} {self.MB - 8:.1f} l S\n"
                      f"BT /F1 6.4 Tf {m[0]:.3f} {m[1]:.3f} {m[2]:.3f} rg "
                      f"{self.ML:.1f} {self.MB - 18:.1f} Td ({fl} - 62443 SL-3 Cheat Sheet) Tj ET\n"
                      f"BT /F1 6.4 Tf {m[0]:.3f} {m[1]:.3f} {m[2]:.3f} rg "
                      f"{self.PW - self.MR - 60:.1f} {self.MB - 18:.1f} Td (Page {idx + 1} of {npages}) Tj ET\n")
            full = content + footer
            cid = obj_id; obj_id += 1
            content_objs.append((cid, full))
            pid = obj_id; obj_id += 1
            page_ids.append(pid)
            page_objs.append((pid, cid))

        parts = []
        parts.append((1, "<< /Type /Catalog /Pages 2 0 R >>"))
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        parts.append((2, f"<< /Type /Pages /Count {npages} /Kids [{kids}] >>"))
        parts.append((3, font_objs["F1"]))
        parts.append((4, font_objs["F2"]))
        for (cid, full) in content_objs:
            stream = full.encode("latin-1", "replace")
            parts.append((cid, f"<< /Length {len(stream)} >>\nstream\n", stream, "\nendstream"))
        for (pid, cid) in page_objs:
            parts.append((pid, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PW:.2f} {self.PH:.2f}] "
                               f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>"))
        parts.sort(key=lambda p: p[0])
        out = bytearray()
        out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        offsets = {}
        for p in parts:
            oid = p[0]
            offsets[oid] = len(out)
            if len(p) == 2:
                out += f"{oid} 0 obj\n{p[1]}\nendobj\n".encode("latin-1", "replace")
            else:
                out += f"{oid} 0 obj\n{p[1]}".encode("latin-1", "replace")
                out += p[2]
                out += f"{p[3]}\nendobj\n".encode("latin-1", "replace")
        xref_pos = len(out)
        maxid = max(offsets)
        out += f"xref\n0 {maxid + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for i in range(1, maxid + 1):
            out += f"{offsets.get(i, 0):010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {maxid + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF").encode()
        return bytes(out)


def pdf_available():
    """Native PDF is always available (pure standard library)."""
    return True


def checklist_to_pdf(rep, meta=None):
    """Render the cheat sheet to a landscape-Letter PDF using the built-in engine
    (no third-party dependencies)."""
    rep = rep or {}
    product = rep.get("product", "") or "Component"
    doc = SheetPDF(title=f"{product} 62443 SL-3 Cheat Sheet", footer_left=product)
    doc.title_band(product, rep.get("component_type_label", ""), rep.get("target_sl", "SL 3"))
    doc.preamble(rep.get("preamble") or [])

    col_verify = rep.get("col_verify_header") or "Where & how to verify (native steps + Ext. tools)"
    col_notes = rep.get("col_notes_header") or "Notes / firmware"
    headers = ["Req (3-3 / 4-2)", "Requirement", col_verify, "Pass criteria / evidence", col_notes]
    props = [0.088, 0.150, 0.408, 0.208, 0.146]
    colw = [p * doc.cw for p in props]

    for fr in (rep.get("foundational_requirements") or []):
        frname = fr.get("fr", "")
        frtitle = fr.get("title", "") or FR_TITLES.get(frname.replace(" ", ""), "")
        doc.section_band(f"{frname} - {frtitle}")
        rows, na = [], []
        for row in (fr.get("rows") or []):
            rows.append([row.get("req_id", ""), row.get("requirement", ""),
                         row.get("verify", ""), row.get("pass", ""), row.get("notes", "")])
            na.append(row.get("pass", "").strip().upper().startswith("N/A"))
        doc.data_table(headers, rows, colw, na_flags=na, bold_col0=True, rich_cols={2, 3, 4})

    ext = rep.get("external_tools") or []
    if ext:
        doc.section_band("External Test Tools - how to use")
        eh = ["Tool / method", "Verifies", "How to use - steps / example", "Constraints"]
        ecolw = [0.185 * doc.cw, 0.235 * doc.cw, 0.44 * doc.cw, 0.14 * doc.cw]
        erows = [[t.get("tool", ""), t.get("verifies", ""), t.get("how", ""), t.get("constraints", "")]
                 for t in ext]
        doc.data_table(eh, erows, ecolw, bold_col0=True, rich_cols={1, 2, 3})

    doc.disclaimer(rep.get("footer") or DEFAULT_FOOTER)
    return doc.save_bytes()


def _h(s):
    return _htmlmod.escape(s or "", quote=True)


def _h_ext(s):
    t = _htmlmod.escape(s or "", quote=False)
    t = re.sub(r"\s*(Ext\.?\s*tools:)", r"<br>\1", t, count=1)   # Ext. tools: on its own line
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)       # **bold** key terms
    t = _KW_RE.sub(r"<strong>\g<0></strong>", t)                  # bold keyword leads
    return t.replace("\n", "<br>")


def checklist_to_html(rep, meta=None, standalone=False):
    """Render the cheat sheet as HTML — used for the on-screen results view and as a
    print-to-PDF (landscape) fallback when reportlab is not installed."""
    meta = meta or {}
    col_verify = rep.get("col_verify_header") or "Where & how to verify (native steps + Ext. tools)"
    col_notes = rep.get("col_notes_header") or "Notes / firmware"
    out = []
    out.append('<div class="cs-band"><div class="cs-title">ISA/IEC 62443-3-3 / 4-2 &bull; SL-3 TESTING CHEAT SHEET</div>'
               f'<div class="cs-comp"><b>{_h(rep.get("product",""))}</b> &middot; Component type: '
               f'<b>{_h(rep.get("component_type_label",""))}</b> &middot; Target SL = {_h(rep.get("target_sl","SL 3"))}</div></div>')
    if rep.get("preamble"):
        out.append('<table class="cs-pre">')
        for pr in rep["preamble"]:
            out.append(f'<tr><td class="k">{_h(pr.get("label",""))}</td><td>{_h_ext(pr.get("text",""))}</td></tr>')
        out.append('</table>')
    for fr in (rep.get("foundational_requirements") or []):
        frname = fr.get("fr", "")
        frtitle = fr.get("title", "") or FR_TITLES.get(frname.replace(" ", ""), "")
        out.append(f'<div class="cs-fr">{_h(frname)} — {_h(frtitle)}</div>')
        out.append('<table class="cs-tbl"><thead><tr>'
                   '<th class="c1">Req (3-3 / 4-2)</th><th class="c2">Requirement</th>'
                   f'<th class="c3">{_h(col_verify)}</th><th class="c4">Pass criteria / evidence</th>'
                   f'<th class="c5">{_h(col_notes)}</th></tr></thead><tbody>')
        for row in (fr.get("rows") or []):
            na = " na" if row.get("pass", "").strip().upper().startswith("N/A") else ""
            out.append(f'<tr class="row{na}"><td class="c1"><b>{_h(row.get("req_id",""))}</b></td>'
                       f'<td class="c2">{_h(row.get("requirement",""))}</td>'
                       f'<td class="c3">{_h_ext(row.get("verify",""))}</td>'
                       f'<td class="c4">{_h_ext(row.get("pass",""))}</td>'
                       f'<td class="c5">{_h_ext(row.get("notes",""))}</td></tr>')
        out.append('</tbody></table>')
    if rep.get("external_tools"):
        out.append('<div class="cs-fr">External Test Tools — how to use</div>')
        out.append('<table class="cs-tbl ext"><thead><tr><th class="e1">Tool / method</th>'
                   '<th class="e2">Verifies</th><th class="e3">How to use — steps / example</th>'
                   '<th class="e4">Constraints</th></tr></thead><tbody>')
        for t in rep["external_tools"]:
            out.append(f'<tr class="row"><td class="e1"><b>{_h(t.get("tool",""))}</b></td>'
                       f'<td class="e2">{_h_ext(t.get("verifies",""))}</td>'
                       f'<td class="e3">{_h_ext(t.get("how",""))}</td>'
                       f'<td class="e4">{_h_ext(t.get("constraints",""))}</td></tr>')
        out.append('</tbody></table>')
    out.append(f'<div class="cs-foot">{_h(rep.get("footer") or DEFAULT_FOOTER)}</div>')
    inner = "\n".join(out)
    if not standalone:
        return inner
    css = CS_PRINT_CSS
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>'
            f'{_h(rep.get("product",""))} — 62443 SL-3 Cheat Sheet</title><style>{css}</style></head>'
            f'<body><div class="sheet">{inner}</div></body></html>')


CS_PRINT_CSS = """
@page { size: letter landscape; margin: 10mm; }
* { box-sizing: border-box; }
body { font-family: Helvetica, Arial, sans-serif; color:#1b2430; margin:0; }
.sheet { padding: 6px 4px; }
.cs-band { background:#0b3d63; color:#fff; padding:9px 12px; border-radius:2px; margin-bottom:8px; }
.cs-title { font-weight:800; font-size:15px; letter-spacing:.2px; }
.cs-comp { font-size:9.5px; margin:3px 0 0; color:#dbe6f2; }
.cs-pre { width:100%; border-collapse:collapse; margin-bottom:8px; font-size:7.6px; }
.cs-pre td { vertical-align:top; padding:3px 5px; border-bottom:.5px solid #d7dee7; }
.cs-pre td.k { width:130px; font-weight:700; background:#f4f6f9; }
.cs-fr { background:#0b3d63; color:#fff; font-weight:700; font-size:9.5px; padding:3px 6px; margin-top:9px; }
.cs-tbl { width:100%; border-collapse:collapse; font-size:7.5px; }
.cs-tbl th { background:#e7edf4; text-align:left; font-weight:700; }
.cs-tbl th, .cs-tbl td { border:.4px solid #9aa7b8; vertical-align:top; padding:2.6px 3.5px; line-height:1.28; }
.cs-tbl tr.na td { background:#f4f6f9; color:#5b6675; }
.cs-tbl .c1 { width:8.5%; } .cs-tbl .c2 { width:15%; } .cs-tbl .c3 { width:40%; }
.cs-tbl .c4 { width:21%; } .cs-tbl .c5 { width:15.5%; }
.cs-tbl.ext .e1 { width:16%; } .cs-tbl.ext .e2 { width:24%; } .cs-tbl.ext .e3 { width:44%; } .cs-tbl.ext .e4 { width:16%; }
.cs-foot { margin-top:10px; font-size:6.6px; color:#5b6675; border-top:.5px solid #c7d0db; padding-top:4px; }
"""


# =============================================================================
#  SECTION 8 — SQLITE PERSISTENCE + IN-MEMORY SESSION CACHE
# =============================================================================
DB_PATH = DEFAULT_DB
_db_lock = threading.Lock()


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    with _db_lock:
        conn = db_conn()
        conn.execute("""CREATE TABLE IF NOT EXISTS checklist (
            id TEXT PRIMARY KEY, title TEXT, product TEXT, target TEXT, scope TEXT,
            provider TEXT, model TEXT, type_codes TEXT, report_json TEXT, created_at TEXT)""")
        conn.commit()
        conn.close()


def db_save(target, scope, provider, model, rep):
    cid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    title = rep.get("product") or target
    codes = ",".join(rep.get("component_type_codes") or [])
    with _db_lock:
        conn = db_conn()
        conn.execute("INSERT INTO checklist VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (cid, title, rep.get("product") or target, target, scope or "", provider, model,
                      codes, json.dumps(rep), now))
        conn.commit()
        conn.close()
    return cid, now


def db_update(cid, rep):
    with _db_lock:
        conn = db_conn()
        conn.execute("UPDATE checklist SET report_json=?, product=?, title=? WHERE id=?",
                     (json.dumps(rep), rep.get("product", ""), rep.get("product", ""), cid))
        conn.commit()
        conn.close()


def db_list():
    conn = db_conn()
    rows = conn.execute("SELECT id,title,product,provider,model,type_codes,created_at "
                        "FROM checklist ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def db_get(cid):
    conn = db_conn()
    row = conn.execute("SELECT * FROM checklist WHERE id=?", (cid,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["report"] = json.loads(d.get("report_json") or "{}")
    return d


def db_delete(cid):
    with _db_lock:
        conn = db_conn()
        conn.execute("DELETE FROM checklist WHERE id=?", (cid,))
        conn.commit()
        conn.close()


# In-memory cache of distilled context between the classify and generate phases so
# large documents / web pages are read only once. Bounded, newest-kept.
_SESSIONS = {}
_sess_lock = threading.Lock()
_SESSION_CAP = 24


def _session_put(data):
    tok = str(uuid.uuid4())
    with _sess_lock:
        _SESSIONS[tok] = data
        if len(_SESSIONS) > _SESSION_CAP:
            for k in list(_SESSIONS.keys())[:-_SESSION_CAP]:
                _SESSIONS.pop(k, None)
    return tok


def _session_get(tok):
    with _sess_lock:
        return _SESSIONS.get(tok)


# =============================================================================
#  SECTION 9 — ORCHESTRATION (classify -> confirm -> generate)
# =============================================================================
def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _build_contexts(payload, provider, model, api_key, base_url, vision_ok, progress):
    arts = payload.get("artifacts") or []
    artifact_ctx, images, notes1 = build_analysis_context(
        arts, provider, model, api_key, base_url, vision_ok, progress)
    web_ctx, notes2, sources = gather_web_context(
        payload.get("urls") or [], bool(payload.get("do_search")),
        payload.get("search_query") or payload.get("target") or "",
        provider, model, api_key, base_url, progress)
    images, dropped = sanitize_images(images)
    if dropped:
        progress(f"Skipped {dropped} image(s) a vision model can't read.")
    return artifact_ctx, web_ctx, images, (notes1 + notes2), sources


def run_classify(payload, progress=None):
    progress = progress or (lambda _m: None)
    target = (payload.get("target") or "").strip()
    if not target:
        raise ValueError("target required")
    scope = payload.get("scope") or ""
    provider = payload["provider"]; model = payload["model"]
    api_key = payload.get("api_key"); base_url = payload.get("base_url")
    vision_ok = bool(PROVIDERS.get(provider, {}).get("vision"))
    progress("Reading your sources…")
    artifact_ctx, web_ctx, images, notes, sources = _build_contexts(
        payload, provider, model, api_key, base_url, vision_ok, progress)
    progress("Identifying the product and its 62443-4-2 component type…")
    user = build_classify_prompt(target, scope, artifact_ctx, web_ctx)
    classification = generate_classification(provider, model, user, images, api_key, base_url)
    tok = _session_put({"target": target, "scope": scope, "provider": provider, "model": model,
                        "api_key": api_key, "base_url": base_url, "artifact_ctx": artifact_ctx,
                        "web_ctx": web_ctx, "images": images, "sources": sources,
                        "classification": classification})
    return {"session": tok, "classification": classification, "sources": sources, "notes": notes}


def run_generate(payload, progress=None):
    progress = progress or (lambda _m: None)
    tok = payload.get("session")
    sess = _session_get(tok) if tok else None
    if sess:
        target, scope = sess["target"], sess["scope"]
        provider, model = sess["provider"], sess["model"]
        api_key, base_url = sess["api_key"], sess["base_url"]
        artifact_ctx, web_ctx, images = sess["artifact_ctx"], sess["web_ctx"], sess["images"]
        sources = sess["sources"]; classification = dict(sess["classification"])
    else:
        # Fallback: no cached session (e.g. server restarted) — rebuild from payload.
        target = (payload.get("target") or "").strip()
        scope = payload.get("scope") or ""
        provider = payload["provider"]; model = payload["model"]
        api_key = payload.get("api_key"); base_url = payload.get("base_url")
        vision_ok = bool(PROVIDERS.get(provider, {}).get("vision"))
        artifact_ctx, web_ctx, images, _n, sources = _build_contexts(
            payload, provider, model, api_key, base_url, vision_ok, progress)
        classification = payload.get("classification") or {}
    # Apply the user's confirmed / overridden component type.
    codes = payload.get("component_type_codes")
    if codes:
        codes = [c for c in codes if c in COMPONENT_TYPES]
        if codes:
            classification["component_type_codes"] = codes
    if payload.get("component_type_label"):
        classification["component_type_label"] = payload["component_type_label"]
    classification.setdefault("component_type_codes", ["EDR"])
    classification.setdefault("component_type_label",
                              " + ".join(COMPONENT_TYPES[c] for c in classification["component_type_codes"]))
    progress("Building the SL-3 cheat sheet (staged: header, each FR, then tools)…")
    rep, total_rows = generate_checklist_streamed(
        provider, model, classification, target, scope, artifact_ctx, web_ctx,
        api_key, base_url, progress)
    if total_rows == 0:
        raise ValueError("The model returned no requirement rows for this product. Try again, pick a stronger "
                         "model, or add a manual/URL in Step 3 so it has more to work from.")
    # Ensure header identity is present even if the model omitted it.
    rep.setdefault("product", classification.get("product") or target)
    rep.setdefault("component_type_label", classification.get("component_type_label"))
    rep["component_type_codes"] = classification["component_type_codes"]
    cid, created = db_save(target, scope, provider, model, rep)
    meta = {"target": target, "provider": provider, "model": model, "generated_at": created}
    return {"id": cid, "report": rep, "html": checklist_to_html(rep, meta),
            "sources": sources, "reportlab": pdf_available(),
            "missing": checklist_missing(rep)}


def run_refine_streamed(payload, progress=None):
    """Apply a natural-language change to a saved checklist using the SAME staged,
    streamed generator (so the user sees progress and it can't time out)."""
    progress = progress or (lambda _m: None)
    cid = payload.get("id")
    row = db_get(cid) if cid else None
    if not row:
        raise ValueError("checklist not found")
    instruction = (payload.get("instruction") or "").strip()
    if not instruction:
        raise ValueError("instruction required")
    current = row.get("report") or {}
    provider = payload["provider"]; model = payload["model"]
    api_key = payload.get("api_key"); base_url = payload.get("base_url")
    classification = {"product": current.get("product") or row.get("product"),
                      "component_type_codes": current.get("component_type_codes") or ["EDR"],
                      "component_type_label": current.get("component_type_label") or "",
                      "key_facts": []}
    progress("Applying your change (staged: header, each FR, then tools)…")
    rep, _rows = generate_checklist_streamed(
        provider, model, classification, classification["product"], "", "", "",
        api_key, base_url, progress, revision=instruction, current=current)
    rep.setdefault("product", classification["product"])
    rep.setdefault("component_type_label", classification["component_type_label"])
    rep["component_type_codes"] = classification["component_type_codes"]
    db_update(cid, rep)
    return {"id": cid, "report": rep, "html": checklist_to_html(rep),
            "reportlab": pdf_available(), "missing": checklist_missing(rep)}


# =============================================================================
#  SECTION 10 — HTTP SERVER (stdlib http.server)
# =============================================================================
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, status=200, ctype="text/html; charset=utf-8", download=None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse_start(self):
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

    def _sse(self, event, data):
        self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._html(INDEX_HTML)
        if path == "/api/providers":
            return self._json({"providers": provider_catalog(),
                               "component_types": COMPONENT_TYPES, "stats": catalog_stats()})
        if path == "/api/health":
            return self._json({"status": "ok", "version": APP_VERSION,
                               "reportlab": pdf_available(), "catalog": catalog_stats()})
        if path == "/api/checklists":
            return self._json({"checklists": db_list()})
        if path.startswith("/api/checklists/") and path.endswith("/pdf"):
            return self._pdf(path[len("/api/checklists/"):-len("/pdf")])
        if path.startswith("/api/checklists/") and path.endswith("/html"):
            return self._print_html(path[len("/api/checklists/"):-len("/html")])
        if path.startswith("/api/checklists/"):
            cid = path.rsplit("/", 1)[-1]
            m = db_get(cid)
            if not m:
                return self._json({"error": "not found"}, 404)
            rep = m.get("report") or {}
            m["html"] = checklist_to_html(rep)
            m["reportlab"] = pdf_available()
            return self._json(m)
        return self._json({"error": "not found"}, 404)

    def _pdf(self, cid):
        m = db_get(cid)
        if not m:
            return self._json({"error": "not found"}, 404)
        rep = m.get("report") or {}
        try:
            pdf = checklist_to_pdf(rep, {"generated_at": m.get("created_at")})
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"PDF generation failed: {e}"}, 500)
        fname = _safe_name(m.get("product") or "62443_SL3_CheatSheet") + "_62443_SL3_CheatSheet.pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(pdf)))
        self.end_headers()
        self.wfile.write(pdf)

    def _print_html(self, cid):
        m = db_get(cid)
        if not m:
            return self._json({"error": "not found"}, 404)
        rep = m.get("report") or {}
        html = checklist_to_html(rep, standalone=True)
        fname = _safe_name(m.get("product") or "62443_SL3_CheatSheet") + "_62443_SL3_CheatSheet.html"
        return self._html(html, download=fname)

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            if path == "/api/validate_key":
                pl = self._read_json()
                return self._json(validate_key(pl.get("provider"), pl.get("api_key"), pl.get("base_url")))
            if path == "/api/artifacts/parse":
                return self._parse_artifacts()
            if path == "/api/classify/stream":
                return self._classify_stream()
            if path == "/api/generate/stream":
                return self._generate_stream()
            if path == "/api/refine/stream":
                return self._refine_stream()
            if path == "/api/refine":
                return self._refine()
            return self._json({"error": "not found"}, 404)
        except Exception as e:  # noqa: BLE001
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/checklists/"):
            db_delete(path.rsplit("/", 1)[-1])
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)

    def _parse_artifacts(self):
        payload = self._read_json()
        out = []
        for f in payload.get("files", []):
            out.append(ingest_artifact(f.get("filename", "file"), f.get("b64", "")))
        return self._json({"artifacts": out})

    def _classify_stream(self):
        p = self._read_json()
        if not (p.get("target") or "").strip():
            return self._json({"error": "target required"}, 400)
        self._sse_start()
        def progress(msg):
            self._sse("progress", {"message": msg})
        try:
            out = run_classify(p, progress)
        except ProviderError as e:
            return self._sse("error", {"message": str(e)})
        except ValueError as e:
            return self._sse("error", {"message": str(e)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001
            return self._sse("error", {"message": f"Identification error: {e}"})
        try:
            self._sse("done", out)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _generate_stream(self):
        p = self._read_json()
        self._sse_start()
        def progress(msg):
            self._sse("progress", {"message": msg})
        try:
            out = run_generate(p, progress)
        except ProviderError as e:
            return self._sse("error", {"message": str(e)})
        except ValueError as e:
            return self._sse("error", {"message": f"Model did not return valid data: {e}"})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001
            return self._sse("error", {"message": f"Generation error: {e}"})
        try:
            self._sse("done", out)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _refine_stream(self):
        p = self._read_json()
        self._sse_start()
        def progress(msg):
            self._sse("progress", {"message": msg})
        try:
            out = run_refine_streamed(p, progress)
        except ProviderError as e:
            return self._sse("error", {"message": str(e)})
        except ValueError as e:
            return self._sse("error", {"message": str(e)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001
            return self._sse("error", {"message": f"Refine error: {e}"})
        try:
            self._sse("done", out)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _refine(self):
        p = self._read_json()
        cid = p.get("id")
        row = db_get(cid) if cid else None
        if not row:
            return self._json({"error": "checklist not found"}, 404)
        instruction = (p.get("instruction") or "").strip()
        if not instruction:
            return self._json({"error": "instruction required"}, 400)
        current = row.get("report") or {}
        user = build_refine_prompt(current, instruction)
        try:
            rep = _gen_structured(p["provider"], p["model"], REFINE_SYSTEM, user, TOOL_CHECKLIST,
                                  None, p.get("api_key"), p.get("base_url"), p.get("max_tokens", 22000))
        except ProviderError as e:
            return self._json({"error": str(e)}, 502)
        except ValueError as e:
            return self._json({"error": f"Model did not return valid data: {e}"}, 422)
        rep = normalize_checklist(rep)
        rep.setdefault("product", current.get("product") or row.get("product"))
        rep.setdefault("component_type_label", current.get("component_type_label"))
        rep.setdefault("component_type_codes", current.get("component_type_codes") or [])
        db_update(cid, rep)
        return self._json({"id": cid, "report": rep, "html": checklist_to_html(rep),
                           "reportlab": pdf_available()})


def _safe_name(s):
    s = re.sub(r"[^A-Za-z0-9]+", "_", s or "").strip("_")
    return (s or "checklist")[:60]


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# =============================================================================
#  SECTION 11 — EMBEDDED WEB UI (single-page app; CSS + JS inline)
# =============================================================================
INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>62443 SL-3 Checklist Generator</title>
<style>
:root{--bg:#0e1420;--panel:#151d2e;--panel2:#1b2438;--line:#28324a;--ink:#e7edf6;--muted:#93a1b8;--accent:#3d9be0;--accent2:#0b3d63;--ok:#3ecf8e;--warn:#f4b942;--crit:#ff5b6e}
*{box-sizing:border-box}html,body{margin:0;min-height:100%}
body{background:var(--bg);color:var(--ink);font:14.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
h1,h2,h3{margin:0}button{cursor:pointer;font:inherit}
select,input,textarea{width:100%;background:var(--panel2);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:11px 13px;font:inherit;outline:none}
select:focus,input:focus,textarea:focus{border-color:var(--accent)}textarea{resize:vertical}
.hidden{display:none!important}.muted{color:var(--muted)}
button.primary{background:linear-gradient(90deg,var(--accent),#2f7fc0);color:#fff;border:none;border-radius:9px;padding:12px 20px;font-weight:700}
button.primary:hover{filter:brightness(1.08)}button.primary:disabled{opacity:.5;cursor:not-allowed}
button.ghost{background:var(--panel2);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:10px 16px}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 22px;background:linear-gradient(90deg,#0b1220,#12203a);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}
.brand{display:flex;gap:12px;align-items:center}.logo{font-size:24px;color:var(--accent)}
.topbar h1{font-size:16px}.tag{margin:2px 0 0;color:var(--muted);font-size:11px}
.top-right{display:flex;gap:8px;align-items:center}
.badge{background:var(--panel2);border:1px solid var(--line);border-radius:20px;padding:5px 11px;font-size:11.5px;color:var(--muted)}
.wrap{max-width:960px;margin:26px auto;padding:0 18px}
.wizard{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px}
.steps{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-wrap:wrap}
.stepdot{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12.5px}
.stepdot .num{display:inline-flex;width:22px;height:22px;border-radius:50%;background:var(--panel2);border:1px solid var(--line);align-items:center;justify-content:center;font-size:12px}
.stepdot.active{color:var(--ink)}.stepdot.active .num{background:var(--accent);border-color:var(--accent);color:#fff}
.stepdot.done .num{background:var(--ok);border-color:var(--ok);color:#08221a}
.stepsep{flex:1;height:1px;background:var(--line);min-width:14px}
.wstep{display:none}.wstep.active{display:block}
h2{font-size:19px;margin-bottom:6px}.sub{color:var(--muted);font-size:13px;margin:0 0 14px}
.field-label{display:block;margin:12px 0 5px;font-size:12.5px;color:var(--muted)}
.opt{color:var(--muted);font-size:11.5px}
.wnav{display:flex;justify-content:space-between;gap:10px;margin-top:20px}
.status{margin-top:12px;font-size:13px;color:var(--muted);min-height:20px}
.status.err{color:var(--crit)}.status.ok{color:var(--ok)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.drop{border:1.5px dashed var(--line);border-radius:12px;padding:26px;text-align:center;color:var(--muted);cursor:pointer;background:var(--panel2)}
.drop.hot{border-color:var(--accent);color:var(--ink)}
.artifacts,.saved{list-style:none;margin:12px 0 0;padding:0}
.artifacts li{display:flex;justify-content:space-between;gap:10px;padding:9px 12px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;margin-bottom:7px;font-size:12.5px}
.chk{display:flex;gap:8px;align-items:flex-start;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:10px 12px;margin-top:8px}
.chk input{width:auto;margin-top:3px}
.typegrid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px}
.typecard{display:flex;gap:9px;align-items:flex-start;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 13px;cursor:pointer}
.typecard input{width:auto;margin-top:3px}.typecard.sel{border-color:var(--accent);background:#16283f}
.typecard b{font-size:13.5px}.typecard .d{font-size:11.5px;color:var(--muted)}
.pill{display:inline-block;background:#16324e;color:#bfe0f5;border-radius:20px;padding:3px 10px;font-size:11.5px;margin:2px 4px 2px 0}
.facts{margin:8px 0 0;padding-left:18px;font-size:12.5px;color:var(--muted)}
.stream{margin-top:12px;background:#0a1018;border:1px solid var(--line);border-radius:10px;padding:12px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;color:#a9c7de;max-height:240px;overflow:auto;white-space:pre-wrap}
.results-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.meta{color:var(--muted);font-size:12px;margin-top:3px}
.sheetbox{background:#fff;color:#1b2430;border-radius:12px;padding:16px 14px;overflow-x:auto}
/* on-screen cheat sheet styling mirrors the print CSS */
.sheetbox .cs-band{background:#0b3d63;color:#fff;padding:11px 14px;border-radius:3px;margin-bottom:10px}
.sheetbox .cs-title{font-weight:800;font-size:17px}
.sheetbox .cs-comp{font-size:12px;margin:4px 0 0;color:#dbe6f2}
.sheetbox .cs-pre{width:100%;border-collapse:collapse;margin-bottom:10px;font-size:11px}
.sheetbox .cs-pre td{vertical-align:top;padding:4px 6px;border-bottom:.5px solid #d7dee7}
.sheetbox .cs-pre td.k{width:150px;font-weight:700;background:#f4f6f9}
.sheetbox .cs-fr{background:#0b3d63;color:#fff;font-weight:700;font-size:12.5px;padding:4px 8px;margin-top:12px}
.sheetbox .cs-tbl{width:100%;border-collapse:collapse;font-size:10.7px}
.sheetbox .cs-tbl th{background:#e7edf4;text-align:left;font-weight:700}
.sheetbox .cs-tbl th,.sheetbox .cs-tbl td{border:.5px solid #9aa7b8;vertical-align:top;padding:4px 5px;line-height:1.32}
.sheetbox .cs-tbl tr.na td{background:#f4f6f9;color:#5b6675}
.sheetbox .cs-tbl .c1{width:8.5%}.sheetbox .cs-tbl .c2{width:15%}.sheetbox .cs-tbl .c3{width:40%}.sheetbox .cs-tbl .c4{width:21%}.sheetbox .cs-tbl .c5{width:15.5%}
.sheetbox .cs-tbl.ext .e1{width:16%}.sheetbox .cs-tbl.ext .e2{width:24%}.sheetbox .cs-tbl.ext .e3{width:44%}.sheetbox .cs-tbl.ext .e4{width:16%}
.sheetbox .cs-foot{margin-top:12px;font-size:9.6px;color:#5b6675;border-top:.5px solid #c7d0db;padding-top:5px}
.refine{margin-top:18px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.chat-input{display:flex;gap:8px;margin-top:8px}.chat-input textarea{flex:1}
.savedpanel{position:fixed;top:0;right:0;width:380px;max-width:92vw;height:100%;background:var(--panel);border-left:1px solid var(--line);padding:18px;overflow:auto;z-index:40}
.saved li{padding:10px 12px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;margin-bottom:8px;font-size:12.5px;cursor:pointer}
.saved li:hover{border-color:var(--accent)}
.modal{position:fixed;inset:0;background:rgba(4,8,14,.7);display:flex;align-items:center;justify-content:center;z-index:50;padding:18px}
.modal-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;max-width:640px;width:100%;max-height:88vh;overflow:auto}
a.dl{color:var(--accent)}
</style></head>
<body>
<div class="topbar">
 <div class="brand"><span class="logo">▦</span><div><h1>ISA/IEC 62443 SL-3 Checklist Generator</h1>
 <p class="tag">Product-specific 3-3 / 4-2 SL-3 testing cheat sheets — model-agnostic</p></div></div>
 <div class="top-right"><span id="cat-badge" class="badge">catalog…</span>
  <button id="savedBtn" class="ghost">Saved</button><button id="settingsBtn" class="ghost">⚙ AI Settings</button></div>
</div>

<div class="wrap">
<div id="wizard" class="wizard">
 <div class="steps">
  <div class="stepdot active" data-dot="1"><span class="num">1</span> AI Model &amp; keys</div><div class="stepsep"></div>
  <div class="stepdot" data-dot="2"><span class="num">2</span> Describe</div><div class="stepsep"></div>
  <div class="stepdot" data-dot="3"><span class="num">3</span> Sources</div><div class="stepsep"></div>
  <div class="stepdot" data-dot="4"><span class="num">4</span> Confirm &amp; generate</div>
 </div>

 <div class="wstep active" id="w1">
  <h2>Choose your AI model &amp; enter your key</h2>
  <p class="sub">Pick which AI writes the checklist and paste its API key (stored only in this browser). This one key does everything — including searching the web. No second key is needed.</p>
  <div class="row2">
   <div><label class="field-label">AI provider</label><select id="provider"></select></div>
   <div><label class="field-label">Model</label><select id="model"></select></div>
  </div>
  <input id="customModel" style="margin-top:6px" placeholder="…or type a custom model id"/>
  <div id="localRow" style="display:none"><label class="field-label">Base URL (local / OpenAI-compatible)</label><input id="baseUrl" placeholder="http://localhost:11434/v1"/></div>
  <label class="field-label">API key <span id="keyState" class="opt"></span></label>
  <input id="apiKey" type="password" placeholder="paste your API key"/>
  <p class="sub" id="providerNotes" style="margin-top:8px"></p>
  <p class="sub" id="searchCap" style="margin-top:2px"></p>
  <div id="keyMsg" class="status"></div>
  <div class="wnav"><button class="ghost" id="clearKey">Clear saved keys</button><button class="primary" id="aiNext">Verify &amp; continue →</button></div>
 </div>

 <div class="wstep" id="w2">
  <h2>What component are we assessing?</h2>
  <p class="sub">Name the product as specifically as you can — vendor, model, family, firmware/version.</p>
  <label class="field-label">Component / product</label>
  <textarea id="target" rows="3" placeholder="e.g. Siemens SIPROTEC 5 7SJ85 overcurrent/feeder protection relay (IEC 61850, DIGSI 5)"></textarea>
  <label class="field-label">Scope / context (optional)</label>
  <textarea id="scope" rows="2" placeholder="Deployment, firmware/version, boundaries, what the assessor can/can't touch, target zone…"></textarea>
  <div class="wnav"><button class="ghost" data-back="1">← Back</button><button class="primary" data-next="3">Continue →</button></div>
 </div>

 <div class="wstep" id="w3">
  <h2>Add sources <span class="opt">(recommended)</span></h2>
  <p class="sub">The more the AI can read, the more product-specific the checklist. Add any mix: let the AI search the web itself (using your model's key), paste product-page / online-manual / datasheet URLs (scraped live), and/or upload manuals &amp; datasheets (large 400+ page PDFs are chunked and fully read).</p>
  <div class="chk"><input type="checkbox" id="doSearch" checked/><label for="doSearch" style="cursor:pointer"><b>Let the AI search the web on its own</b> for this product's manual, datasheet &amp; security guides <span id="searchDisabled" class="opt"></span></label></div>
  <label class="field-label">Source URLs <span class="opt">(optional — one per line: product page, online manual, datasheet PDF)</span></label>
  <textarea id="urls" rows="3" placeholder="https://vendor.com/product/model&#10;https://vendor.com/manuals/model-user-manual.pdf"></textarea>
  <label class="field-label">Upload manuals / datasheets <span class="opt">(PDF, DOCX, TXT, images)</span></label>
  <div id="drop" class="drop">Drag &amp; drop files here, or click to browse</div>
  <input id="fileInput" type="file" multiple class="hidden" accept=".pdf,.docx,.txt,.md,.csv,.json,.xml,.png,.jpg,.jpeg,.gif,.webp"/>
  <ul id="artifactList" class="artifacts"></ul>
  <div class="wnav"><button class="ghost" data-back="2">← Back</button><button class="primary" id="identifyBtn">Identify component →</button></div>
 </div>

 <div class="wstep" id="w4">
  <h2 id="w4h">Working…</h2>
  <p class="sub" id="w4sub">Reading your sources and identifying the product.</p>
  <div id="w4status" class="status">Contacting the model…</div>
  <div id="w4hint" class="sub hidden" style="margin-top:8px"></div>
  <div id="w4stream" class="stream hidden"></div>
  <div id="w4actions" class="wnav hidden" style="margin-top:16px">
   <button class="ghost" id="w4edit">← Edit sources</button>
   <div style="display:flex;gap:8px"><button class="ghost" id="w4settings">Change model / key</button><button class="primary" id="w4retry">↻ Retry</button></div>
  </div>
 </div>
</div>

<div id="results" class="hidden">
 <div class="results-head">
  <div><h2 id="r-title">SL-3 Cheat Sheet</h2><div class="meta" id="r-meta"></div></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
   <button id="pdfBtn" class="primary">⬇ Download PDF</button>
   <button id="htmlBtn" class="ghost">Printable HTML</button>
   <button id="newBtn" class="ghost">+ New checklist</button>
  </div>
 </div>
 <div id="sheet" class="sheetbox"></div>
 <div class="refine">
  <h3 style="font-size:15px">Refine this checklist</h3>
  <p class="sub" style="margin:4px 0 0">Ask for changes — e.g. "add IEC 61850 GOOSE/MMS test steps to FR3", "treat it as EDR+NDR", "expand the External Test Tools table".</p>
  <div class="chat-input"><textarea id="refineMsg" rows="2" placeholder="Describe the change… (Ctrl/Cmd+Enter)"></textarea><button id="refineSend" class="primary">Update</button></div>
  <div id="refineStatus" class="status"></div>
 </div>
</div>
</div>

<div id="savedPanel" class="savedpanel hidden">
 <h3 style="font-size:15px">Saved checklists <button class="ghost" id="closeSaved" style="padding:4px 10px;float:right">×</button></h3>
 <ul id="savedList" class="saved" style="margin-top:12px"></ul>
</div>

<div id="typeModal" class="modal hidden"><div class="modal-card">
 <h3 style="font-size:17px">Confirm the component type</h3>
 <p class="sub" style="margin:6px 0 0" id="tm-conf"></p>
 <label class="field-label">Product (edit if needed)</label>
 <input id="tm-product"/>
 <p class="sub" style="margin:10px 0 2px"><b>Why:</b> <span id="tm-reason"></span></p>
 <div id="tm-facts"></div>
 <label class="field-label" style="margin-top:10px">ISA/IEC 62443-4-2 component type(s) — confirm or override</label>
 <div class="typegrid" id="tm-types"></div>
 <div id="tm-sources" class="sub" style="margin-top:10px"></div>
 <div class="wnav"><button class="ghost" id="tm-back">← Back to sources</button><button class="primary" id="tm-go">Generate SL-3 checklist →</button></div>
</div></div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let PROVIDERS=[],CTYPES={},STATE={session:null,classification:null,artifacts:[],id:null,report:null};
const LS={get k(){return JSON.parse(localStorage.getItem('icg_keys')||'{}')},set k(v){localStorage.setItem('icg_keys',JSON.stringify(v))},
  get b(){return JSON.parse(localStorage.getItem('icg_bases')||'{}')},set b(v){localStorage.setItem('icg_bases',JSON.stringify(v))},
  get s(){return JSON.parse(localStorage.getItem('icg_sel')||'{}')},set s(v){localStorage.setItem('icg_sel',JSON.stringify(v))}};

async function init(){await loadProviders();wire();}
async function loadProviders(){
 const r=await fetch('/api/providers').then(x=>x.json());
 PROVIDERS=r.providers;CTYPES=r.component_types;
 const st=r.stats||{};$('#cat-badge').textContent=(st['62443-3-3 SR']||0)+' SR · '+(st['62443-4-2 CR']||0)+' CR · EDR/HDR/NDR/SAR';
 const sel=LS.s;
 $('#provider').innerHTML=PROVIDERS.map(p=>`<option value="${p.id}">${p.label}</option>`).join('');
 if(sel.provider)$('#provider').value=sel.provider;
 onProv();
}
function curP(){return PROVIDERS.find(p=>p.id===$('#provider').value)}
function onProv(){const p=curP();if(!p)return;
 $('#model').innerHTML=p.models.map(m=>`<option value="${m.id}">${m.label}</option>`).join('');
 const sel=LS.s;if(sel.provider===p.id&&sel.model)$('#model').value=sel.model;
 $('#providerNotes').textContent=p.notes||'';
 $('#localRow').style.display=(p.id==='local'||(p.base_url||'').includes('localhost'))?'block':'none';
 $('#baseUrl').value=(LS.b[p.id]||p.base_url||'');$('#apiKey').value=(LS.k[p.id]||'');
 $('#keyState').textContent=p.server_key?'(server key detected — optional)':'';
 $('#searchCap').textContent=p.web_search
   ? '✓ This model can search the web on its own using your key.'
   : '• This provider has no live web search — it will use its built-in knowledge plus any URLs/files you add.';
 if($('#searchDisabled')) $('#searchDisabled').textContent=p.web_search?'':'(this provider has no live web search — uses model knowledge + your URLs/files)';
}
function goStep(n){$$('.wstep').forEach(w=>w.classList.remove('active'));$('#w'+n).classList.add('active');
 $$('.stepdot').forEach(d=>{const k=+d.dataset.dot;d.classList.toggle('active',k===n);d.classList.toggle('done',k<n)});
 $('#results').classList.add('hidden');$('#wizard').classList.remove('hidden');window.scrollTo(0,0);}
function saveStep1(){const p=curP();if(!p)return;
 const ks=LS.k;ks[p.id]=$('#apiKey').value.trim();LS.k=ks;
 const bs=LS.b;bs[p.id]=$('#baseUrl').value.trim();LS.b=bs;
 LS.s={provider:p.id,model:($('#customModel').value.trim()||$('#model').value)};}
function cfg(){const p=curP();return{provider:p.id,model:($('#customModel').value.trim()||$('#model').value),
 api_key:$('#apiKey').value.trim(),base_url:$('#baseUrl').value.trim()||p.base_url};}

function wire(){
 $('#provider').addEventListener('change',onProv);
 $('#aiNext').addEventListener('click',verifyKey);
 $('#clearKey').addEventListener('click',()=>{localStorage.clear();$('#apiKey').value='';setStatus('#keyMsg','Cleared saved keys.','');});
 $$('[data-next]').forEach(b=>b.addEventListener('click',()=>{if(b.dataset.next==='3'&&!$('#target').value.trim()){alert('Describe the component first.');return}goStep(+b.dataset.next)}));
 $$('[data-back]').forEach(b=>b.addEventListener('click',()=>goStep(+b.dataset.back)));
 $('#identifyBtn').addEventListener('click',identify);
 $('#settingsBtn').addEventListener('click',()=>goStep(1));
 $('#savedBtn').addEventListener('click',openSaved);$('#closeSaved').addEventListener('click',()=>$('#savedPanel').classList.add('hidden'));
 $('#newBtn').addEventListener('click',()=>{STATE={session:null,classification:null,artifacts:[],id:null,report:null};$('#artifactList').innerHTML='';$('#urls').value='';$('#target').value='';$('#scope').value='';goStep(2);});
 $('#pdfBtn').addEventListener('click',dlPdf);$('#htmlBtn').addEventListener('click',dlHtml);
 $('#tm-back').addEventListener('click',()=>{$('#typeModal').classList.add('hidden');goStep(3);});
 $('#tm-go').addEventListener('click',generate);
 $('#w4retry').addEventListener('click',()=>{w4busy();retryLast();});
 $('#w4edit').addEventListener('click',()=>{w4busy();goStep(3);});
 $('#w4settings').addEventListener('click',()=>{w4busy();goStep(1);});
 $('#refineSend').addEventListener('click',refine);
 $('#refineMsg').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter')refine();});
 setupDrop();
}
function setStatus(sel,msg,cls){const el=$(sel);el.textContent=msg;el.className='status'+(cls?' '+cls:'');}

async function verifyKey(){
 saveStep1();const c=cfg();setStatus('#keyMsg','Verifying key…','');
 $('#aiNext').disabled=true;
 try{const r=await fetch('/api/validate_key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(c)}).then(x=>x.json());
  if(!r.ok){setStatus('#keyMsg',r.message||'Key check failed.','err');$('#aiNext').disabled=false;return;}
  setStatus('#keyMsg','Key verified.','ok');$('#aiNext').disabled=false;goStep(2);
 }catch(e){setStatus('#keyMsg','Error: '+e,'err');$('#aiNext').disabled=false;}
}

function setupDrop(){
 const d=$('#drop'),fi=$('#fileInput');
 d.addEventListener('click',()=>fi.click());
 d.addEventListener('dragover',e=>{e.preventDefault();d.classList.add('hot')});
 d.addEventListener('dragleave',()=>d.classList.remove('hot'));
 d.addEventListener('drop',e=>{e.preventDefault();d.classList.remove('hot');addFiles(e.dataTransfer.files)});
 fi.addEventListener('change',()=>addFiles(fi.files));
}
function b64(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(file)});}
async function addFiles(files){
 const arr=[...files];if(!arr.length)return;
 const payload={files:[]};
 for(const f of arr){payload.files.push({filename:f.name,b64:await b64(f)})}
 setStatus('#w4status','',''); // no-op
 const r=await fetch('/api/artifacts/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(x=>x.json());
 for(const a of r.artifacts){STATE.artifacts.push(a)}
 renderArtifacts();
}
function renderArtifacts(){
 $('#artifactList').innerHTML=STATE.artifacts.map((a,i)=>{
  const w=(a.warnings&&a.warnings.length)?` — <span class="muted">${a.warnings[0]}</span>`:'';
  const meta=a.is_image?'image':(a.text_len?`${a.text_len.toLocaleString()} chars`:'no text');
  return `<li><span>📄 ${a.filename} <span class="muted">(${meta})</span>${w}</span><button class="ghost" style="padding:3px 9px" onclick="rmArt(${i})">×</button></li>`;
 }).join('');
}
window.rmArt=i=>{STATE.artifacts.splice(i,1);renderArtifacts();};

function urlsList(){return $('#urls').value.split('\n').map(s=>s.trim()).filter(Boolean);}
function genPayload(){const c=cfg();return{...c,target:$('#target').value.trim(),scope:$('#scope').value.trim(),
 artifacts:STATE.artifacts,urls:urlsList(),do_search:$('#doSearch').checked,search_query:$('#target').value.trim()};}

function sseFetch(url,body,{onProgress,onDone,onError}){
 fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(async resp=>{
  const reader=resp.body.getReader();const dec=new TextDecoder();let buf='';
  while(true){const{done,value}=await reader.read();if(done)break;buf+=dec.decode(value,{stream:true});
   const parts=buf.split('\n\n');buf=parts.pop();
   for(const p of parts){const ev=/event: (.*)/.exec(p),da=/data: ([\s\S]*)/.exec(p);
    if(!ev||!da)continue;const type=ev[1].trim();let d={};try{d=JSON.parse(da[1])}catch(_){}
    if(type==='progress')onProgress&&onProgress(d.message||'');
    else if(type==='done')onDone&&onDone(d);
    else if(type==='error')onError&&onError(d.message||'error');}}
 }).catch(e=>onError&&onError(''+e));
}

let LAST_ACTION=null;
function w4busy(){$('#w4actions').classList.add('hidden');$('#w4hint').classList.add('hidden');}
function friendlyError(m){
 m=m||'Something went wrong.';
 const low=m.toLowerCase();
 if(/credit|billing|too low|insufficient|quota|payment|402/.test(low)){
   let anth=/anthropic/.test(low);
   let tip='This is an account/billing issue at your AI provider, not the tool — the provider rejected the request. ';
   if(anth) tip+='If you just bought credits but still see this on Anthropic: (1) make sure you purchased <b>API credits in the Anthropic Console</b> (console.anthropic.com → Settings → Billing) — a Claude.ai Pro/Max subscription does NOT add API credits; (2) confirm the credits are in the <b>same Organization/Workspace</b> your key belongs to (org switcher, top-left in the Console); (3) <b>create a fresh API key</b> and paste it — a stale key can bill-fail even when your balance is positive. ';
   else tip+='Confirm a positive balance and that the payment cleared with your provider. ';
   tip+='Or click <b>Change model / key</b> to switch to another provider (OpenAI, Google, DeepSeek, or a local model), then <b>Retry</b>. Your inputs are all preserved.';
   return {tip:tip,raw:m};
 }
 if(/401|403|rejected|api key|unauthorized|invalid.*key/.test(low))
   return {tip:'Your API key was rejected. Click <b>Change model / key</b> to re-enter it, then <b>Retry</b>.',raw:m};
 if(/rate limit|429|overloaded|529|timeout|timed out|temporarily/.test(low))
   return {tip:'The provider is rate-limited or busy. Wait a few seconds, then click <b>Retry</b> — nothing was lost.',raw:m};
 if(/connection|network|reach|urlerror/.test(low))
   return {tip:'Could not reach the provider. Check your connection, then click <b>Retry</b>.',raw:m};
 return {tip:'Click <b>Retry</b> to try again — your inputs are preserved. If it persists, try Change model / key or Edit sources.',raw:m};
}
function w4error(m){
 const f=friendlyError(m);
 setStatus('#w4status',f.raw,'err');
 $('#w4hint').innerHTML=f.tip;$('#w4hint').classList.remove('hidden');
 $('#w4actions').classList.remove('hidden');
}
function retryLast(){if(LAST_ACTION)LAST_ACTION();}

function identify(){
 if(!$('#target').value.trim()){alert('Describe the component first.');return;}
 LAST_ACTION=identify;w4busy();
 goStep(4);$('#w4h').textContent='Identifying the component…';
 $('#w4sub').textContent='Reading your sources (URLs, uploads, web search) and determining the 62443-4-2 component type.';
 $('#w4stream').classList.remove('hidden');$('#w4stream').textContent='';
 setStatus('#w4status','Starting…','');
 sseFetch('/api/classify/stream',genPayload(),{
  onProgress:m=>{$('#w4stream').textContent+=m+'\n';$('#w4stream').scrollTop=1e9;setStatus('#w4status',m,'');},
  onError:m=>{w4error(m);},
  onDone:d=>{if(d&&d.error){w4error(d.error);return;}STATE.session=d.session;STATE.classification=d.classification;STATE.sources=d.sources||[];showTypeModal(d.classification);}
 });
}

function showTypeModal(c){
 setStatus('#w4status','Identified.','ok');
 $('#tm-conf').textContent=`Detected: ${c.component_type_label||''} — confidence ${c.confidence||'?'}`;
 $('#tm-product').value=c.product||$('#target').value.trim();
 $('#tm-reason').textContent=c.reasoning||'';
 const facts=(c.key_facts||[]);
 $('#tm-facts').innerHTML=facts.length?('<b class="muted" style="font-size:12px">Key facts:</b><ul class="facts">'+facts.map(f=>`<li>${esc(f)}</li>`).join('')+'</ul>'):'';
 const codes=c.component_type_codes||['EDR'];
 $('#tm-types').innerHTML=Object.entries(CTYPES).map(([code,label])=>{
  const on=codes.includes(code);
  return `<label class="typecard ${on?'sel':''}"><input type="checkbox" value="${code}" ${on?'checked':''} onchange="this.closest('.typecard').classList.toggle('sel',this.checked)"><div><b>${code}</b> — <span class="d">${label}</span></div></label>`;
 }).join('');
 const src=STATE.sources||[];
 $('#tm-sources').innerHTML=src.length?('<b>Sources used:</b> '+src.map(s=>`<a class="dl" href="${s.url}" target="_blank" rel="noopener">${esc(s.title||s.url)}</a>`).join(' · ')):'';
 $('#typeModal').classList.remove('hidden');
}

function generate(){
 const codes=$$('#tm-types input:checked').map(i=>i.value);
 if(!codes.length){alert('Pick at least one component type.');return;}
 const label=codes.map(c=>CTYPES[c]).join(' + ');
 // remember the confirmed type so Retry works even after the modal is closed
 STATE.genCodes=codes;STATE.genLabel=label;STATE.genProduct=($('#tm-product').value.trim()||STATE.genProduct||'');
 $('#typeModal').classList.add('hidden');
 LAST_ACTION=regenerate;
 regenerate();
}
function regenerate(){
 const codes=STATE.genCodes||['EDR'];const label=STATE.genLabel||'';
 LAST_ACTION=regenerate;w4busy();
 goStep(4);$('#w4h').textContent='Building the SL-3 cheat sheet…';
 $('#w4sub').textContent='Mapping every FR1–FR7 requirement (SR/CR + '+codes.join('/')+') to product-specific test steps.';
 $('#w4stream').classList.remove('hidden');$('#w4stream').textContent='';setStatus('#w4status','Starting…','');
 const body={...genPayload(),session:STATE.session,component_type_codes:codes,component_type_label:label,
   product:STATE.genProduct,classification:STATE.classification};
 sseFetch('/api/generate/stream',body,{
  onProgress:m=>{$('#w4stream').textContent+=m+'\n';$('#w4stream').scrollTop=1e9;setStatus('#w4status',m,'');},
  onError:m=>{w4error(m);},
  onDone:d=>{if(d&&d.error){w4error(d.error);return;}showResults(d);}
 });
}

function showResults(d){
 STATE.id=d.id;STATE.report=d.report;STATE.reportlab=d.reportlab;
 $('#wizard').classList.add('hidden');$('#results').classList.remove('hidden');
 const rep=d.report||{};
 $('#r-title').textContent=(rep.product||'SL-3 Cheat Sheet');
 $('#r-meta').textContent=`${rep.component_type_label||''} · Target ${rep.target_sl||'SL 3'}`+(d.missing&&d.missing.length?` · ⚠ check: ${d.missing.join(', ')}`:'');
 $('#sheet').innerHTML=d.html||'';
 $('#pdfBtn').style.display=d.reportlab?'inline-block':'none';
 window.scrollTo(0,0);
}
function dlPdf(){if(STATE.id)window.location='/api/checklists/'+STATE.id+'/pdf';}
function dlHtml(){if(STATE.id)window.open('/api/checklists/'+STATE.id+'/html','_blank');}

function refine(){
 const ins=$('#refineMsg').value.trim();if(!ins||!STATE.id)return;
 const c=cfg();$('#refineSend').disabled=true;setStatus('#refineStatus','Applying your change…','');
 const body={...c,id:STATE.id,instruction:ins};
 sseFetch('/api/refine/stream',body,{
  onProgress:m=>{setStatus('#refineStatus',m,'');},
  onError:m=>{$('#refineSend').disabled=false;const f=friendlyError(m);setStatus('#refineStatus',f.raw,'err');},
  onDone:d=>{$('#refineSend').disabled=false;
   if(d&&d.error){setStatus('#refineStatus',d.error,'err');return;}
   STATE.report=d.report;$('#sheet').innerHTML=d.html||'';$('#refineMsg').value='';
   setStatus('#refineStatus','Updated'+(d.missing&&d.missing.length?(' · check: '+d.missing.join(', ')):'.'),'ok');
   window.scrollTo(0,0);}
 });
}

async function openSaved(){
 $('#savedPanel').classList.remove('hidden');
 const r=await fetch('/api/checklists').then(x=>x.json());
 $('#savedList').innerHTML=(r.checklists||[]).map(c=>`<li onclick="loadSaved('${c.id}')"><b>${esc(c.title||c.product||'—')}</b><br><span class="muted">${c.type_codes||''} · ${c.model||''} · ${c.created_at||''}</span> <button class="ghost" style="padding:2px 8px;float:right" onclick="event.stopPropagation();delSaved('${c.id}')">del</button></li>`).join('')||'<li class="muted">No saved checklists yet.</li>';
}
window.loadSaved=async id=>{const m=await fetch('/api/checklists/'+id).then(x=>x.json());
 STATE.id=id;STATE.report=m.report;STATE.reportlab=m.reportlab;
 $('#savedPanel').classList.add('hidden');$('#wizard').classList.add('hidden');$('#results').classList.remove('hidden');
 $('#r-title').textContent=m.product||'SL-3 Cheat Sheet';$('#r-meta').textContent=`${(m.report||{}).component_type_label||''} · ${m.created_at||''}`;
 $('#sheet').innerHTML=m.html||'';$('#pdfBtn').style.display=m.reportlab?'inline-block':'none';window.scrollTo(0,0);};
window.delSaved=async id=>{await fetch('/api/checklists/'+id,{method:'DELETE'});openSaved();};
function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
init();
</script>
</body></html>'''


# =============================================================================
#  SECTION 12 — ENTRYPOINT
# =============================================================================
def main():
    global DB_PATH
    ap = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 ics_62443_sl3_checklist_generator.py\n"
               "  python3 ics_62443_sl3_checklist_generator.py --port 9000 --open\n"
               "  ANTHROPIC_API_KEY=sk-ant-... python3 ics_62443_sl3_checklist_generator.py")
    ap.add_argument("--host", default=os.environ.get("ICG_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("ICG_PORT", "8010")))
    ap.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path for saved checklists")
    ap.add_argument("--open", action="store_true", help="Open the UI in a browser on start")
    ap.add_argument("--stats", action="store_true", help="Print the embedded 62443 catalog counts and exit")
    args = ap.parse_args()

    DB_PATH = args.db
    if args.stats:
        for k, v in catalog_stats().items():
            print(f"  {k:16} {v}")
        print("  native PDF        yes (no third-party dependencies)")
        return

    try:
        db_init()
    except Exception as e:  # noqa: BLE001
        print(f"\n[ERROR] Could not initialize the database at {DB_PATH}:\n  {e}\n"
              f"  Try a writable location, e.g.:  python3 ics_62443_sl3_checklist_generator.py --db checklists.db")
        _pause_if_windowed()
        return

    server = None
    port = args.port
    for candidate in range(args.port, args.port + 21):
        try:
            server = ThreadingHTTPServer((args.host, candidate), Handler)
            port = candidate
            break
        except OSError as e:
            if candidate == args.port:
                print(f"  Port {args.port} is busy ({e.strerror or e}); trying another…")
            continue
    if server is None:
        print(f"\n[ERROR] Could not bind to {args.host} on ports {args.port}-{args.port + 20}.")
        _pause_if_windowed()
        return

    url = f"http://{args.host}:{port}"
    print("=" * 70)
    print(f"  {APP_NAME}  v{APP_VERSION}")
    print("  62443 catalog: " + ", ".join(f"{k} {v}" for k, v in catalog_stats().items()))
    print("  PDF engine: built-in (pure standard library — no dependencies to install)")
    print(f"  Serving at:  {url}")
    if port != args.port:
        print(f"  (requested port {args.port} was busy — using {port} instead)")
    print(f"  Saved checklists DB:  {DB_PATH}")
    print("  Press Ctrl+C to stop.")
    print("=" * 70)
    if args.open:
        threading.Thread(target=lambda: (time.sleep(1), webbrowser.open(url)), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


def _pause_if_windowed():
    try:
        if os.name == "nt" and sys.stdin and sys.stdin.isatty():
            input("\nPress Enter to close…")
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        import traceback
        print("\n[FATAL] The tool hit an unexpected error at startup:\n")
        traceback.print_exc()
        _pause_if_windowed()