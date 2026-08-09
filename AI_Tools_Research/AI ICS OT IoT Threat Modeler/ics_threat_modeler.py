#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ICS / OT / IoT  THREAT MODELER  —  single-file interactive threat-modeling tool
================================================================================

An open-source, model-agnostic threat-modeling agent for industrial control
systems, operational technology, and IoT devices, components, applications and
systems. Successor to the "IoT_OT_ICS_ThreatModeler" Agent.ai agent, rebuilt as
ONE self-contained Python file with a local web UI.

    $ python3 ics_threat_modeler.py            # serve on http://127.0.0.1:8000
    $ python3 ics_threat_modeler.py --port 9000 --open
    $ python3 ics_threat_modeler.py --help

Describe a target (e.g. "Siemens S7-1500 PLC"), optionally attach engineering
artifacts (P&ID, PFD, datasheets, manuals, functional design specs, SysML/UML),
pick ANY AI model, and generate a full threat model mapped to:

  * MITRE EMB3D(TM)          — device properties (PID), threats (TID), mitigations (MID)
  * MITRE ATT&CK(R) for ICS  — tactics, techniques (T0xxx), mitigations (M0xxx)
  * ISA/IEC 62443            — 3-3 system, 4-2 component, 4-1 lifecycle, 2-1 program
  * ISA-TR84.00.09           — safety / hazard / consequence (SIS/SIF) analysis
  * Attify IoT               — reverse-engineering / attack-surface methodology

Providers: Anthropic (Claude Opus 4.8, ...), OpenAI, Google Gemini, DeepSeek,
Kimi (Moonshot), and ANY local / OpenAI-compatible endpoint (Ollama, LM Studio,
vLLM, OpenRouter). Real-time streaming, interactive chat, artifact ingestion,
data-flow / attack diagrams, and print-to-PDF export — all in this one file.

DEPENDENCIES: Python 3.9+ standard library ONLY is required. Optional extras
enhance artifact parsing (pip install pypdf python-docx) and server-side PDF
(pip install reportlab); the tool runs and degrades gracefully without them.

FRAMEWORK DATA: The full EMB3D, ATT&CK-for-ICS, and (representative-to-full)
62443 / ISA-84 / Attify reference sets are embedded below. IDs and titles are
the frameworks' own; concise descriptions are paraphrased for mapping. The
frameworks remain the property of their owners (MITRE, ISA/IEC, Attify) — this
tool is not affiliated with or endorsed by them. Consult the primary sources
for authoritative, complete text:
  https://emb3d.mitre.org   https://attack.mitre.org/matrices/ics/
  https://www.isa.org       https://www.attify.com

License: MIT.  © 2026 contributors. Created by Isiah Jones.
================================================================================
"""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import socketserver
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone

APP_NAME = "ICS/OT/IoT Threat Modeler"
APP_VERSION = "3.7.1"
DEFAULT_DB = os.environ.get("ITM_DB", os.path.join(os.path.expanduser("~"), ".ics_threat_modeler.db"))

# =============================================================================
#  SECTION 1 — EMBEDDED FRAMEWORK DATA  (full EMB3D)
# =============================================================================
# Tuples kept compact: expanded to dicts by _build_indexes() at import time.

# --- EMB3D device properties: (PID, category, title) — full property tree ---
EMB3D_PROPERTIES = [
    # Hardware
    ("PID-11", "Hardware", "Device includes a microprocessor"),
    ("PID-12", "Hardware", "Device includes Memory/Storage (external to CPU)"),
    ("PID-121", "Hardware", "Device includes buses for external memory/storage"),
    ("PID-122", "Hardware", "Device includes discrete chips/devices with same physical memory access"),
    ("PID-123", "Hardware", "Device includes ROM, VRAM, or removable Storage"),
    ("PID-124", "Hardware", "Device includes Random Access Memory (RAM) chips"),
    ("PID-1241", "Hardware", "Device includes DDR DRAM"),
    ("PID-13", "Hardware", "Device includes peripheral chips and integrated data buses"),
    ("PID-14", "Hardware", "Device includes external peripheral interconnects (e.g., USB, Serial)"),
    ("PID-15", "Hardware", "Device includes a hardware access port (e.g., UART, JTAG)"),
    # System Software
    ("PID-21", "System Software", "Device includes a bootloader"),
    ("PID-22", "System Software", "Device includes debugging capabilities"),
    ("PID-23", "System Software", "Device includes OS/kernel"),
    ("PID-231", "System Software", "Device includes OS that uses loadable drivers/modules"),
    ("PID-232", "System Software", "Device includes separate users/processes with different OS data access"),
    ("PID-2321", "System Software", "Device lacks access enforcement/privilege mechanism"),
    ("PID-2322", "System Software", "Device deploys access enforcement/privilege mechanism"),
    ("PID-23221", "System Software", "Device includes and enforces OS user accounts"),
    ("PID-23222", "System Software", "Device includes memory management with access protections"),
    ("PID-24", "System Software", "Device includes virtualization and containers"),
    ("PID-241", "System Software", "Device includes containers"),
    ("PID-242", "System Software", "Device includes hypervisor"),
    ("PID-25", "System Software", "Device includes software/hardware root of trust"),
    ("PID-251", "System Software", "Root of Trust is physically accessible or not immutable"),
    ("PID-252", "System Software", "Root of Trust is immutable"),
    ("PID-26", "System Software", "Device lacks firmware/software update support"),
    ("PID-27", "System Software", "Device includes firmware/software update support"),
    ("PID-271", "System Software", "Device firmware/software lacks cryptographic integrity validation"),
    ("PID-272", "System Software", "Device includes cryptographic firmware/software integrity mechanisms"),
    ("PID-2721", "System Software", "Device includes shared key for firmware integrity validation"),
    ("PID-2722", "System Software", "Device includes digitally signed firmware (with private key)"),
    ("PID-273", "System Software", "Device has unencrypted firmware updates"),
    ("PID-274", "System Software", "Device includes user firmware/software version selection during updates"),
    ("PID-275", "System Software", "Device includes remotely-initiated firmware/software updates"),
    ("PID-28", "System Software", "Device stores logs of system events and information"),
    # Application Software
    ("PID-31", "Application Software", "Application-level software is present and running on device"),
    ("PID-311", "Application Software", "Device includes usage of web/HTTP applications"),
    ("PID-312", "Application Software", "Device includes programming languages and libraries"),
    ("PID-3121", "Application Software", "Device includes object-oriented programming language support"),
    ("PID-3122", "Application Software", "Device includes manual memory management language support"),
    ("PID-32", "Application Software", "Device includes ability to deploy custom or external programs"),
    ("PID-321", "Application Software", "Device includes ability to deploy custom programs from engineering software/IDE"),
    ("PID-322", "Application Software", "Device includes program runtime environment for custom/external programs"),
    ("PID-323", "Application Software", "Device includes support for program executable formats"),
    ("PID-3231", "Application Software", "Device includes ability to run custom programs as native binary without confinement"),
    ("PID-3232", "Application Software", "Device includes ability to run custom programs through sandboxed environment"),
    ("PID-324", "Application Software", "Device includes support for program uploads from engineering workstation"),
    ("PID-33", "Application Software", "Device includes interactive applications, services, or user interfaces"),
    ("PID-331", "Application Software", "Device includes unauthenticated services"),
    ("PID-332", "Application Software", "Device includes authenticated services"),
    ("PID-3321", "Application Software", "Device includes passwords to authenticate users"),
    ("PID-3322", "Application Software", "Device includes cryptographic mechanism to authenticate users/sessions"),
    ("PID-34", "Application Software", "Device stores logs of application events and information"),
    # Networking
    ("PID-41", "Networking", "Device exposes remote network services"),
    ("PID-411", "Networking", "Device exposes remote services for sensitive information/configuration modification"),
    ("PID-4111", "Networking", "Device lacks protocol support for message authentication"),
    ("PID-4112", "Networking", "Device lacks protocol support for message encryption"),
    ("PID-4113", "Networking", "Device includes cryptographic functions for sensitive data protection"),
    ("PID-42", "Networking", "Device includes procedure to forward or route network messages"),
]

# --- EMB3D threats: (TID, category, title, concise description) — full set ---
EMB3D_THREATS = [
    ("TID-101", "Hardware", "Power Consumption Analysis Side Channel", "Secrets/keys recovered by measuring power draw during cryptographic operations."),
    ("TID-102", "Hardware", "Electromagnetic Analysis Side Channel", "EM emanations during processing leak sensitive data or keys."),
    ("TID-103", "Hardware", "Microarchitectural Side Channels", "Shared CPU structures (caches, speculation) leak data across boundaries."),
    ("TID-105", "Hardware", "Hardware Fault Injection – Control Flow Modification", "Voltage/clock/EM glitching alters instruction flow to bypass checks (e.g., secure boot)."),
    ("TID-106", "Hardware", "Data Bus Interception", "Probing internal buses (CPU-to-flash) reveals code/data in transit."),
    ("TID-107", "Hardware", "Unauthorized Direct Memory Access (DMA)", "DMA-capable peripherals read/write memory regions they should not."),
    ("TID-108", "Hardware", "ROM/NVRAM Data Extraction or Modification", "Reading/altering non-volatile memory to extract secrets or implant code."),
    ("TID-109", "Hardware", "RAM Chip Contents Readout", "Cold-boot or physical readout of RAM recovers runtime secrets."),
    ("TID-110", "Hardware", "Hardware Fault Injection – Data Manipulation", "Glitching corrupts data values to influence logic or safety decisions."),
    ("TID-111", "Hardware", "Untrusted External Storage", "Firmware/config loaded from external storage without integrity checks."),
    ("TID-113", "Hardware", "Unverified Peripheral Firmware Loaded", "Peripheral firmware loaded without authenticity/integrity verification."),
    ("TID-114", "Hardware", "Peripheral Data Bus Interception", "Sniffing a peripheral bus (SPI/I2C/USB) exposes exchanged data."),
    ("TID-115", "Hardware", "Firmware/Data Extraction via Hardware Interface", "Debug/programming interfaces used to dump firmware or memory."),
    ("TID-116", "Hardware", "Latent Privileged Access Port", "Undocumented/leftover ports grant privileged access."),
    ("TID-118", "Hardware", "Weak Peripheral Port Electrical Damage Protection", "Ports lack protection against electrical/ESD attacks causing damage or DoS."),
    ("TID-119", "Hardware", "Latent Hardware Debug Port Allows Memory/Code Manipulation", "Enabled JTAG/SWD permits memory read/write and code injection."),
    ("TID-201", "System Software", "Inadequate Bootloader Protection and Verification", "Bootloader does not verify authenticity/integrity of loaded images."),
    ("TID-202", "System Software", "Exploitable System Network Stack Component", "Vulnerabilities in the network stack enable remote compromise."),
    ("TID-203", "System Software", "Malicious OS Kernel Driver/Module Installable", "Unsigned or unverified kernel modules/drivers can be loaded."),
    ("TID-204", "System Software", "Untrusted Programs Can Access Privileged OS Functions", "Insufficient privilege separation exposes privileged OS functions."),
    ("TID-205", "System Software", "Existing OS Tools Maliciously Used for Device Manipulation", "Living-off-the-land abuse of built-in OS tools."),
    ("TID-206", "System Software", "Memory Management Protections Subverted", "MMU/MPU/ASLR/DEP protections missing or bypassable."),
    ("TID-207", "System Software", "Container Escape", "A process escapes container isolation to the host."),
    ("TID-208", "System Software", "Virtual Machine Escape", "A guest escapes hypervisor isolation."),
    ("TID-209", "System Software", "Host Can Manipulate Guest Virtual Machines", "A compromised host tampers with guest VMs."),
    ("TID-210", "System Software", "Device Vulnerabilities Unpatchable", "No supported path exists to remediate known vulnerabilities."),
    ("TID-211", "System Software", "Device Allows Unauthenticated Firmware Installation", "Firmware can be installed without authentication."),
    ("TID-212", "System Software", "FW/SW Update Integrity Shared Secrets Extraction", "Shared integrity keys can be extracted to forge updates."),
    ("TID-213", "System Software", "Faulty FW/SW Update Integrity Verification", "Update integrity verification is flawed or bypassable."),
    ("TID-214", "System Software", "Secrets Extracted from Device Root of Trust", "Root-of-trust secrets can be extracted."),
    ("TID-215", "System Software", "Unencrypted SW/FW Updates", "Updates are transmitted/stored without encryption."),
    ("TID-216", "System Software", "Firmware Update Rollbacks Allowed", "Older, vulnerable firmware can be reinstalled (downgrade)."),
    ("TID-217", "System Software", "Remotely Initiated Updates Can Cause DoS", "A remote update can be triggered to deny service."),
    ("TID-218", "System Software", "Operating System Susceptible to Rootkit", "The OS can be persistently subverted by a rootkit."),
    ("TID-219", "System Software", "OS/Kernel Privilege Escalation", "Flaws allow escalation to OS/kernel privileges."),
    ("TID-220", "System Software", "Unpatchable Hardware Root of Trust", "A root-of-trust flaw cannot be fixed in the field."),
    ("TID-221", "System Software", "Authentication Bypass By Message Replay", "Replayed messages bypass authentication."),
    ("TID-222", "System Software", "Critical System Service May Be Disabled", "An attacker disables essential services."),
    ("TID-223", "System Software", "System Susceptible to RAM Scraping", "Secrets are scraped from process/system RAM."),
    ("TID-224", "System Software", "Excessive Access via Software Diagnostic Features", "Diagnostic features expose excessive access/functionality."),
    ("TID-225", "System Software", "Logs can be manipulated on the device", "Audit logs can be altered or deleted on-device."),
    ("TID-226", "System Software", "Device leaks security information in logs", "Logs disclose sensitive/security information."),
    ("TID-301", "Application Software", "Applications Binaries Modified", "On-device application binaries can be altered."),
    ("TID-302", "Application Software", "Install Untrusted Application", "Untrusted applications can be installed and run."),
    ("TID-303", "Application Software", "Excessive Trust in Offboard Management/IDE Software", "Device over-trusts engineering/IDE software."),
    ("TID-304", "Application Software", "Manipulate Runtime Environment", "The application runtime environment can be tampered."),
    ("TID-305", "Application Software", "Program Executes Dangerous System Calls", "Programs invoke dangerous system calls."),
    ("TID-306", "Application Software", "Sandboxed Environments Escaped", "Application sandbox can be escaped."),
    ("TID-307", "Application Software", "Device Code Representations Inconsistent", "Displayed vs. executing code differ, hiding malicious logic."),
    ("TID-308", "Application Software", "Code Overwritten to Avoid Detection", "Code is overwritten at runtime to evade detection."),
    ("TID-309", "Application Software", "Device Exploits Engineering Workstation", "A compromised device attacks the engineering workstation."),
    ("TID-310", "Application Software", "Remotely Accessible Unauthenticated Services", "Services are reachable remotely without authentication."),
    ("TID-311", "Application Software", "Default Credentials", "Default accounts/passwords are present."),
    ("TID-312", "Application Software", "Credential Change Mechanism Can Be Abused", "The credential-change flow can be abused."),
    ("TID-313", "Application Software", "Unauthenticated Session Changes Credential", "Credentials can be changed without authentication."),
    ("TID-314", "Application Software", "Passwords Can Be Guessed Using Brute-Force Attempts", "No effective brute-force protection."),
    ("TID-315", "Application Software", "Password Retrieval Mechanism Abused", "A recovery/retrieval flow is abused to obtain passwords."),
    ("TID-316", "Application Software", "Incorrect Certificate Verification Allows Authentication Bypass", "Flawed certificate validation enables MitM/bypass."),
    ("TID-317", "Application Software", "Predictable Cryptographic Key", "Cryptographic keys are predictable."),
    ("TID-318", "Application Software", "Insecure Cryptographic Implementation", "Broken or weak cryptographic implementation."),
    ("TID-319", "Application Software", "Cross Site Scripting (XSS)", "Device web UI is vulnerable to XSS."),
    ("TID-320", "Application Software", "SQL Injection", "Device application is vulnerable to SQL injection."),
    ("TID-321", "Application Software", "HTTP Application Session Hijacking", "Web sessions can be hijacked."),
    ("TID-322", "Application Software", "Cross Site Request Forgery (CSRF)", "Web UI is vulnerable to CSRF."),
    ("TID-323", "Application Software", "Path Traversal", "Path traversal grants unauthorized file access."),
    ("TID-324", "Application Software", "HTTP Direct Object Reference", "Insecure direct object reference (IDOR)."),
    ("TID-325", "Application Software", "HTTP Injection/Response Splitting", "HTTP header/response injection or splitting."),
    ("TID-326", "Application Software", "Insecure Deserialization", "Unsafe deserialization enables code execution."),
    ("TID-327", "Application Software", "Out of Bounds Memory Access", "Out-of-bounds read/write in application code."),
    ("TID-328", "Application Software", "Hardcoded Credentials", "Hardcoded credentials/secrets in the application."),
    ("TID-329", "Application Software", "Improper Password Storage", "Passwords stored with weak or no hashing."),
    ("TID-330", "Application Software", "Cryptographic Timing Side-Channel", "Timing side channel leaks cryptographic secrets."),
    ("TID-401", "Networking", "Undocumented Protocol Features", "Hidden/undocumented protocol features or backdoors."),
    ("TID-404", "Networking", "Remotely Triggerable Deadlock/DoS", "A remote input triggers deadlock or denial of service."),
    ("TID-405", "Networking", "Network Stack Resource Exhaustion", "Resource exhaustion via crafted network traffic."),
    ("TID-406", "Networking", "Unauthorized Messages or Connections", "Unauthenticated messages/connections are accepted."),
    ("TID-407", "Networking", "Missing Message Replay Protection", "No anti-replay for network messages."),
    ("TID-408", "Networking", "Unencrypted Sensitive Data Communication", "Sensitive data and commands sent in cleartext."),
    ("TID-410", "Networking", "Cryptographic Protocol Side Channel", "Protocol-level cryptographic side channel."),
    ("TID-411", "Networking", "Weak/Insecure Cryptographic Protocol", "Weak or broken cryptographic protocol."),
    ("TID-412", "Networking", "Network Routing Capability Abuse", "Routing/forwarding capability abused (pivot, spoof)."),
]

# --- EMB3D mitigations: (MID, title) — full set ---
EMB3D_MITIGATIONS = [
    ("MID-001", "Software Only Bootloader Authentication"),
    ("MID-002", "Hardware-backed Bootloader Authentication"),
    ("MID-003", "Periodic/Continuous Integrity Measurement and Remote Attestation"),
    ("MID-004", "Memory Hardening Against Code Injection"),
    ("MID-005", "Memory Safe Programming Languages"),
    ("MID-006", "Driver Memory Isolation"),
    ("MID-007", "Control Flow Manipulation Protections"),
    ("MID-008", "Decidable Protocols and Parsers"),
    ("MID-009", "Runtime System Integrity Checking"),
    ("MID-010", "No Runtime OS Driver Loading"),
    ("MID-011", "OS Driver/Peripheral Authentication"),
    ("MID-012", "OS-based Access Control Mechanisms"),
    ("MID-013", "Process and Thread Memory Segmentation"),
    ("MID-014", "Sandboxing"),
    ("MID-015", "Containerization"),
    ("MID-016", "Least Functionality"),
    ("MID-017", "Security-relevant Auditing and Logging"),
    ("MID-018", "Require Authentication for Privileged Functions"),
    ("MID-019", "ROP Gadget Minimization"),
    ("MID-020", "Pointer Authentication"),
    ("MID-021", "VM Hardening"),
    ("MID-022", "Segmentation Through Hardware-assisted VMs"),
    ("MID-023", "Hypervisor Hardening"),
    ("MID-024", "Encrypted VM Isolation"),
    ("MID-025", "End-of-Life Management Features"),
    ("MID-026", "Secure Firmware Update"),
    ("MID-027", "Validated Cryptographic Libraries"),
    ("MID-028", "Hardware-backed Key Storage"),
    ("MID-029", "Hardware Root of Trust"),
    ("MID-030", "Firmware Rollback Protections"),
    ("MID-031", "Physical Presence Validation"),
    ("MID-032", "System Service Availability Manager"),
    ("MID-033", "Unique and Unpredictable Factory Preinstalled Secret Keys"),
    ("MID-034", "Authenticate Network Messages"),
    ("MID-035", "Encrypt Network Traffic"),
    ("MID-036", "Cryptographic Nonces"),
    ("MID-037", "Network Timestamps"),
    ("MID-038", "Authenticate for Administrative Actions"),
    ("MID-039", "Restrict Software Diagnostic Functions"),
    ("MID-040", "Cryptographically Signed Custom Programs"),
    ("MID-041", "Cryptographically Signed Vendor-supplied Programs"),
    ("MID-042", "Device Checks Consistency Between Binary/Running Code and Textual Code"),
    ("MID-043", "Manage Default Login Credentials"),
    ("MID-044", "Strong Cryptographic Algorithms and Protocols"),
    ("MID-045", "Multi-factor Authentication"),
    ("MID-046", "Authentication Attempts Timeouts and Lockouts"),
    ("MID-047", "Sufficient Entropy for Keys"),
    ("MID-048", "Hardware Random Number Generator"),
    ("MID-049", "Secure Password Storage"),
    ("MID-050", "Operating System Defenses Against Microarchitecture Feature Side Channels"),
    ("MID-051", "Disallow User-Provided Code"),
    ("MID-052", "Physically Protect Circuit Board Traces and Chip Pins"),
    ("MID-053", "Use IOMMU to Implement DMA Access Controls"),
    ("MID-054", "Encrypt and Authenticate Non-volatile Storage Contents"),
    ("MID-055", "Use Highly Integrated Processors to Avoid Physical Attacks"),
    ("MID-056", "Allow Device Administrators to Disable Removable Storage Support"),
    ("MID-057", "Disable Physical Development and Debugging Ports"),
    ("MID-058", "Engage Hardware Readout Protection Mechanisms"),
    ("MID-059", "Software Patterns for Side Channel Resistance"),
    ("MID-060", "Dedicated Hardware Cryptographic Modules"),
    ("MID-061", "Use Separate Processors for Isolation"),
    ("MID-062", "Hardware Mitigations for Fault Injection"),
    ("MID-063", "Software Mitigations for Fault Injection"),
    ("MID-064", "Store Critical Code and Data in On-Chip Memory"),
    ("MID-065", "RAM Encryption"),
    ("MID-066", "Implement Redundant Processing and Memory"),
    ("MID-067", "Implement RowHammer-resistant DRAM and Memory Controllers"),
    ("MID-068", "Data Bus Encryption and Message Authentication"),
    ("MID-069", "Electrical Fault Protection"),
    ("MID-070", "Peripheral Component Authentication"),
    ("MID-071", "Sanitized and Escaped User Data for Web Applications"),
    ("MID-072", "Parameterized SQL Queries"),
    ("MID-073", "Secure HTTP Session Management"),
    ("MID-074", "Cross Site Request Forgery Mitigations"),
    ("MID-075", "Path Traversal Protections"),
    ("MID-076", "Web Direct Object Reference Authentication"),
    ("MID-077", "Secure Deserialization"),
    ("MID-078", "HTTP Request/Response Validation"),
    ("MID-079", "Remove Undocumented Network Functionality"),
    ("MID-080", "Network Request Processing Limits"),
    ("MID-081", "Secure Network Tunnels"),
    ("MID-082", "Post-quantum Cryptography"),
    ("MID-083", "Network Firewall/Access Control List"),
    ("MID-084", "Restrict Sensitive Data from Logs"),
    ("MID-085", "Export Logs Over the Network Off of Device"),
    ("MID-086", "Hardware Enforcement of Memory Access"),
    ("MID-087", "Utilization of Formally Verified OS (Micro-)Kernels"),
    ("MID-088", "Formally Verified Parsers"),
    ("MID-089", "Formal Methods Verification of Critical Functionality Implementation"),
]

# =============================================================================
#  SECTION 2 — EMBEDDED FRAMEWORK DATA  (full MITRE ATT&CK for ICS)
# =============================================================================

# --- Tactics: (id, name, description) ---
ATTACK_ICS_TACTICS = [
    ("TA0108", "Initial Access", "Techniques to gain an initial foothold within the ICS/OT environment."),
    ("TA0104", "Execution", "Techniques that run adversary-controlled code on ICS devices/systems."),
    ("TA0110", "Persistence", "Techniques to maintain access across restarts and credential changes."),
    ("TA0111", "Privilege Escalation", "Techniques to gain higher-level permissions."),
    ("TA0103", "Evasion", "Techniques to avoid detection and defenses."),
    ("TA0102", "Discovery", "Techniques to learn about the ICS environment and assets."),
    ("TA0109", "Lateral Movement", "Techniques to move through the environment toward targets."),
    ("TA0100", "Collection", "Techniques to gather data of interest (process, engineering, operational)."),
    ("TA0101", "Command and Control", "Techniques to communicate with and control compromised systems."),
    ("TA0107", "Inhibit Response Function", "Techniques to prevent safety/protection/response functions from working."),
    ("TA0106", "Impair Process Control", "Techniques to manipulate, disable, or damage physical control processes."),
    ("TA0105", "Impact", "Techniques whose consequence is loss/damage to process, property, or safety."),
]

# --- Techniques: (id, name, [tactics], description) — full ICS technique set ---
ATTACK_ICS_TECHNIQUES = [
    ("T0800", "Activate Firmware Update Mode", ["Inhibit Response Function"], "Put a device into firmware-update mode to render it non-responsive."),
    ("T0801", "Monitor Process State", ["Collection"], "Observe process state to time or guide an attack."),
    ("T0802", "Automated Collection", ["Collection"], "Automatically gather process/engineering data."),
    ("T0803", "Block Command Message", ["Inhibit Response Function"], "Block command messages from reaching devices."),
    ("T0804", "Block Reporting Message", ["Inhibit Response Function"], "Block reporting/telemetry from reaching operators."),
    ("T0805", "Block Serial COM", ["Inhibit Response Function"], "Block serial communications to disrupt control/response."),
    ("T0806", "Brute Force I/O", ["Impair Process Control"], "Rapidly manipulate I/O to disrupt or damage the process."),
    ("T0807", "Command-Line Interface", ["Execution"], "Use a device/OS command line to execute actions."),
    ("T0809", "Data Destruction", ["Inhibit Response Function", "Impact"], "Destroy data on systems/devices."),
    ("T0811", "Data from Information Repositories", ["Collection"], "Collect data from historians/engineering repositories."),
    ("T0812", "Default Credentials", ["Lateral Movement"], "Use default credentials to access devices/services."),
    ("T0813", "Denial of Control", ["Impact"], "Deny operators the ability to control the process."),
    ("T0814", "Denial of Service", ["Inhibit Response Function"], "Exhaust or crash devices to deny service."),
    ("T0815", "Denial of View", ["Impact"], "Deny operators visibility into the process."),
    ("T0816", "Device Restart/Shutdown", ["Inhibit Response Function"], "Restart or shut down devices to disrupt function."),
    ("T0817", "Drive-by Compromise", ["Initial Access"], "Gain access via a user visiting a compromised resource."),
    ("T0819", "Exploit Public-Facing Application", ["Initial Access"], "Exploit an exposed application to enter the environment."),
    ("T0820", "Exploitation for Evasion", ["Evasion"], "Exploit flaws to bypass or disable defenses."),
    ("T0821", "Modify Controller Tasking", ["Execution", "Impair Process Control"], "Alter the tasks/scan cycle a controller executes."),
    ("T0822", "External Remote Services", ["Initial Access"], "Use exposed remote services (VPN, RDP, vendor access) for entry."),
    ("T0823", "Graphical User Interface", ["Execution"], "Use an HMI/engineering GUI to perform actions."),
    ("T0826", "Loss of Availability", ["Impact"], "Make the process/service unavailable."),
    ("T0827", "Loss of Control", ["Impact"], "Operators lose the ability to control the process."),
    ("T0828", "Loss of Productivity and Revenue", ["Impact"], "Disruption reduces production/revenue."),
    ("T0829", "Loss of View", ["Impact"], "Operators lose visibility of the process."),
    ("T0830", "Adversary-in-the-Middle", ["Collection"], "Intercept/relay communications to read or alter them."),
    ("T0831", "Manipulation of Control", ["Impair Process Control"], "Manipulate control to alter the physical process."),
    ("T0832", "Manipulation of View", ["Impact"], "Falsify what operators see about the process."),
    ("T0834", "Native API", ["Execution"], "Use native controller functions/APIs to execute logic."),
    ("T0835", "Manipulate I/O Image", ["Impair Process Control"], "Alter the controller I/O image to change state."),
    ("T0836", "Modify Parameter", ["Impair Process Control"], "Change setpoints/parameters to affect the process."),
    ("T0837", "Loss of Protection", ["Impact"], "Protective/safety functions are lost."),
    ("T0838", "Modify Alarm Settings", ["Inhibit Response Function"], "Change alarm thresholds/settings to hide unsafe states."),
    ("T0839", "Module Firmware", ["Persistence", "Impair Process Control"], "Implant malicious firmware in a module/peripheral."),
    ("T0840", "Network Connection Enumeration", ["Discovery"], "Enumerate network connections and relationships."),
    ("T0842", "Network Sniffing", ["Discovery", "Collection"], "Capture network traffic to learn assets and data."),
    ("T0843", "Program Download", ["Lateral Movement", "Impair Process Control"], "Download a program/logic to a controller."),
    ("T0845", "Program Upload", ["Collection"], "Upload a controller program to analyze or clone logic."),
    ("T0846", "Remote System Discovery", ["Discovery"], "Identify remote systems/devices on the network."),
    ("T0847", "Replication Through Removable Media", ["Initial Access", "Lateral Movement"], "Spread via USB/removable media into isolated networks."),
    ("T0848", "Rogue Master", ["Initial Access"], "Pose as a master/controller to issue commands to field devices."),
    ("T0849", "Masquerading", ["Evasion"], "Disguise malicious files/traffic as legitimate."),
    ("T0851", "Rootkit", ["Evasion", "Inhibit Response Function"], "Conceal presence at OS/firmware level."),
    ("T0852", "Screen Capture", ["Collection"], "Capture HMI/engineering screens."),
    ("T0853", "Scripting", ["Execution"], "Use scripting to automate malicious actions."),
    ("T0855", "Unauthorized Command Message", ["Impair Process Control"], "Send unauthorized commands to devices to manipulate the process."),
    ("T0856", "Spoof Reporting Message", ["Evasion", "Impair Process Control"], "Send falsified reporting/telemetry to mask manipulation."),
    ("T0857", "System Firmware", ["Persistence", "Inhibit Response Function"], "Modify device system firmware to persist or disable functions."),
    ("T0858", "Change Operating Mode", ["Execution", "Evasion", "Impair Process Control"], "Switch controller mode (e.g., to program/remote) to enable changes."),
    ("T0859", "Valid Accounts", ["Persistence", "Lateral Movement", "Initial Access"], "Use legitimate credentials to access and persist."),
    ("T0860", "Wireless Compromise", ["Initial Access"], "Gain access over a wireless (RF) interface."),
    ("T0861", "Point & Tag Identification", ["Collection"], "Identify process points/tags to understand and target the process."),
    ("T0862", "Supply Chain Compromise", ["Initial Access"], "Compromise hardware/software/firmware before it reaches the target."),
    ("T0863", "User Execution", ["Execution"], "Rely on a user to run malicious content."),
    ("T0864", "Transient Cyber Asset", ["Initial Access"], "Use engineering laptops/tools that move in and out of the OT network."),
    ("T0865", "Spearphishing Attachment", ["Initial Access"], "Deliver malware via a targeted email attachment."),
    ("T0866", "Exploitation of Remote Services", ["Initial Access", "Lateral Movement"], "Exploit remote services to gain access or move laterally."),
    ("T0867", "Lateral Tool Transfer", ["Lateral Movement"], "Transfer tools/malware between systems in the environment."),
    ("T0868", "Detect Operating Mode", ["Collection"], "Determine a controller's current operating mode."),
    ("T0869", "Standard Application Layer Protocol", ["Command and Control"], "Use standard protocols for C2 to blend in."),
    ("T0871", "Execution through API", ["Execution"], "Invoke device/vendor APIs to execute functionality."),
    ("T0872", "Indicator Removal on Host", ["Evasion"], "Delete logs/artifacts to hide activity."),
    ("T0873", "Project File Infection", ["Persistence"], "Infect engineering project files to persist and spread."),
    ("T0874", "Hooking", ["Privilege Escalation", "Persistence"], "Hook APIs/functions to intercept execution or escalate."),
    ("T0877", "I/O Image", ["Collection"], "Read the controller I/O image to understand process state."),
    ("T0878", "Alarm Suppression", ["Inhibit Response Function"], "Suppress alarms so operators do not detect abnormal conditions."),
    ("T0879", "Damage to Property", ["Impact"], "Cause physical damage to equipment/property."),
    ("T0880", "Loss of Safety", ["Impact"], "Loss of the safety function, risking harm to people/environment."),
    ("T0881", "Service Stop", ["Inhibit Response Function"], "Stop services to inhibit response/safety functions."),
    ("T0882", "Theft of Operational Information", ["Collection", "Impact"], "Exfiltrate operational/engineering information."),
    ("T0883", "Internet Accessible Device", ["Initial Access"], "Directly reach ICS devices exposed to the Internet."),
    ("T0884", "Connection Proxy", ["Command and Control"], "Relay C2 through a proxy to hide origin."),
    ("T0885", "Commonly Used Port", ["Command and Control"], "Blend C2 into commonly used ports."),
    ("T0886", "Remote Services", ["Lateral Movement"], "Use remote services to move between systems."),
    ("T0887", "Wireless Sniffing", ["Discovery", "Collection"], "Sniff wireless communications for data/assets."),
    ("T0888", "Remote System Information Discovery", ["Discovery"], "Query devices for type, firmware, and configuration."),
    ("T0889", "Modify Program", ["Persistence", "Impair Process Control"], "Change the control program/logic on a device."),
    ("T0890", "Exploitation for Privilege Escalation", ["Privilege Escalation"], "Exploit a flaw to obtain higher privileges."),
    ("T0891", "Hardcoded Credentials", ["Persistence", "Lateral Movement"], "Use hardcoded/embedded credentials to access devices."),
    ("T0892", "Change Credential", ["Inhibit Response Function"], "Change credentials to lock out legitimate operators."),
    ("T0893", "Data from Local System", ["Collection"], "Collect data stored on the local device/system."),
]

# --- ATT&CK for ICS mitigations: (id, name) — full set ---
ATTACK_ICS_MITIGATIONS = [
    ("M0801", "Access Management"), ("M0936", "Account Use Policies"),
    ("M0915", "Active Directory Configuration"), ("M0949", "Antivirus/Antimalware"),
    ("M0913", "Application Developer Guidance"), ("M0948", "Application Isolation and Sandboxing"),
    ("M0947", "Audit"), ("M0800", "Authorization Enforcement"), ("M0946", "Boot Integrity"),
    ("M0945", "Code Signing"), ("M0802", "Communication Authenticity"), ("M0953", "Data Backup"),
    ("M0803", "Data Loss Prevention"), ("M0942", "Disable or Remove Feature or Program"),
    ("M0808", "Encrypt Network Traffic"), ("M0941", "Encrypt Sensitive Information"),
    ("M0938", "Execution Prevention"), ("M0950", "Exploit Protection"), ("M0937", "Filter Network Traffic"),
    ("M0804", "Human User Authentication"), ("M0935", "Limit Access to Resource Over Network"),
    ("M0934", "Limit Hardware Installation"), ("M0805", "Mechanical Protection Layers"),
    ("M0806", "Minimize Wireless Signal Propagation"), ("M0816", "Mitigation Limited or Not Effective"),
    ("M0932", "Multi-factor Authentication"), ("M0807", "Network Allowlists"),
    ("M0931", "Network Intrusion Prevention"), ("M0930", "Network Segmentation"),
    ("M0928", "Operating System Configuration"), ("M0809", "Operational Information Confidentiality"),
    ("M0810", "Out-of-Band Communications Channel"), ("M0927", "Password Policies"),
    ("M0926", "Privileged Account Management"), ("M0811", "Redundancy of Service"),
    ("M0922", "Restrict File and Directory Permissions"), ("M0944", "Restrict Library Loading"),
    ("M0924", "Restrict Registry Permissions"), ("M0921", "Restrict Web-Based Content"),
    ("M0812", "Safety Instrumented Systems"), ("M0954", "Software Configuration"),
    ("M0813", "Software Process and Device Authentication"), ("M0920", "SSL/TLS Inspection"),
    ("M0814", "Static Network Configuration"), ("M0817", "Supply Chain Management"),
    ("M0919", "Threat Intelligence Program"), ("M0951", "Update Software"),
    ("M0918", "User Account Management"), ("M0917", "User Training"),
    ("M0818", "Validate Program Inputs"), ("M0916", "Vulnerability Scanning"),
    ("M0815", "Watchdog Timers"),
]

# =============================================================================
#  SECTION 3 — EMBEDDED FRAMEWORK DATA (IEC 62443, ISA-TR84.00.09, Attify)
# =============================================================================
# 62443 requirements: (id, FR, name, summary). SR = 3-3 system requirement;
# CR = 4-2 component requirement; EDR/HDR/NDR/SAR = 4-2 component-type reqs.

IEC62443 = {
    "foundational_requirements": {
        "FR1": "Identification and Authentication Control (IAC)",
        "FR2": "Use Control (UC)", "FR3": "System Integrity (SI)",
        "FR4": "Data Confidentiality (DC)", "FR5": "Restricted Data Flow (RDF)",
        "FR6": "Timely Response to Events (TRE)", "FR7": "Resource Availability (RA)",
    },
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
    "part_4_2": [  # IEC 62443-4-2 component requirements (CR mirror + component-type)
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
        ("CR 2.13", "FR2", "Use of physical diagnostic and test interfaces", "Protect physical diagnostic/test interfaces."),
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
        # Embedded Device Requirements (EDR)
        ("EDR 2.13", "FR2", "Use of physical diagnostic and test interfaces (Embedded Device)", "Protect physical debug/test interfaces (JTAG/UART)."),
        ("EDR 3.2", "FR3", "Protection from malicious code (Embedded Device)", "Memory-corruption and code-injection protections."),
        ("EDR 3.10", "FR3", "Support for updates (Embedded Device)", "Authenticated, verified firmware update."),
        ("EDR 3.11", "FR3", "Physical tamper resistance and detection (Embedded Device)", "Resist/detect physical tampering."),
        ("EDR 3.12", "FR3", "Provisioning product supplier roots of trust (Embedded Device)", "Hardware root of trust / key provisioning by supplier."),
        ("EDR 3.13", "FR3", "Provisioning asset owner roots of trust (Embedded Device)", "Owner-provisioned roots of trust."),
        ("EDR 3.14", "FR3", "Integrity of the boot process (Embedded Device)", "Verify integrity/authenticity of the boot process."),
        # Host Device Requirements (HDR)
        ("HDR 2.4", "FR2", "Mobile code (Host Device)", "Control mobile code on host devices."),
        ("HDR 3.2", "FR3", "Protection from malicious code (Host Device)", "Anti-malware/allowlisting support."),
        ("HDR 3.10", "FR3", "Support for updates (Host Device)", "Authenticated, verified updates."),
        ("HDR 3.11", "FR3", "Physical tamper resistance and detection (Host Device)", "Tamper resistance/detection."),
        ("HDR 3.12", "FR3", "Provisioning product supplier roots of trust (Host Device)", "Supplier roots of trust."),
        ("HDR 3.13", "FR3", "Provisioning asset owner roots of trust (Host Device)", "Owner roots of trust."),
        ("HDR 3.14", "FR3", "Integrity of the boot process (Host Device)", "Secure/verified boot."),
        # Network Device Requirements (NDR)
        ("NDR 1.6", "FR1", "Wireless access management (Network Device)", "Manage wireless access."),
        ("NDR 1.13", "FR1", "Access via untrusted networks (Network Device)", "Control access from untrusted networks."),
        ("NDR 2.4", "FR2", "Mobile code (Network Device)", "Control mobile code."),
        ("NDR 3.2", "FR3", "Protection from malicious code (Network Device)", "Malicious code protections."),
        ("NDR 3.10", "FR3", "Support for updates (Network Device)", "Authenticated, verified updates."),
        ("NDR 3.11", "FR3", "Physical tamper resistance and detection (Network Device)", "Tamper resistance/detection."),
        ("NDR 3.12", "FR3", "Provisioning product supplier roots of trust (Network Device)", "Supplier roots of trust."),
        ("NDR 3.13", "FR3", "Provisioning asset owner roots of trust (Network Device)", "Owner roots of trust."),
        ("NDR 3.14", "FR3", "Integrity of the boot process (Network Device)", "Secure/verified boot."),
        ("NDR 5.2", "FR5", "Zone boundary protection (Network Device)", "Enforce boundary protection / deny by default."),
        ("NDR 5.3", "FR5", "General purpose person-to-person communication restrictions (Network Device)", "Restrict general-purpose comms."),
        # Software Application Requirements (SAR)
        ("SAR 2.4", "FR2", "Mobile code (Software Application)", "Control mobile code in the application."),
        ("SAR 3.2", "FR3", "Protection from malicious code (Software Application)", "Protections against malicious code/memory corruption."),
    ],
    "part_4_1": [  # IEC 62443-4-1 secure development lifecycle practices
        ("SM", "Practice 1 – Security Management", "Define/manage the secure development process, roles, controls; incl. SM-9 SBOM/third-party component management and SM-13 control of private keys."),
        ("SR", "Practice 2 – Specification of Security Requirements", "Define product security requirements from intended use/threat environment; SR-2 product threat model."),
        ("SD", "Practice 3 – Secure by Design", "Defense in depth, least privilege, attack surface reduction; SD-4 secure design best practices."),
        ("SI", "Practice 4 – Secure Implementation", "Secure coding standards; SI-1 implementation review; SI-2 secure coding."),
        ("SVV", "Practice 5 – Security Verification and Validation Testing", "Requirements, vulnerability, penetration, and fuzz testing (SVV-1..SVV-5)."),
        ("DM", "Practice 6 – Management of Security-related Issues", "Receive, triage, remediate reported vulnerabilities (DM-1..DM-6)."),
        ("SUM", "Practice 7 – Security Update Management", "Qualify, document, and deliver security updates (SUM-1..SUM-5)."),
        ("SG", "Practice 8 – Security Guidelines", "Secure deployment/operation/decommissioning guidance (SG-1..SG-7)."),
    ],
    "part_2_1": [  # IEC 62443-2-1 asset-owner security program (CSMS)
        ("2-1 Risk", "Risk analysis and assessment", "Business rationale; identify, assess, and rank IACS risk."),
        ("2-1 Policy", "Security policy, organization and awareness", "Policies, roles/responsibilities, training and awareness."),
        ("2-1 Countermeasures", "Selected security countermeasures", "Personnel, physical, network segmentation, access control, hardening."),
        ("2-1 Implementation", "Implementation", "Risk management, system development/maintenance, information/document management."),
        ("2-1 Monitoring", "Monitoring and improving the CSMS", "Conformance, review, incident handling, continual improvement."),
    ],
}

ISA84 = {
    "concepts": [
        ("TR84-SIS", "Safety Instrumented System (SIS)", "Sensors, logic solver (safety PLC), and final elements that bring the process to a safe state; a prime target whose compromise can defeat safety."),
        ("TR84-SIF", "Safety Instrumented Function (SIF)", "A specific protective function (sensor->logic->final element) with a defined Safety Integrity Level (SIL)."),
        ("TR84-SIL", "Safety Integrity Level (SIL 1-4)", "Required risk reduction / probability of failure on demand; cyber events can invalidate SIL claims."),
        ("TR84-INDEP", "Independence of BPCS and SIS", "Keep Basic Process Control System and SIS independent; cyber pathways linking them defeat that independence."),
        ("TR84-SECZONE", "SIS security zone", "Place the SIS in its own 62443 security zone with strictly controlled conduits; default-deny."),
        ("TR84-CRA", "Cyber Risk Assessment integrated with PHA/HAZOP/LOPA", "Assess cyber-initiated deviations alongside process hazards to find cyber-caused hazardous scenarios."),
        ("TR84-CONSEQ", "Consequence / severity analysis", "Characterize worst-case consequences (safety, environmental, financial) of cyber manipulation."),
        ("TR84-DEMAND", "Cyber as a demand source / defeat of protection layers", "Attacks can create a demand on the SIF and simultaneously defeat independent protection layers (IPLs)."),
        ("TR84-COUNTER", "Countermeasures and compensating measures", "Security controls + safety compensating measures to preserve safety-function integrity."),
        ("TR84-MOC", "Management of Change (MoC) for security", "Apply MoC to security-relevant changes to SIS/BPCS across the safety lifecycle."),
        ("TR84-VERIFY", "Verification & validation of security in the safety lifecycle", "Verify security controls do not impair the safety function and that assumptions hold."),
    ],
    "impact_scale": [
        ("Negligible", "No injury", "No release", "Negligible disruption"),
        ("Minor", "Minor injury, first aid", "Minor contained release", "Short disruption"),
        ("Serious", "Serious injury / lost time", "Reportable release", "Significant downtime"),
        ("Major", "Single fatality or severe injuries", "Major release requiring response", "Extended outage, major loss"),
        ("Catastrophic", "Multiple fatalities", "Severe/offsite environmental damage", "Loss of facility / community impact"),
    ],
    "hazard_workflow": [
        "1. Identify the SIS/SIF and the hazardous scenario it protects against (from PHA/HAZOP/LOPA).",
        "2. Identify cyber attack paths (map to EMB3D TID + ATT&CK-ICS T0xxx) that could manipulate, disable, or spoof the SIF.",
        "3. Determine whether the attack creates a demand and/or defeats independent protection layers (IPLs).",
        "4. Assess consequence/severity using the impact scale and likelihood considering cyber exposure.",
        "5. Select 62443 security countermeasures + safety compensating measures; verify no adverse effect on the safety function.",
        "6. Document residual risk and manage via MoC across the safety lifecycle.",
    ],
}

# Attify IoT reverse-engineering / attack-surface mindmap: (domain, node, [techniques], [emb3d])
ATTIFY_MINDMAP = [
    ("Hardware / Device Teardown", "Component identification & datasheet recon", ["PCB inspection", "chip markings -> datasheets", "block-diagram reconstruction", "identify SoC/MCU/flash/crypto"], ["PID-11", "PID-123"]),
    ("Hardware / Device Teardown", "Debug/test interface discovery (UART/JTAG/SWD)", ["logic analyzer", "JTAGulator/pin mapping", "baud-rate detection", "open a root shell"], ["TID-115", "TID-119"]),
    ("Hardware / Device Teardown", "Bus sniffing (SPI/I2C/CAN)", ["logic analyzer capture", "Bus Pirate", "decode flash/EEPROM traffic"], ["TID-106", "TID-114"]),
    ("Hardware / Device Teardown", "Chip-off / flash extraction", ["SPI/NAND dump", "chip-off desolder", "flashrom / CH341A read"], ["TID-108", "TID-111"]),
    ("Hardware / Device Teardown", "Fault injection & side-channel", ["voltage/clock glitching", "EM/power analysis (ChipWhisperer)", "bypass secure boot"], ["TID-101", "TID-102", "TID-105", "TID-110"]),
    ("Hardware / Device Teardown", "Physical tamper / port abuse", ["tamper-switch bypass", "electrical/ESD abuse", "latent port access"], ["TID-116", "TID-118"]),
    ("Firmware Analysis", "Firmware acquisition", ["OTA/download capture", "flash dump", "vendor update files"], ["TID-215", "TID-111"]),
    ("Firmware Analysis", "Unpacking & filesystem extraction", ["binwalk", "firmware-mod-kit", "extract squashfs/jffs2/ubifs"], ["TID-301"]),
    ("Firmware Analysis", "Secret & credential hunting", ["entropy/grep scan", "hardcoded keys/passwords", "certificates/private keys"], ["TID-226", "TID-328", "TID-329"]),
    ("Firmware Analysis", "Binary reverse engineering", ["Ghidra/IDA/radare2", "identify vulnerable functions", "backdoor/logic analysis"], ["TID-327", "TID-301", "TID-305"]),
    ("Firmware Analysis", "Update/boot chain analysis", ["verify signing/secure boot", "rollback checks", "key location"], ["TID-201", "TID-213", "TID-216"]),
    ("Firmware Analysis", "Third-party component / SBOM", ["identify OSS libs & versions", "map to CVEs"], ["TID-303"]),
    ("Firmware Analysis", "Emulation & dynamic analysis", ["QEMU/firmadyne", "run services", "fuzz interfaces"], ["TID-304", "TID-310"]),
    ("Radio / Wireless Communication", "WiFi", ["capture/crack keys", "rogue AP", "deauth"], ["TID-408", "TID-411"]),
    ("Radio / Wireless Communication", "Bluetooth / BLE", ["GATT enumeration", "sniff pairing", "replay/spoof"], ["TID-407", "TID-410"]),
    ("Radio / Wireless Communication", "Zigbee / Z-Wave / Thread", ["key capture", "join/pairing abuse", "replay"], ["TID-407", "TID-411"]),
    ("Radio / Wireless Communication", "LoRa / LoRaWAN", ["join-request capture", "key extraction", "replay"], ["TID-407", "TID-411"]),
    ("Radio / Wireless Communication", "Sub-GHz / proprietary RF", ["SDR (HackRF/RTL-SDR)", "GNU Radio demod", "replay/jam"], ["TID-411"]),
    ("Radio / Wireless Communication", "RFID / NFC", ["Proxmark", "clone/emulate tags"], ["TID-406"]),
    ("Radio / Wireless Communication", "Cellular / GNSS", ["modem AT abuse", "spoofing", "rogue base station awareness"], ["TID-412"]),
    ("Network Services", "Service & port enumeration", ["nmap", "banner grab", "identify ICS protocols"], ["TID-401"]),
    ("Network Services", "ICS/OT protocol testing", ["Modbus/DNP3/S7/EtherNet-IP/OPC UA probing", "unauthorized command", "fuzzing"], ["TID-406", "TID-405"]),
    ("Network Services", "Cleartext & MitM", ["traffic capture", "ARP/redirect", "downgrade"], ["TID-408", "TID-407"]),
    ("Network Services", "Remote access services", ["SSH/Telnet/RDP/VNC review", "default creds", "exposure check"], ["TID-310", "TID-311"]),
    ("Network Services", "Cloud / broker connectivity", ["MQTT/HTTP API review", "mutual-auth check", "topic/authz abuse"], ["TID-316", "TID-412"]),
    ("Web / Mobile / Cloud Applications", "Embedded / management web UI", ["auth bypass", "injection (XSS/SQLi/cmd)", "CSRF", "session flaws"], ["TID-319", "TID-320", "TID-322"]),
    ("Web / Mobile / Cloud Applications", "Companion mobile app", ["APK/IPA reverse engineering", "hardcoded secrets", "insecure storage"], ["TID-328", "TID-329"]),
    ("Web / Mobile / Cloud Applications", "Cloud API / backend", ["authz testing (IDOR)", "device impersonation", "provisioning flaws"], ["TID-324", "TID-412"]),
    ("Web / Mobile / Cloud Applications", "Authentication & session", ["MFA review", "token analysis", "brute-force resistance"], ["TID-314", "TID-321"]),
]

# =============================================================================
#  SECTION 4 — indexes, providers, prompts
# =============================================================================

def _idx_props():
    return [{"code": c, "category": cat, "name": n} for (c, cat, n) in EMB3D_PROPERTIES]

def _idx_threats():
    return [{"id": i, "category": c, "name": n, "desc": d} for (i, c, n, d) in EMB3D_THREATS]

def _idx_mits():
    return [{"id": i, "name": n} for (i, n) in EMB3D_MITIGATIONS]

def _idx_tactics():
    return [{"id": i, "name": n, "desc": d} for (i, n, d) in ATTACK_ICS_TACTICS]

def _idx_techniques():
    return [{"id": i, "name": n, "tactic": t, "desc": d} for (i, n, t, d) in ATTACK_ICS_TECHNIQUES]

def _idx_attack_mits():
    return [{"id": i, "name": n} for (i, n) in ATTACK_ICS_MITIGATIONS]

def framework_stats():
    return {
        "emb3d_properties": len(EMB3D_PROPERTIES),
        "emb3d_threats": len(EMB3D_THREATS),
        "emb3d_mitigations": len(EMB3D_MITIGATIONS),
        "attack_ics_tactics": len(ATTACK_ICS_TACTICS),
        "attack_ics_techniques": len(ATTACK_ICS_TECHNIQUES),
        "attack_ics_mitigations": len(ATTACK_ICS_MITIGATIONS),
        "iec62443_3_3": len(IEC62443["part_3_3"]),
        "iec62443_4_2": len(IEC62443["part_4_2"]),
        "iec62443_4_1": len(IEC62443["part_4_1"]),
        "iec62443_2_1": len(IEC62443["part_2_1"]),
        "isa84_concepts": len(ISA84["concepts"]),
        "attify_nodes": len(ATTIFY_MINDMAP),
    }

# --- Providers (wire-protocol families: anthropic | openai | google) ---
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

def provider_catalog():
    out = []
    for pid, p in PROVIDERS.items():
        out.append({
            "id": pid, "label": p["label"], "kind": p["kind"], "base_url": p["base_url"],
            "vision": p["vision"], "notes": p["notes"],
            "server_key": bool(os.environ.get(p["env"], "")),
            "models": [{"id": m[0], "label": m[1]} for m in p["models"]],
        })
    return out

SYSTEM_PROMPT = """You are a Systems Security Engineer with 20+ years of experience creating technical security threat models of ICS/OT/IoT devices, components, applications, and systems (PLC, RTU, IED, DCS, SIS/safety PLC, HMI, smart meter, sensor/actuator, gateway, vehicle ECU, medical device) including sub-components (SoC, FPGA, MCU, radios, memories).

You produce rigorous, standards-aligned threat models suitable for design reviews, procurement (62443-4-2), asset-owner risk assessments (62443-3-3 / 2-1), secure development (62443-4-1), and safety-lifecycle integration (ISA-TR84.00.09 with IEC 61511/62443).

Reason across four perspectives: (1) SYSTEM modeling — decompose into components, interfaces, data flows, trust boundaries, and 62443 zones/conduits; (2) DEVICE modeling — EMB3D property types (Hardware, System Software, Application Software, Networking) with concrete features/interfaces; (3) THREAT modeling — map EMB3D threats (TID) to properties with EMB3D mitigations (MID); (4) ATTACK modeling — map MITRE ATT&CK for ICS tactics/techniques (T0xxx) and the Attify IoT reverse-engineering attack surface, then tie consequences to safety via ISA-TR84.00.09.

METHOD:
- Use the provided REFERENCE CONTEXT (full EMB3D / ATT&CK-ICS / 62443 / ISA-84 / Attify data) as the authoritative source of IDs and names. Prefer those exact IDs and titles.
- HYBRID mode: if a relevant item is not present, add well-known correct entries from your own expertise and mark them with a trailing "*" on the ID.
- Ground everything in the target and any ingested artifacts (datasheets, manuals, P&ID/PFD, functional design specs, SysML/UML). Extract real properties, interfaces, and protocols; never fabricate a datasheet fact — state assumptions explicitly.
- Be specific to the actual device; avoid generic filler.
"""

REPORT_SCHEMA = """Return your answer as a SINGLE JSON object (no prose, no markdown fences) matching this schema:
{
 "target": "string",
 "executive_summary": "string (4-8 sentences, risk-focused)",
 "system_model": {"description":"str","components":[{"name":"str","role":"str","sub_components":["str"]}],
   "interfaces":[{"name":"str","type":"network|wireless|physical|bus|debug|api","protocol":"str","exposure":"external|zone|internal|physical"}],
   "data_flows":[{"from":"str","to":"str","data":"str","protocol":"str","trust_boundary_crossed":true}],
   "zones_conduits":[{"zone":"str","assets":["str"],"conduit_to":"str","controls":"str"}]},
 "device_model_emb3d":{"properties":[{"property_code":"PID-...","category":"Hardware|System Software|Application Software|Networking","feature_or_interface":"str","present":true,"notes":"str"}]},
 "threat_table_emb3d":[{"emb3d_element":"str","threat_id":"TID-...","threat_name":"str","description":"str","likelihood":"Low|Medium|High","impact":"Low|Medium|High","mitigation_ids":["MID-..."],"mitigation_summary":"str"}],
 "attack_ics_table":[{"tactic":"str","technique_id":"T0...","technique_name":"str","applicability":"str","related_threat_ids":["TID-..."]}],
 "attify_surface":[{"domain":"str","vector":"str","technique":"str","finding_or_hypothesis":"str","related_threat_ids":["TID-..."]}],
 "iec62443":{"part_4_2_component":[{"req_id":"CR x.y / EDR x.y","name":"str","design_mitigation":"str","addresses_threats":["TID-..."]}],
   "part_3_3_system":[{"req_id":"SR x.y","name":"str","system_control":"str"}],
   "part_4_1_lifecycle":[{"practice":"SD/SVV/...","name":"str","recommendation":"str"}],
   "part_2_1_program":[{"element":"str","recommendation":"str"}]},
 "isa84_safety":{"applicable":true,"sis_sif":"str","hazard_scenarios":[{"scenario":"str","attack_path":"str (TID/T0 chain)","consequence":"str","severity":"Negligible|Minor|Serious|Major|Catastrophic","defeats_protection_layers":true,"countermeasures":"str"}]},
 "risk_register":[{"id":"R1","risk":"str","threat_ids":["TID-..."],"attack_ids":["T0..."],"likelihood":"Low|Medium|High","impact":"Low|Medium|High","risk_level":"Low|Medium|High|Critical","recommendation":"str","mapped_requirements":["CR x.y","SR x.y"]}],
 "assumptions":["str"],
 "threat_diagram":{
    "zones":[{"name":"str (e.g. Control Zone)","nodes":[{"id":"short_unique_id","label":"str"}]}],
    "external_nodes":[{"id":"short_unique_id","label":"str (e.g. Engineering WS, Cloud, HMI)"}],
    "flows":[{"from":"node_id","to":"node_id","label":"str (protocol/data)"}],
    "attacker_entrypoints":[{"to":"node_id","label":"str","threat_id":"TID-... or T0..."}]
 },
 "kill_chain":[{"tactic":"ATT&CK-for-ICS tactic name, in kill-chain order","techniques":[{"id":"T0...","name":"str"}],"note":"how this stage applies to the target"}],
 "attack_mindmap":{"root":"the target name","branches":[{"domain":"Hardware/Firmware/Radio/Network/Application","items":[{"label":"attack vector/technique","ids":["TID-... or T0..."]}]}]},
 "references":["str — include the artifact filenames you used"]
}
Rules:
- Output ONLY valid JSON (double quotes, no trailing commas, no comments).
- MANDATORY — every one of these fields MUST be present and substantively populated (never omit or leave empty): executive_summary, system_model (with components, interfaces, data_flows), device_model_emb3d.properties, threat_table_emb3d, attack_ics_table, attify_surface, iec62443.part_3_3_system, iec62443.part_4_2_component, iec62443.part_4_1_lifecycle, isa84_safety, risk_register, threat_diagram, kill_chain, attack_mindmap. A report missing any of these is invalid.
- YOU perform the whole analysis automatically: examine the target against EVERY framework and select all relevant items yourself. The user does not choose properties, threats, techniques, or requirements — you do.
- MINE THE UPLOADED ARTIFACTS. Read the ingested datasheets, manuals, functional design specs, P&IDs/PFDs, and SysML/UML (text and images) and extract the device's REAL features, components, interfaces, protocols, ports, memory/debug features, firmware/update mechanisms, credentials, and KNOWN VULNERABILITIES. Base every section on those actual facts and cite artifact filenames in references. If a fact is unknown, state it as an assumption rather than inventing it.
- Populate arrays with substantive, target-specific entries: aim for 10+ EMB3D threats, 8+ ATT&CK-for-ICS techniques, 8+ 62443-4-2 requirements, the relevant 62443-3-3 system requirements and 62443-4-1 practices, 6+ Attify attack-surface vectors, and a risk register covering the top risks.
- HONOR THE USER'S SCOPE/NOTES exactly. Produce precisely the frameworks and analysis they request. Do NOT pad the report with content they did not ask for. In particular, do NOT add 62443-3-2 zones/conduits, firewall rule mappings, or 62443-2-1 program content unless the user explicitly requests them (leave system_model.zones_conduits and iec62443.part_2_1 empty if not requested). Keep the executive summary focused on features/components/interfaces/vulnerabilities and their framework mappings — not on firewall/network architecture unless asked.
- ALWAYS build all three visuals (threat_diagram, kill_chain, attack_mindmap) from the analysis — these are required deliverables. In threat_diagram, every flow 'from'/'to' MUST reference an id you defined in zones[].nodes[] or external_nodes[]. Order kill_chain stages in MITRE ATT&CK for ICS tactic order (Initial Access -> ... -> Impact) with the relevant ATT&CK-for-ICS techniques per stage; this feeds the "ATT&CK for ICS Kill Chain" diagram (the SANS ICS Cyber Kill Chain diagram is derived automatically). attack_mindmap.branches should cover the relevant Attify domains (Hardware, Firmware, Radio, Network, Application) with specific vectors and framework IDs.
- If ISA-84 does not apply (non-safety component), set isa84_safety.applicable=false and explain in sis_sif; otherwise populate hazard_scenarios.
"""

CHAT_SYSTEM_PROMPT = """You are an ICS/OT/IoT security threat-modeling assistant (EMB3D, MITRE ATT&CK for ICS, IEC 62443, ISA-TR84.00.09, Attify IoT). Answer questions about the device/system under analysis, refine the model, explain mappings, and suggest tests. Be concrete and cite framework IDs (TID/MID/T0/M0/CR/SR) where relevant."""


def build_reference_context():
    L = []
    L.append("### EMB3D DEVICE PROPERTIES (PID | category | title)")
    for c, cat, n in EMB3D_PROPERTIES:
        L.append(f"{c} [{cat}] {n}")
    L.append("\n### EMB3D THREATS (TID | category | title — desc)")
    for i, c, n, d in EMB3D_THREATS:
        L.append(f"{i} [{c}] {n} — {d}")
    L.append("\n### EMB3D MITIGATIONS (MID | title)")
    for i, n in EMB3D_MITIGATIONS:
        L.append(f"{i} {n}")
    L.append("\n### MITRE ATT&CK FOR ICS TACTICS")
    L.append(", ".join(n for _, n, _ in ATTACK_ICS_TACTICS))
    L.append("### MITRE ATT&CK FOR ICS TECHNIQUES (T0 | title [tactics] — desc)")
    for i, n, t, d in ATTACK_ICS_TECHNIQUES:
        L.append(f"{i} {n} [{', '.join(t)}] — {d}")
    L.append("### MITRE ATT&CK FOR ICS MITIGATIONS (M0 | title)")
    L.append(", ".join(f"{i} {n}" for i, n in ATTACK_ICS_MITIGATIONS))
    L.append("\n### IEC 62443-3-3 SYSTEM REQUIREMENTS (SR | FR | name — summary)")
    for i, fr, n, s in IEC62443["part_3_3"]:
        L.append(f"{i} ({fr}) {n} — {s}")
    L.append("\n### IEC 62443-4-2 COMPONENT REQUIREMENTS (CR/EDR/HDR/NDR/SAR | FR | name — summary)")
    for i, fr, n, s in IEC62443["part_4_2"]:
        L.append(f"{i} ({fr}) {n} — {s}")
    L.append("\n### IEC 62443-4-1 SECURE DEVELOPMENT LIFECYCLE PRACTICES")
    for i, n, s in IEC62443["part_4_1"]:
        L.append(f"{i}: {n} — {s}")
    L.append("\n### IEC 62443-2-1 ASSET-OWNER PROGRAM ELEMENTS")
    for i, n, s in IEC62443["part_2_1"]:
        L.append(f"{i}: {n} — {s}")
    L.append("\n### ISA-TR84.00.09 SAFETY/SECURITY CONCEPTS")
    for i, t, d in ISA84["concepts"]:
        L.append(f"{i}: {t} — {d}")
    L.append("Impact severity scale: " + " | ".join(f"{lv} (safety: {s})" for lv, s, e, o in ISA84["impact_scale"]))
    L.append("\n### ATTIFY IoT REVERSE-ENGINEERING / ATTACK-SURFACE MINDMAP")
    cur = None
    for dom, node, techs, emb in ATTIFY_MINDMAP:
        if dom != cur:
            cur = dom
            L.append(f"[{dom}]")
        L.append(f"  {node} :: {', '.join(techs)} -> {', '.join(emb)}")
    return "\n".join(L)


REFINE_SYSTEM_PROMPT = SYSTEM_PROMPT + """

You are now REVISING an existing threat model. Apply the user's requested change and return the COMPLETE updated report (same schema, every mandatory section and all three diagrams). Preserve existing correct content that the change does not touch; only add, remove, or edit what the user asked for. Honor the request literally — if they ask to remove something (e.g., firewall/zones content) remove it; if they ask to add or expand a section, do so."""


def build_refine_prompt(current_report, instruction):
    import json as _j
    parts = ["# CURRENT THREAT MODEL (JSON)\n" + _j.dumps(current_report)[:60000]]
    parts.append("\n# REQUESTED CHANGE\n" + instruction)
    parts.append("\n# REFERENCE CONTEXT (full framework data — prefer these IDs/titles)\n" + build_reference_context())
    parts.append("\n# TASK\nReturn the COMPLETE updated threat model reflecting the requested change.\n" + REPORT_SCHEMA)
    return "\n".join(parts)


def build_user_prompt(target, scope, artifact_ctx, online_notes=""):
    parts = [f"# IN-SCOPE TARGET\n{target}"]
    if scope:
        parts.append(f"\n# SCOPE / NOTES\n{scope}")
    if artifact_ctx:
        parts.append(f"\n# INGESTED ARTIFACTS (extracted)\n{artifact_ctx}")
    if online_notes:
        parts.append(f"\n# ADDITIONAL CONTEXT\n{online_notes}")
    parts.append("\n# REFERENCE CONTEXT (full framework data — prefer these IDs/titles)\n" + build_reference_context())
    parts.append("\n# TASK\nProduce the complete threat model for the in-scope target.\n" + REPORT_SCHEMA)
    return "\n".join(parts)


# =============================================================================
#  SECTION 5 — model router (stdlib urllib; non-stream + streaming)
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
    if kind != "openai" or provider != "local":
        if not key and provider != "local":
            raise ProviderError(f"No API key for '{provider}'. Enter one in the UI (Keys) or set {p['env']}.")
    return kind, base, key


TOOL_NAME = "emit_threat_model"

# Explicit output schema — forces the model to include every mapping table and
# all three diagrams (the permissive {"type":"object"} let models omit them).
_ARR = {"type": "array", "items": {"type": "object"}}
_STRARR = {"type": "array", "items": {"type": "string"}}
SCHEMA_REPORT = {
    "type": "object",
    "properties": {
        "target": {"type": "string"},
        "executive_summary": {"type": "string"},
        "system_model": {"type": "object", "properties": {
            "description": {"type": "string"}, "components": _ARR, "interfaces": _ARR,
            "data_flows": _ARR, "zones_conduits": _ARR},
            "required": ["description", "components", "interfaces", "data_flows"]},
        "device_model_emb3d": {"type": "object", "properties": {"properties": _ARR}, "required": ["properties"]},
        "threat_table_emb3d": _ARR,
        "attack_ics_table": _ARR,
        "attify_surface": _ARR,
        "iec62443": {"type": "object", "properties": {
            "part_4_2_component": _ARR, "part_3_3_system": _ARR,
            "part_4_1_lifecycle": _ARR, "part_2_1_program": _ARR},
            "required": ["part_3_3_system", "part_4_2_component", "part_4_1_lifecycle"]},
        "isa84_safety": {"type": "object", "properties": {
            "applicable": {"type": "boolean"}, "sis_sif": {"type": "string"}, "hazard_scenarios": _ARR}},
        "risk_register": _ARR,
        "assumptions": _STRARR,
        "threat_diagram": {"type": "object", "properties": {
            "zones": _ARR, "external_nodes": _ARR, "flows": _ARR, "attacker_entrypoints": _ARR},
            "required": ["zones", "flows"]},
        "kill_chain": {"type": "array", "items": {"type": "object", "properties": {
            "tactic": {"type": "string"}, "techniques": _ARR, "note": {"type": "string"}},
            "required": ["tactic", "techniques"]}},
        "attack_mindmap": {"type": "object", "properties": {
            "root": {"type": "string"}, "branches": _ARR}, "required": ["root", "branches"]},
        "references": _STRARR,
    },
    "required": ["target", "executive_summary", "system_model", "device_model_emb3d",
                 "threat_table_emb3d", "attack_ics_table", "attify_surface", "iec62443",
                 "isa84_safety", "risk_register", "threat_diagram", "kill_chain", "attack_mindmap"],
}
# Which top-level fields must be non-empty for a report to count as complete.
MANDATORY_FIELDS = ["executive_summary", "system_model", "device_model_emb3d", "threat_table_emb3d",
                    "attack_ics_table", "attify_surface", "iec62443", "risk_register",
                    "threat_diagram", "kill_chain", "attack_mindmap"]


def _build_request(kind, base, key, model, system, user, images, stream, max_tokens, temperature,
                   provider="", structured=False):
    images = images or []
    if kind == "anthropic":
        content = [{"type": "text", "text": user}]
        for im in images:
            content.append({"type": "image", "source": {"type": "base64",
                            "media_type": im.get("media_type", "image/png"), "data": im["b64"]}})
        body = {"model": model, "max_tokens": max_tokens,
                "system": system, "messages": [{"role": "user", "content": content}], "stream": stream}
        if structured:
            # Force valid, schema-shaped JSON via tool use — no hand-written JSON to break.
            body["tools"] = [{"name": TOOL_NAME,
                              "description": "Return the COMPLETE threat model. Every field marked required must be populated: all mapping tables (EMB3D, ATT&CK-ICS, 62443, Attify), the risk register, and all three diagrams.",
                              "input_schema": SCHEMA_REPORT}]
            body["tool_choice"] = {"type": "tool", "name": TOOL_NAME}
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
        # OpenAI's newer models (GPT-5.x, o-series) reject `max_tokens` and
        # require `max_completion_tokens`. DeepSeek / Kimi / local OpenAI-compatible
        # servers still expect the classic `max_tokens`.
        tok_key = "max_completion_tokens" if provider == "openai" else "max_tokens"
        body = {"model": model, "messages": [{"role": "system", "content": system},
                {"role": "user", "content": user_content}],
                tok_key: max_tokens, "stream": stream}
        # JSON mode guarantees syntactically valid JSON. Supported by OpenAI,
        # DeepSeek, and Moonshot; skipped for unknown local servers.
        if structured and provider in ("openai", "deepseek", "moonshot"):
            body["response_format"] = {"type": "json_object"}
        url = f"{base}/chat/completions"
        headers = {"content-type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
    # temperature is OFF by default: many current models (Claude Opus 4.x,
    # OpenAI o-series/GPT-5) reject a custom temperature. Only include it if a
    # caller explicitly opts in.
    if temperature is not None:
        if kind == "google":
            body["generationConfig"]["temperature"] = temperature
        else:
            body["temperature"] = temperature
    return url, headers, body


def call_model(provider, model, system, user, images=None, api_key=None, base_url=None,
               max_tokens=8000, temperature=None):
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, False, max_tokens, temperature, provider)
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


def call_model_json(provider, model, system, user, images=None, api_key=None, base_url=None, max_tokens=16000):
    """Return a parsed report dict using each provider's guaranteed structured-output
    mode (Claude tool-use; OpenAI/DeepSeek/Kimi JSON mode; Gemini JSON mime type),
    with a tolerant parser as a final safety net. Never returns invalid JSON."""
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, False,
                                        max_tokens, None, provider, structured=True)
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
                return blk["input"]           # already-valid JSON object from the API
        txt = "".join(b.get("text", "") for b in raw.get("content", []) if b.get("type") == "text")
        return parse_model_json(txt)
    return parse_model_json(_extract_text(kind, raw))


def missing_sections(rep):
    """Return the list of mandatory report fields that are empty/absent.
    Tolerant of malformed model output: a field the model returned as the wrong
    type (e.g. a string where a dict/object was expected) counts as missing rather
    than crashing the whole generation."""
    if not isinstance(rep, dict):
        return list(MANDATORY_FIELDS)
    miss = []
    _dict_fields = {
        "system_model": "components",
        "device_model_emb3d": "properties",
        "threat_diagram": "zones",
        "attack_mindmap": "branches",
    }
    for k in MANDATORY_FIELDS:
        v = rep.get(k)
        if not v:
            miss.append(k); continue
        if k in _dict_fields:
            if not (isinstance(v, dict) and v.get(_dict_fields[k])):
                miss.append(k)
        elif k == "iec62443":
            if not (isinstance(v, dict) and (v.get("part_3_3_system") or v.get("part_4_2_component"))):
                miss.append(k)
    return miss


def _is_image_error(exc):
    """True if a provider error is about an image it couldn't accept, so we can
    safely retry the same request with the images removed."""
    m = str(exc).lower()
    return ("image" in m) and ("could not process" in m or "400" in m or "invalid" in m
                               or "unsupported" in m or "media type" in m or "decode" in m)


def generate_report(provider, model, system, user, images=None, api_key=None, base_url=None, max_tokens=20000):
    """Generate a complete report; if the first pass drops required sections,
    do one focused retry so the user never receives a half-empty report.
    If the provider rejects an image, transparently retry without images so the
    user still gets a full text-based report instead of an error."""
    try:
        rep = call_model_json(provider, model, system, user, images, api_key, base_url, max_tokens)
    except ProviderError as e:
        if images and _is_image_error(e):
            rep = call_model_json(provider, model, system, user, None, api_key, base_url, max_tokens)
            images = None  # don't re-send the bad image on the completeness retry
        else:
            raise
    miss = missing_sections(rep)
    if miss:
        aug = user + ("\n\n# CRITICAL COMPLETENESS FIX\nYour previous output OMITTED these REQUIRED sections: "
                      + ", ".join(miss) + ". Regenerate the COMPLETE report now with EVERY mandatory section and "
                      "all three diagrams (threat_diagram, kill_chain, attack_mindmap) fully populated. Do not omit anything.")
        try:
            rep2 = call_model_json(provider, model, system, aug, images, api_key, base_url, max_tokens)
            if len(missing_sections(rep2)) < len(miss):
                rep = rep2
        except (ProviderError, ValueError):
            pass
    return rep


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


def stream_model(provider, model, system, user, images=None, api_key=None, base_url=None,
                 max_tokens=8000, temperature=None):
    """Generator yielding text deltas."""
    kind, base, key = _resolve(provider, api_key, base_url)
    url, headers, body = _build_request(kind, base, key, model, system, user, images, True, max_tokens, temperature, provider)
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
    """Cheaply verify a provider credential by listing models (no token cost).
    Returns {"ok": bool, "message": str, "models": [ids]}. Never raises."""
    p = PROVIDERS.get(provider)
    if not p:
        return {"ok": False, "message": f"Unknown provider '{provider}'."}
    kind = p["kind"]
    base = (base_url or p["base_url"]).rstrip("/")
    key = (api_key or os.environ.get(p["env"], "") or "").strip()
    if not key and provider != "local":
        return {"ok": False, "message": "Enter an API key to continue."}
    if kind == "anthropic":
        url = f"{base}/models"
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    elif kind == "google":
        url = f"{base}/models?key={key}"
        headers = {}
    else:
        url = f"{base}/models"
        headers = {"Authorization": f"Bearer {key}"} if key else {}
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
            msg = ("Your API key was rejected. Make sure you pasted the FULL key "
                   "(Anthropic keys start with sk-ant-) with no extra spaces, and that it is active.")
        elif e.code == 404:
            msg = "Endpoint not found — check the Base URL for this provider."
        elif e.code == 429:
            msg = "Rate limited while checking the key — wait a moment and try again."
        else:
            msg = f"Provider returned {e.code}: {body}"
        return {"ok": False, "message": msg, "status": e.code}
    except urllib.error.URLError as e:
        return {"ok": False, "message": f"Could not reach the provider ({e.reason}). "
                                        f"Check your network or the Base URL."}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"Key check failed: {e}"}


# =============================================================================
#  SECTION 6 — report rendering (JSON -> Markdown), artifact context
# =============================================================================

def _json_repair(s):
    """Best-effort repair of common LLM JSON mistakes (safety net for models
    without a guaranteed JSON mode)."""
    import re
    t = s
    # remove trailing commas before } or ]
    t = re.sub(r",(\s*[}\]])", r"\1", t)
    # balance quotes/brackets if the response was truncated mid-structure
    # 1) if an odd number of unescaped quotes, close the last string
    quotes = len(re.findall(r'(?<!\\)"', t))
    if quotes % 2 == 1:
        t += '"'
    # 2) close any unclosed brackets/braces in the right order
    stack = []
    in_str = False
    esc = False
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
    # 1) straight parse
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # 2) narrow to the outermost object
    a, b = s.find("{"), s.rfind("}")
    frag = s[a:b + 1] if (a != -1 and b > a) else s
    try:
        return json.loads(frag)
    except json.JSONDecodeError:
        pass
    # 3) repair pass (trailing commas, truncation, unbalanced brackets)
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


def _mdtable(headers, rows):
    if not rows:
        return "_None identified._\n"
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("\n", " ").replace("|", "\\|") for c in r) + " |")
    return "\n".join(out) + "\n"


def report_to_markdown(rep, meta=None):
    meta = meta or {}
    L = []
    target = _g(rep, "target") or meta.get("target", "Target")
    L.append(f"# ICS/OT/IoT Threat Model — {target}\n")
    gen = meta.get("generated_at", "")
    prov = f"{meta.get('provider','')} / {meta.get('model','')}".strip(" /")
    L.append(f"*Generated {gen}" + (f" · Model: {prov}" if prov else "") + "*\n")
    L.append("> Frameworks: MITRE EMB3D · MITRE ATT&CK for ICS · ISA/IEC 62443 (3-3,4-2,4-1,2-1) · ISA-TR84.00.09 · Attify IoT. IDs suffixed `*` are model-supplied.\n")
    if _g(rep, "executive_summary"):
        L.append("## Executive Summary\n\n" + _g(rep, "executive_summary") + "\n")
    sm = _g(rep, "system_model", default={})
    if sm:
        L.append("## 1. System Model\n")
        if _g(sm, "description"):
            L.append(_g(sm, "description") + "\n")
        comps = _g(sm, "components", default=[])
        if comps:
            L.append("### Components\n")
            L.append(_mdtable(["Component", "Role", "Sub-components"],
                     [[_g(c, "name"), _g(c, "role"), ", ".join(_g(c, "sub_components", default=[]))] for c in comps]))
        ifs = _g(sm, "interfaces", default=[])
        if ifs:
            L.append("### Interfaces\n")
            L.append(_mdtable(["Interface", "Type", "Protocol", "Exposure"],
                     [[_g(i, "name"), _g(i, "type"), _g(i, "protocol"), _g(i, "exposure")] for i in ifs]))
        fl = _g(sm, "data_flows", default=[])
        if fl:
            L.append("### Data Flows\n")
            L.append(_mdtable(["From", "To", "Data", "Protocol", "Crosses boundary"],
                     [[_g(f, "from"), _g(f, "to"), _g(f, "data"), _g(f, "protocol"),
                       "Yes" if _g(f, "trust_boundary_crossed", default=False) else "No"] for f in fl]))
        zc = _g(sm, "zones_conduits", default=[])
        if zc:
            L.append("### Security Zones & Conduits (62443)\n")
            L.append(_mdtable(["Zone", "Assets", "Conduit to", "Controls"],
                     [[_g(z, "zone"), ", ".join(_g(z, "assets", default=[])), _g(z, "conduit_to"), _g(z, "controls")] for z in zc]))
    dm = _g(rep, "device_model_emb3d", default={})
    props = _g(dm, "properties", default=[]) if dm else []
    if props:
        L.append("## 2. Device Model — EMB3D Properties\n")
        L.append(_mdtable(["EMB3D Property", "Category", "Feature/Interface", "Present", "Notes"],
                 [[_g(p, "property_code"), _g(p, "category"), _g(p, "feature_or_interface"),
                   "Yes" if _g(p, "present", default=True) else "No", _g(p, "notes")] for p in props]))
    tt = _g(rep, "threat_table_emb3d", default=[])
    if tt:
        L.append("## 3. EMB3D Threat → Mitigation Table\n")
        L.append(_mdtable(["Element", "Threat ID", "Threat", "Likelihood", "Impact", "Mitigations", "Summary"],
                 [[_g(t, "emb3d_element"), _g(t, "threat_id"), _g(t, "threat_name"), _g(t, "likelihood"),
                   _g(t, "impact"), ", ".join(_g(t, "mitigation_ids", default=[])), _g(t, "mitigation_summary")] for t in tt]))
    at = _g(rep, "attack_ics_table", default=[])
    if at:
        L.append("## 4. MITRE ATT&CK for ICS — Tactics & Techniques\n")
        L.append(_mdtable(["Tactic", "Technique ID", "Technique", "Applicability", "Related EMB3D"],
                 [[_g(a, "tactic"), _g(a, "technique_id"), _g(a, "technique_name"), _g(a, "applicability"),
                   ", ".join(_g(a, "related_threat_ids", default=[]))] for a in at]))
    af = _g(rep, "attify_surface", default=[])
    if af:
        L.append("## 5. Attify IoT Reverse-Engineering / Attack Surface\n")
        L.append(_mdtable(["Domain", "Vector", "Technique", "Finding / Hypothesis", "Related EMB3D"],
                 [[_g(x, "domain"), _g(x, "vector"), _g(x, "technique"), _g(x, "finding_or_hypothesis"),
                   ", ".join(_g(x, "related_threat_ids", default=[]))] for x in af]))
    iec = _g(rep, "iec62443", default={})
    if iec:
        L.append("## 6. ISA/IEC 62443 Requirements Mapping\n")
        p42 = _g(iec, "part_4_2_component", default=[])
        if p42:
            L.append("### 6.1 62443-4-2 — Component Requirements\n")
            L.append(_mdtable(["Req ID", "Name", "Design Mitigation", "Addresses Threats"],
                     [[_g(r, "req_id"), _g(r, "name"), _g(r, "design_mitigation"), ", ".join(_g(r, "addresses_threats", default=[]))] for r in p42]))
        p33 = _g(iec, "part_3_3_system", default=[])
        if p33:
            L.append("### 6.2 62443-3-3 — System Requirements\n")
            L.append(_mdtable(["Req ID", "Name", "System Control"], [[_g(r, "req_id"), _g(r, "name"), _g(r, "system_control")] for r in p33]))
        p41 = _g(iec, "part_4_1_lifecycle", default=[])
        if p41:
            L.append("### 6.3 62443-4-1 — Secure Development Lifecycle\n")
            L.append(_mdtable(["Practice", "Name", "Recommendation"], [[_g(r, "practice"), _g(r, "name"), _g(r, "recommendation")] for r in p41]))
        p21 = _g(iec, "part_2_1_program", default=[])
        if p21:
            L.append("### 6.4 62443-2-1 — Asset-Owner Security Program\n")
            L.append(_mdtable(["Element", "Recommendation"], [[_g(r, "element"), _g(r, "recommendation")] for r in p21]))
    isa = _g(rep, "isa84_safety", default={})
    if isa:
        L.append("## 7. ISA-TR84.00.09 — Safety / Hazard / Consequence Analysis\n")
        L.append(f"**Applicable:** {'Yes' if _g(isa,'applicable',default=False) else 'No'} · **SIS/SIF:** {_g(isa,'sis_sif')}\n")
        hs = _g(isa, "hazard_scenarios", default=[])
        if hs:
            L.append(_mdtable(["Scenario", "Attack Path", "Consequence", "Severity", "Defeats IPLs", "Countermeasures"],
                     [[_g(h, "scenario"), _g(h, "attack_path"), _g(h, "consequence"), _g(h, "severity"),
                       "Yes" if _g(h, "defeats_protection_layers", default=False) else "No", _g(h, "countermeasures")] for h in hs]))
    rr = _g(rep, "risk_register", default=[])
    if rr:
        L.append("## 8. Risk Register\n")
        L.append(_mdtable(["ID", "Risk", "Threats", "ATT&CK", "Likelihood", "Impact", "Risk", "Recommendation", "Requirements"],
                 [[_g(r, "id"), _g(r, "risk"), ", ".join(_g(r, "threat_ids", default=[])), ", ".join(_g(r, "attack_ids", default=[])),
                   _g(r, "likelihood"), _g(r, "impact"), _g(r, "risk_level"), _g(r, "recommendation"), ", ".join(_g(r, "mapped_requirements", default=[]))] for r in rr]))
    if _g(rep, "diagram_mermaid"):
        L.append("## 9. Threat Model Diagram\n")
        L.append("```mermaid\n" + _g(rep, "diagram_mermaid").strip() + "\n```\n")
    if _g(rep, "assumptions", default=[]):
        L.append("## Assumptions\n")
        for a in _g(rep, "assumptions", default=[]):
            L.append(f"- {a}")
        L.append("")
    if _g(rep, "references", default=[]):
        L.append("## References\n")
        for r in _g(rep, "references", default=[]):
            L.append(f"- {r}")
        L.append("")
    return "\n".join(L)


def _inline_md(s):
    import re
    s = (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def md_to_html(md):
    """Tiny Markdown->HTML for the subset report_to_markdown emits (headings,
    GFM tables, blockquotes, bullet lists, bold, code). Stdlib only, no CDN."""
    lines = (md or "").split("\n")
    out = []
    i, n = 0, len(lines)
    in_ul = False

    def close_ul():
        nonlocal in_ul
        if in_ul:
            out.append("</ul>"); in_ul = False

    while i < n:
        st = lines[i].strip()
        if st.startswith("|") and i + 1 < n and set(lines[i + 1].strip()) <= set("|-: "):
            close_ul()
            header = [c.strip() for c in st.strip("|").split("|")]
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append("<table><thead><tr>" + "".join(f"<th>{_inline_md(h)}</th>" for h in header) +
                       "</tr></thead><tbody>" +
                       "".join("<tr>" + "".join(f"<td>{_inline_md(c)}</td>" for c in r) + "</tr>" for r in rows) +
                       "</tbody></table>")
            continue
        if st.startswith("### "):
            close_ul(); out.append(f"<h3>{_inline_md(st[4:])}</h3>")
        elif st.startswith("## "):
            close_ul(); out.append(f"<h2>{_inline_md(st[3:])}</h2>")
        elif st.startswith("# "):
            close_ul(); out.append(f"<h1>{_inline_md(st[2:])}</h1>")
        elif st.startswith("> "):
            close_ul(); out.append(f"<blockquote>{_inline_md(st[2:])}</blockquote>")
        elif st.startswith("- "):
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline_md(st[2:])}</li>")
        elif st == "":
            close_ul()
        else:
            close_ul(); out.append(f"<p>{_inline_md(st)}</p>")
        i += 1
    close_ul()
    return "\n".join(out)


def risk_counts(rep):
    c = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in _g(rep, "risk_register", default=[]):
        if _g(r, "risk_level") in c:
            c[_g(r, "risk_level")] += 1
    return c


# --- Artifact ingestion (server side; base64 input from browser) ---
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"}
KIND_HINTS = {
    "pid": ["p&id", "pid", "piping", "p-id"], "pfd": ["pfd", "process flow", "flow diagram"],
    "datasheet": ["datasheet", "data sheet", "spec sheet"], "manual": ["manual", "guide", "handbook", "instruction"],
    "fds": ["fds", "functional design", "design spec", "frs", "requirement"],
    "sysml": ["sysml", "bdd", "ibd", "block definition"], "uml": ["uml", "class diagram", "sequence", "xmi"],
    "network": ["network", "topology", "architecture"],
}
MAX_TEXT = 3_000_000        # retain full document text (hundreds of pages); distilled at analysis time
MAX_PDF_IMAGES = 10         # embedded images pulled from a PDF for vision models
MIN_PDF_IMAGE_BYTES = 12000 # skip tiny logos/icons


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
    """Best-effort PDF text extraction using ONLY the standard library (zlib).

    Handles the common case: FlateDecode content streams with standard text
    operators (Tj/TJ). Not a full PDF parser, but works for most text-based
    datasheets/manuals without any third-party dependency. Returns "" if it
    cannot recover text (e.g. scanned image PDFs)."""
    import re
    import zlib

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
                if n.isdigit():  # octal \ddd
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
        # 1) FlateDecode (most common in real datasheets/manuals)
        for attempt in (raw2, raw):
            try:
                return zlib.decompress(attempt)
            except Exception:
                pass
        # 2) ASCII85 (optionally + Flate) — e.g. reportlab default
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
        # 3) ASCIIHex (optionally + Flate)
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
        # 4) uncompressed content stream
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
    """Extract text from a .docx using only the standard library (zipfile+re)."""
    import io
    import re
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
        joined = "".join(texts)
        # crude cell separation
        joined = joined
        import html as _html
        chunks.append(_html.unescape(joined))
    return "\n".join(c for c in chunks if c.strip())


# Vision-provider image constraints. Anthropic/OpenAI/Gemini accept only these
# media types, reject CMYK JPEGs, and reject very large images. We validate every
# image BEFORE sending so one bad picture can't 400 the whole analysis.
SUPPORTED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_IMAGE_DIM = 8000        # px per side (provider hard limit is ~8000)
MAX_IMAGE_BYTES = 4_800_000  # ~5 MB provider cap, with headroom


def _scan_jpeg(data, start):
    """Walk JPEG marker segments from `start` (which must point at FF D8).
    Returns (end_offset, width, height, components) or None if not a valid JPEG.
    Walking segments (rather than searching for FF D9) avoids truncating a photo
    at an embedded EXIF thumbnail's end marker, and lets us read the color model."""
    n = len(data)
    if start + 2 > n or data[start] != 0xFF or data[start + 1] != 0xD8:
        return None
    pos = start + 2
    w = h = comps = None
    while pos + 1 < n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        # skip fill bytes
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]; pos += 1
        if marker == 0xD9:            # EOI
            return (pos, w, h, comps)
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:  # TEM / RSTn: no payload
            continue
        if pos + 2 > n:
            return None
        seg_len = (data[pos] << 8) | data[pos + 1]
        if seg_len < 2 or pos + seg_len > n:
            return None
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):  # SOF (frame header)
            if seg_len >= 8:
                h = (data[pos + 3] << 8) | data[pos + 4]
                w = (data[pos + 5] << 8) | data[pos + 6]
                comps = data[pos + 7]
        if marker == 0xDA:            # SOS: entropy data follows; find EOI
            pos += seg_len
            while pos + 1 < n:
                if data[pos] == 0xFF:
                    b = data[pos + 1]
                    if b == 0xD9:
                        return (pos + 2, w, h, comps)
                    if b == 0x00 or (0xD0 <= b <= 0xD7):  # stuffed byte / restart
                        pos += 2; continue
                pos += 1
            return (n, w, h, comps)   # ran to EOF without EOI: take what we have
        pos += seg_len
    return None


def _jpeg_ok(blob):
    """True if a JPEG blob is safe to send to a vision model (valid, RGB/grayscale
    — not CMYK — and within dimension/byte limits)."""
    info = _scan_jpeg(blob, 0)
    if not info:
        return False
    _end, w, h, comps = info
    if comps == 4:                       # CMYK — providers reject with "Could not process image"
        return False
    if w and h and (w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM):
        return False
    if len(blob) > MAX_IMAGE_BYTES:
        return False
    return True


def _pdf_extract_jpegs(data, cap=MAX_PDF_IMAGES, min_bytes=MIN_PDF_IMAGE_BYTES):
    """Pull embedded JPEG (DCTDecode) images out of a PDF using only the stdlib.
    Handles the common graphics-heavy case (scanned P&IDs/PFDs, product photos).
    Every image is validated (valid structure, non-CMYK, size-bounded) so a bad
    picture can never make the vision request fail. Returns [{b64, media_type}]."""
    out = []
    i, n = 0, len(data)
    while len(out) < cap:
        s = data.find(b"\xff\xd8\xff", i)
        if s == -1:
            break
        info = _scan_jpeg(data, s)
        if not info:
            i = s + 3
            continue
        end, w, h, comps = info
        blob = data[s:end]
        i = end
        if len(blob) < min_bytes:
            continue
        if comps == 4:                   # CMYK: skip (unsupported by vision APIs)
            continue
        if w and h and (w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM):
            continue
        if len(blob) > MAX_IMAGE_BYTES:
            continue
        out.append({"b64": base64.b64encode(blob).decode(), "media_type": "image/jpeg"})
    return out


def _png_dims(blob):
    """Return (w, h) for a PNG, or None."""
    if len(blob) >= 24 and blob[:8] == b"\x89PNG\r\n\x1a\n" and blob[12:16] == b"IHDR":
        w = int.from_bytes(blob[16:20], "big"); h = int.from_bytes(blob[20:24], "big")
        return (w, h)
    return None


def sanitize_images(images):
    """Keep only images a vision model can actually process. Returns (clean, dropped)
    where dropped is a count. Validates media type, base64, JPEG color model/size,
    and PNG dimensions. This is the last line of defense before an API call."""
    clean, dropped = [], 0
    for im in images or []:
        mt = (im.get("media_type") or "").lower()
        b64 = im.get("b64") or ""
        if mt not in SUPPORTED_IMAGE_TYPES or not b64:
            dropped += 1; continue
        try:
            raw = base64.b64decode(b64, validate=False)
        except Exception:  # noqa: BLE001
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
    """Return dict: filename, kind, is_image, text_excerpt, image_b64, media_type,
    extra_images, warnings, text_len. PDF/DOCX parsed with the stdlib only (no pip)."""
    ext = os.path.splitext(filename.lower())[1]
    kind = _classify(filename)
    warnings = []
    extra_images = []
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
            warnings.append(f"{ext} images can't be read by vision models — please re-save as PNG or JPG. "
                            "This file will be skipped for image analysis.")
        return {"filename": filename, "kind": kind if kind != "other" else "image", "is_image": True,
                "text_excerpt": "", "image_b64": b64data, "media_type": media,
                "extra_images": [], "text_len": 0, "warnings": warnings}
    text = ""
    if ext == ".pdf":
        text = _pdf_text_stdlib(data)
        try:
            extra_images = _pdf_extract_jpegs(data)
        except Exception:  # noqa: BLE001
            extra_images = []
        if not text.strip() and not extra_images:
            warnings.append("No embedded text or images found (likely a vector-only PDF). "
                            "Export the drawing pages as images (PNG/JPG) and upload them so a vision model can read them.")
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


def build_artifact_context(artifacts):
    blocks = []
    for a in artifacts or []:
        if a.get("is_image"):
            blocks.append(f"[Artifact: {a['filename']} ({a.get('kind')}) — provided as image to the vision model]")
            continue
        t = (a.get("text_excerpt") or "").strip()
        if t:
            blocks.append(f"--- Artifact: {a['filename']} (type: {a.get('kind')}) ---\n{t}")
    return "\n\n".join(blocks)


# --- Large-document distillation (map-reduce) so nothing is dropped ---
DISTILL_SMALL = 16000          # docs at/below this are used verbatim (no distillation needed)
DISTILL_CHUNK = 14000          # target characters per chunk
DISTILL_MAX_CHUNKS = 80        # per document; chunk size grows so ALL text is covered
DISTILL_PER_DOC_CAP = 45000    # cap distilled facts per document
DISTILL_TOTAL_CAP = 150000     # cap total distilled context fed to the final model

EXTRACT_SYSTEM = ("You are a security analyst extracting facts from ICS/OT/IoT technical documentation "
                  "(datasheets, manuals, P&ID/PFD, functional design specs) to feed a threat model. "
                  "Be terse and factual; preserve specifics.")

EXTRACT_INSTRUCTIONS = (
    "Extract ALL security-relevant facts from this excerpt of {name} (part {i} of {n}). Include, when present: "
    "product/model names & firmware versions; hardware (CPU/SoC/FPGA, memory, debug/test ports e.g. JTAG/UART/SWD); "
    "firmware & update mechanisms; interfaces & protocols (Ethernet/IP, PROFINET, PROFIBUS, S7comm, CIP, Modbus, DNP3, "
    "OPC UA, HART, serial, USB, wireless); network services/ports; authentication/credentials (defaults, hardcoded); "
    "web/management interfaces; cryptography; safety functions (SIS/SIF/SIL/F-CPU/PROFIsafe); and any stated "
    "vulnerabilities, CVEs, or security notes. Output terse bullet lines only. If nothing is security-relevant, output exactly: NONE.\n\nEXCERPT:\n")


def _chunk_text(text, target=DISTILL_CHUNK, max_chunks=DISTILL_MAX_CHUNKS):
    n = len(text)
    size = max(target, -(-n // max_chunks))   # grow chunk size so all text fits in <= max_chunks
    return [text[i:i + size] for i in range(0, n, size)]


def distill_document(text, filename, provider, model, api_key, base_url, progress):
    """Chunk the whole document and extract security-relevant facts from every chunk.
    Returns a compact facts string covering the entire document (nothing dropped)."""
    chunks = _chunk_text(text)
    facts = []
    for idx, ch in enumerate(chunks):
        progress(f"Reading {filename}: section {idx + 1} of {len(chunks)}…")
        prompt = EXTRACT_INSTRUCTIONS.format(name=filename, i=idx + 1, n=len(chunks)) + ch
        try:
            out = call_model(provider, model, EXTRACT_SYSTEM, prompt, None,
                             api_key, base_url, max_tokens=1600)
        except ProviderError:
            raise
        out = (out or "").strip()
        if out and out.upper() != "NONE":
            facts.append(out)
    joined = "\n".join(facts)
    return joined[:DISTILL_PER_DOC_CAP]


def build_analysis_context(artifacts, provider, model, api_key, base_url, vision, progress):
    """Assemble the prompt context from artifacts, distilling large documents so
    the entire content is processed. Returns (context_text, images, notes)."""
    blocks, images, notes = [], [], []
    total = 0
    for a in (artifacts or []):
        if a.get("is_image"):
            if vision and a.get("image_b64"):
                images.append({"b64": a["image_b64"], "media_type": a.get("media_type", "image/png")})
            else:
                notes.append(f"{a['filename']} (image) not sent — current model is not vision-capable.")
            continue
        # embedded images pulled from PDFs -> vision
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
#  SECTION 6B — dependency-free PDF engine (pure standard library)
# =============================================================================
# Standard-14 Helvetica width tables (units/1000), char codes 32..255.
_W_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500]
_W_HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278, 611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556]

_UNI_MAP = {"–": "-", "—": "-", "‘": "'", "’": "'", "“": '"',
            "”": '"', "…": "...", "•": "-", "→": "->", "←": "<-",
            "·": "-", "✓": "v", "✗": "x", "≤": "<=", "≥": ">=",
            " ": " ", "‑": "-", "−": "-", "®": "(R)", "™": "(TM)"}


def _norm(s):
    if s is None:
        return ""
    s = str(s)
    for k, v in _UNI_MAP.items():
        if k in s:
            s = s.replace(k, v)
    return "".join(ch if ord(ch) < 256 else "?" for ch in s)


def _cw(ch, bold):
    o = ord(ch)
    tbl = _W_HELVB if bold else _W_HELV
    if 32 <= o <= 255:
        return tbl[o - 32]
    return 500


def text_width(s, size, bold=False):
    s = _norm(s)
    return sum(_cw(c, bold) for c in s) * size / 1000.0


def wrap_text(s, size, maxw, bold=False):
    s = _norm(s).replace("\r", "")
    out = []
    for para in s.split("\n"):
        if para == "":
            out.append("")
            continue
        line = ""
        for word in para.split(" "):
            trial = word if not line else line + " " + word
            if text_width(trial, size, bold) <= maxw or not line:
                # hard-split very long words
                if text_width(word, size, bold) > maxw and not line:
                    cur = ""
                    for ch in word:
                        if text_width(cur + ch, size, bold) <= maxw:
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


def _esc(s):
    return _norm(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class ReportPDF:
    """Minimal, dependency-free PDF generator: text, tables, and vector graphics."""
    PW, PH = 595.28, 841.89          # A4 in points
    ML, MR, MT, MB = 46, 46, 52, 54  # margins

    C_INK = (0.11, 0.14, 0.18)
    C_HEAD = (0.043, 0.239, 0.388)   # deep blue
    C_ACC = (0.24, 0.61, 0.88)
    C_MUT = (0.42, 0.48, 0.56)
    C_LINE = (0.76, 0.80, 0.85)
    C_ZEBRA = (0.95, 0.97, 0.99)
    C_THFILL = (0.043, 0.239, 0.388)

    def __init__(self, title="Threat Model"):
        self.title = _norm(title)
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

    # ---- primitives (PDF coords: origin bottom-left) ----
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

    def line(self, x1, y1, x2, y2, stroke=(0, 0, 0), lw=0.6, dash=None):
        self._rgb(stroke, True)
        d = f"[{dash[0]} {dash[1]}] 0 d " if dash else ""
        rst = " [] 0 d" if dash else ""
        self.buf.append(f"{d}{lw:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S{rst}\n")

    def polyline(self, pts, stroke=(0, 0, 0), lw=0.8, close=False, fill=None):
        if not pts:
            return
        if fill:
            self._rgb(fill)
            self.buf.append(f"{pts[0][0]:.2f} {pts[0][1]:.2f} m " +
                            " ".join(f"{x:.2f} {y:.2f} l" for x, y in pts[1:]) + " f\n")
        self._rgb(stroke, True)
        self.buf.append(f"{lw:.2f} w {pts[0][0]:.2f} {pts[0][1]:.2f} m " +
                        " ".join(f"{x:.2f} {y:.2f} l" for x, y in pts[1:]) +
                        (" s\n" if close else " S\n"))

    def text(self, x, y, s, size=9.5, bold=False, color=None, align="l", maxw=None):
        s = _norm(s)
        if color is None:
            color = self.C_INK
        if align in ("c", "r") and maxw is not None:
            w = text_width(s, size, bold)
            if align == "c":
                x = x + (maxw - w) / 2.0
            else:
                x = x + (maxw - w)
        f = "F2" if bold else "F1"
        self._rgb(color)
        self.buf.append(f"BT /{f} {size:.1f} Tf {x:.2f} {y:.2f} Td ({_esc(s)}) Tj ET\n")

    # ---- flowing content (top-down cursor) ----
    def gap(self, h):
        self.y -= h

    def heading(self, s, level=1):
        sizes = {0: 19, 1: 14, 2: 11.5, 3: 10.2}
        size = sizes.get(level, 12)
        self.ensure(size + 12)
        self.y -= size
        self.text(self.ML, self.y, s, size=size, bold=True, color=self.C_HEAD)
        if level <= 1:
            self.y -= 4
            self.line(self.ML, self.y, self.PW - self.MR, self.y, stroke=self.C_HEAD, lw=1.2)
        self.y -= 6

    def paragraph(self, s, size=9.5, color=None, gap_after=5, bold=False):
        for ln in wrap_text(s, size, self.cw, bold):
            self.ensure(size + 3)
            self.y -= (size + 2)
            if ln:
                self.text(self.ML, self.y, ln, size=size, bold=bold, color=color or self.C_INK)
        self.y -= gap_after

    def bullet(self, s, size=9.5):
        indent = 12
        lines = wrap_text(s, size, self.cw - indent)
        for i, ln in enumerate(lines):
            self.ensure(size + 3)
            self.y -= (size + 2)
            if i == 0:
                self.text(self.ML + 2, self.y, "-", size=size, bold=True, color=self.C_ACC)
            self.text(self.ML + indent, self.y, ln, size=size)
        self.y -= 2

    def callout(self, s, size=9, color=None, bar=None):
        bar = bar or self.C_ACC
        pad = 6
        lines = wrap_text(s, size, self.cw - 2 * pad - 6)
        h = len(lines) * (size + 2) + 2 * pad
        self.ensure(h + 6)
        top = self.y
        self.rect(self.ML, top - h, self.cw, h, fill=(0.93, 0.96, 0.99))
        self.rect(self.ML, top - h, 3, h, fill=bar)
        ty = top - pad
        for ln in lines:
            ty -= (size + 2)
            self.text(self.ML + pad + 6, ty + 2, ln, size=size, color=color or self.C_INK)
        self.y = top - h - 6

    def kv_meta(self, s, size=9):
        self.ensure(size + 4)
        self.y -= (size + 2)
        self.text(self.ML, self.y, s, size=size, bold=False, color=self.C_MUT)
        self.y -= 3

    def table(self, headers, rows, weights=None, size=8.4, header_size=8.4):
        n = len(headers)
        if weights is None:
            weights = [1] * n
        tot = float(sum(weights))
        colw = [self.cw * (w / tot) for w in weights]
        pad = 3.5
        line_h = size + 2.4

        def row_height(cells, csize, bold=False):
            maxlines = 1
            for i, c in enumerate(cells):
                lines = wrap_text(str(c), csize, colw[i] - 2 * pad, bold)
                maxlines = max(maxlines, len(lines))
            return maxlines * line_h + 2 * pad

        def draw_header():
            hh = row_height(headers, header_size, True)
            self.ensure(hh)
            top = self.y
            self.rect(self.ML, top - hh, self.cw, hh, fill=self.C_THFILL)
            x = self.ML
            for i, c in enumerate(headers):
                ty = top - pad
                for ln in wrap_text(str(c), header_size, colw[i] - 2 * pad, True):
                    ty -= line_h
                    self.text(x + pad, ty + 2, ln, size=header_size, bold=True, color=(1, 1, 1))
                x += colw[i]
            self.y = top - hh
            return

        draw_header()
        zebra = False
        for r in rows:
            cells = [("" if c is None else str(c)) for c in r]
            hh = row_height(cells, size)
            if self.y - hh < self.MB:
                self.new_page()
                draw_header()
            top = self.y
            if zebra:
                self.rect(self.ML, top - hh, self.cw, hh, fill=self.C_ZEBRA)
            zebra = not zebra
            x = self.ML
            for i, c in enumerate(cells):
                ty = top - pad
                for ln in wrap_text(c, size, colw[i] - 2 * pad):
                    ty -= line_h
                    self.text(x + pad, ty + 2, ln, size=size, color=self.C_INK)
                x += colw[i]
            # cell borders
            self._rgb(self.C_LINE, True)
            x = self.ML
            for i in range(n + 1):
                self.line(x, top, x, top - hh, stroke=self.C_LINE, lw=0.4)
                if i < n:
                    x += colw[i]
            self.line(self.ML, top - hh, self.ML + self.cw, top - hh, stroke=self.C_LINE, lw=0.4)
            self.y = top - hh
        self.y -= 6

    # ---- diagram placement: render primitives scaled to content width ----
    def place_diagram(self, dw, dh, prims, max_h=560):
        if dw <= 0 or dh <= 0:
            return
        scale = min(self.cw / dw, 1.6)
        sw, sh = dw * scale, dh * scale
        if sh > max_h:
            scale *= max_h / sh
            sw, sh = dw * scale, dh * scale
        self.ensure(sh + 8)
        top = self.y
        ox = self.ML + (self.cw - sw) / 2.0

        def TX(x):
            return ox + x * scale

        def TY(y):
            return top - y * scale   # primitives use top-left y-down

        for p in prims:
            t = p["t"]
            if t == "rect":
                x, y, w, h = TX(p["x"]), TY(p["y"] + p["h"]), p["w"] * scale, p["h"] * scale
                self.rect(x, y, w, h, fill=p.get("fill"), stroke=p.get("stroke"), lw=p.get("lw", 0.7))
            elif t == "line":
                self.line(TX(p["x1"]), TY(p["y1"]), TX(p["x2"]), TY(p["y2"]),
                          stroke=p.get("stroke", (0, 0, 0)), lw=p.get("lw", 0.7), dash=p.get("dash"))
            elif t == "poly":
                pts = [(TX(x), TY(y)) for x, y in p["pts"]]
                self.polyline(pts, stroke=p.get("stroke", (0, 0, 0)), lw=p.get("lw", 0.8),
                              close=p.get("close", False), fill=p.get("fill"))
            elif t == "text":
                fs = p.get("size", 8) * scale
                self.text(TX(p["x"]), TY(p["y"]) - fs * 0.8, p["s"],
                          size=fs, bold=p.get("bold", False), color=p.get("color", self.C_INK),
                          align=p.get("align", "l"),
                          maxw=(p.get("maxw", 0) * scale if p.get("maxw") else None))
        self.y = top - sh - 8

    # ---- output ----
    def save_bytes(self):
        self._flush()
        # footers with page numbers
        npages = len(self.pages)
        objs = []
        # font objects
        font_objs = {
            "F1": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "F2": "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        }
        # object numbering: 1 Catalog, 2 Pages, 3 F1, 4 F2, then pages+contents
        content_objs = []
        page_objs = []
        obj_id = 5
        page_ids = []
        for idx, content in enumerate(self.pages):
            footer = (f"BT /F1 7.5 Tf {self.C_MUT[0]:.3f} {self.C_MUT[1]:.3f} {self.C_MUT[2]:.3f} rg "
                      f"{self.ML:.1f} {self.MB - 22:.1f} Td (ICS/OT/IoT Threat Modeler) Tj ET\n"
                      f"BT /F1 7.5 Tf {self.C_MUT[0]:.3f} {self.C_MUT[1]:.3f} {self.C_MUT[2]:.3f} rg "
                      f"{self.PW - self.MR - 70:.1f} {self.MB - 22:.1f} Td (Page {idx + 1} of {npages}) Tj ET\n")
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


# =============================================================================
#  SECTION 6C — diagram layout, SVG renderer, and full PDF report assembler
# =============================================================================
# Colors (0..1)
_D_INK = (0.12, 0.15, 0.20)
_D_HEAD = (0.043, 0.239, 0.388)
_D_ACC = (0.18, 0.52, 0.80)
_D_MUT = (0.42, 0.48, 0.56)
_D_ZONE = (0.90, 0.95, 0.99)
_D_ZONEB = (0.55, 0.72, 0.88)
_D_NODE = (1.0, 1.0, 1.0)
_D_NODEB = (0.30, 0.55, 0.78)
_D_EXT = (0.93, 0.94, 0.97)
_D_ATTF = (1.0, 0.90, 0.90)
_D_ATTB = (0.80, 0.22, 0.28)
_D_FLOW = (0.35, 0.45, 0.55)
_STAGE_COLORS = [(0.05, 0.30, 0.50), (0.09, 0.36, 0.55), (0.13, 0.42, 0.58),
                 (0.60, 0.35, 0.15), (0.65, 0.42, 0.12), (0.30, 0.45, 0.20),
                 (0.20, 0.45, 0.45), (0.35, 0.30, 0.55), (0.45, 0.25, 0.45),
                 (0.62, 0.24, 0.30), (0.70, 0.20, 0.24), (0.55, 0.12, 0.16)]


def _arrow(prims, x1, y1, x2, y2, color=_D_FLOW, lw=1.0, dash=None):
    prims.append({"t": "line", "x1": x1, "y1": y1, "x2": x2, "y2": y2, "stroke": color, "lw": lw, "dash": dash})
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    sz = 6
    ax, ay = x2, y2
    p1 = (ax - sz * math.cos(ang - 0.4), ay - sz * math.sin(ang - 0.4))
    p2 = (ax - sz * math.cos(ang + 0.4), ay - sz * math.sin(ang + 0.4))
    prims.append({"t": "poly", "pts": [(ax, ay), p1, p2], "fill": color, "stroke": color, "lw": 0.5, "close": True})


def _node(prims, x, y, w, h, label, fill=_D_NODE, stroke=_D_NODEB, fs=8.2, bold=True, tcol=_D_INK):
    prims.append({"t": "rect", "x": x, "y": y, "w": w, "h": h, "fill": fill, "stroke": stroke, "lw": 1.0, "rx": 4})
    lines = wrap_text(label, fs, w - 8, bold)[:3]
    ty = y + (h - len(lines) * (fs + 1.5)) / 2.0
    for ln in lines:
        ty += (fs + 1.5)
        prims.append({"t": "text", "x": x + 4, "y": ty - fs, "s": ln, "size": fs, "bold": bold,
                      "color": tcol, "align": "c", "maxw": w - 8})


def _as_node(x):
    return x if isinstance(x, dict) else {"id": str(x), "label": str(x)}


def _as_zone(x):
    return x if isinstance(x, dict) else {"name": str(x), "nodes": []}


def layout_threat(td):
    prims = []
    td = td if isinstance(td, dict) else {}
    zones = [_as_zone(z) for z in (td.get("zones") or [])]
    ext = [_as_node(e) for e in (td.get("external_nodes") or [])]
    flows = [f for f in (td.get("flows") or []) if isinstance(f, dict)]
    atk = [a for a in (td.get("attacker_entrypoints") or []) if isinstance(a, dict)]
    NW, NH = 150, 40
    pos = {}
    # external column
    ex_x = 16
    ey = 46
    for e in ext:
        _node(prims, ex_x, ey, NW, NH, e.get("label", e.get("id", "")), fill=_D_EXT, stroke=(0.6, 0.6, 0.68))
        pos[e.get("id", e.get("label", ""))] = (ex_x + NW / 2, ey + NH / 2)
        ey += NH + 22
    ext_bottom = ey
    # zones
    zx = 210
    zy = 40
    cols = 3
    inner_w = cols * NW + (cols - 1) * 16
    zone_w = inner_w + 24
    for zi, z in enumerate(zones):
        nodes = [_as_node(n) for n in (z.get("nodes") or [])]
        rows = max(1, (len(nodes) + cols - 1) // cols)
        zone_h = 26 + rows * (NH + 14) + 6
        prims.append({"t": "rect", "x": zx, "y": zy, "w": zone_w, "h": zone_h, "fill": _D_ZONE,
                      "stroke": _D_ZONEB, "lw": 1.1, "rx": 6})
        prims.append({"t": "text", "x": zx + 10, "y": zy + 6, "s": z.get("name", f"Zone {zi+1}"),
                      "size": 9, "bold": True, "color": _D_HEAD})
        nx0 = zx + 12
        ny0 = zy + 26
        for ni, nd in enumerate(nodes):
            r, c = divmod(ni, cols)
            nx = nx0 + c * (NW + 16)
            ny = ny0 + r * (NH + 14)
            _node(prims, nx, ny, NW, NH, nd.get("label", nd.get("id", "")))
            pos[nd.get("id", nd.get("label", ""))] = (nx + NW / 2, ny + NH / 2)
        zy += zone_h + 20
    zones_bottom = zy
    W = zx + zone_w + 16
    # flows
    for f in flows:
        a = pos.get(f.get("from")); b = pos.get(f.get("to"))
        if not a or not b:
            continue
        _arrow(prims, a[0], a[1], b[0], b[1], color=_D_FLOW, lw=1.0)
        lbl = f.get("label", "")
        if lbl:
            mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
            lw = text_width(lbl, 7) + 6
            prims.append({"t": "rect", "x": mx - lw / 2, "y": my - 7, "w": lw, "h": 12, "fill": (1, 1, 1)})
            prims.append({"t": "text", "x": mx - lw / 2, "y": my - 6, "s": lbl, "size": 7, "color": _D_MUT,
                          "align": "c", "maxw": lw})
    # attacker
    H = max(ext_bottom, zones_bottom) + 10
    if atk:
        ax, ay = 16, H
        _node(prims, ax, ay, NW, NH, "Attacker", fill=_D_ATTF, stroke=_D_ATTB, tcol=_D_ATTB)
        acx, acy = ax + NW / 2, ay + NH / 2
        for e in atk:
            b = pos.get(e.get("to"))
            if not b:
                continue
            _arrow(prims, acx, acy, b[0], b[1], color=_D_ATTB, lw=1.1, dash=(4, 3))
            lbl = e.get("label", e.get("threat_id", ""))
            if lbl:
                mx, my = (acx + b[0]) / 2, (acy + b[1]) / 2
                lw = text_width(lbl, 7) + 6
                prims.append({"t": "rect", "x": mx - lw / 2, "y": my - 7, "w": lw, "h": 12, "fill": (1, 1, 1)})
                prims.append({"t": "text", "x": mx - lw / 2, "y": my - 6, "s": lbl, "size": 7,
                              "color": _D_ATTB, "align": "c", "maxw": lw})
        H = ay + NH + 12
    return max(W, 400), H, prims


def _stage_techs(stage):
    if not isinstance(stage, dict):
        return [str(stage)]
    techs = stage.get("techniques") or []
    out = []
    for t in techs:
        if isinstance(t, dict):
            out.append((t.get("id", "") + " " + t.get("name", "")).strip())
        else:
            out.append(str(t))
    return out


def layout_killchain(kc):
    prims = []
    W = 760
    lab_w = 196
    right_x = 40 + lab_w + 18
    right_w = W - right_x - 16
    y = 24
    spine_x = 22
    centers = []
    for i, st in enumerate(kc if isinstance(kc, list) else []):
        if not isinstance(st, dict):
            st = {"tactic": str(st), "techniques": []}
        techs = _stage_techs(st)
        tlines = []
        for t in techs:
            tlines += wrap_text("- " + t, 8, right_w)
        if st.get("note"):
            tlines += wrap_text(st["note"], 7.5, right_w)
        row_h = max(44, len(tlines) * 11 + 16)
        col = _STAGE_COLORS[i % len(_STAGE_COLORS)]
        # label box
        prims.append({"t": "rect", "x": 40, "y": y, "w": lab_w, "h": row_h, "fill": col, "stroke": col, "rx": 5})
        prims.append({"t": "text", "x": 48, "y": y + 8, "s": f"{i+1}. {st.get('tactic','')}", "size": 9.2,
                      "bold": True, "color": (1, 1, 1), "align": "l", "maxw": lab_w - 16})
        for j, ln in enumerate(wrap_text(st.get("tactic", ""), 9.2, lab_w - 16, True)[1:4]):
            prims.append({"t": "text", "x": 48, "y": y + 8 + (j + 1) * 11, "s": ln, "size": 9.2, "bold": True,
                          "color": (1, 1, 1), "maxw": lab_w - 16})
        # right techniques
        ty = y + 8
        for ln in tlines:
            prims.append({"t": "text", "x": right_x, "y": ty, "s": ln, "size": 8, "color": _D_INK, "maxw": right_w})
            ty += 11
        centers.append(y + row_h / 2)
        y += row_h + 14
    H = y + 4
    # spine with arrows
    for i in range(len(centers) - 1):
        _arrow(prims, spine_x, centers[i], spine_x, centers[i + 1] - 4, color=_D_ACC, lw=1.6)
    for cy in centers:
        prims.append({"t": "rect", "x": spine_x - 4, "y": cy - 4, "w": 8, "h": 8, "fill": _D_ACC, "stroke": _D_ACC, "rx": 4})
    return W, H, prims


def layout_mindmap(mm):
    prims = []
    mm = mm if isinstance(mm, dict) else {}
    branches = [b if isinstance(b, dict) else {"domain": str(b), "items": []}
                for b in (mm.get("branches") or [])]
    root = mm.get("root") or "Target"
    if not isinstance(root, str):
        root = str(root)
    bx = 250
    ix = 462
    item_w = 430
    y = 20
    branch_centers = []
    for bi, br in enumerate(branches):
        items = br.get("items") or []
        ilines = []
        for it in items:
            if isinstance(it, dict):
                s = it.get("label", "")
                ids = it.get("ids") or []
                if ids:
                    s += "  [" + ", ".join(ids) + "]"
            else:
                s = str(it)
            ilines.append(("- " + s, wrap_text("- " + s, 8, item_w)))
        total_ilines = sum(len(w) for _, w in ilines) or 1
        block_h = max(30, total_ilines * 11 + 8)
        col = _STAGE_COLORS[bi % len(_STAGE_COLORS)]
        # branch node
        bnh = 30
        bcy = y + block_h / 2
        _node(prims, bx, bcy - bnh / 2, 180, bnh, br.get("domain", f"Branch {bi+1}"),
              fill=(col[0], col[1], col[2]), stroke=col, tcol=(1, 1, 1), fs=8.6)
        branch_centers.append(bcy)
        # items
        ty = y + 4
        prims.append({"t": "line", "x1": bx + 180, "y1": bcy, "x2": ix - 8, "y2": bcy, "stroke": col, "lw": 1.0})
        for _, wlines in ilines:
            for ln in wlines:
                prims.append({"t": "text", "x": ix, "y": ty, "s": ln, "size": 8, "color": _D_INK, "maxw": item_w})
                ty += 11
        y += block_h + 12
    H = max(y, 80)
    # root
    rh = 40
    rcy = H / 2
    _node(prims, 16, rcy - rh / 2, 180, rh, root, fill=_D_HEAD, stroke=_D_HEAD, tcol=(1, 1, 1), fs=9)
    for bcy in branch_centers:
        prims.append({"t": "line", "x1": 196, "y1": rcy, "x2": bx, "y2": bcy, "stroke": _D_ACC, "lw": 1.1})
    W = ix + item_w + 16
    return W, H, prims


def layout_sans(sk):
    """Two-stage SANS ICS Cyber Kill Chain. Each stage has a header band; each
    phase is a labelled row with the mapped ATT&CK-for-ICS techniques / notes."""
    prims = []
    sk = sk if isinstance(sk, dict) else {}
    stages = [s for s in (sk.get("stages") or []) if isinstance(s, dict)]
    W = 780
    lab_w = 230
    right_x = 40 + lab_w + 18
    right_w = W - right_x - 16
    spine_x = 22
    y = 20
    centers = []
    _S1 = (0.06, 0.28, 0.46)   # stage-1 band
    _S2 = (0.60, 0.20, 0.24)   # stage-2 band (ICS attack — red family)
    for si, st in enumerate(stages):
        stage_name = st.get("stage") or (f"Stage {si+1}")
        phases = [p for p in (st.get("phases") or []) if isinstance(p, dict)]
        band = _S1 if si == 0 else _S2
        # stage header band spanning full width
        prims.append({"t": "rect", "x": 40, "y": y, "w": W - 56, "h": 24, "fill": band, "stroke": band, "rx": 5})
        prims.append({"t": "text", "x": 48, "y": y + 6, "s": stage_name, "size": 10, "bold": True,
                      "color": (1, 1, 1), "maxw": W - 72})
        y += 24 + 10
        for pi, ph in enumerate(phases):
            name = ph.get("phase") or f"Phase {pi+1}"
            items = ph.get("items") or []
            note = ph.get("note") or ""
            tlines = []
            for it in items:
                lbl = it.get("label", "") if isinstance(it, dict) else str(it)
                if lbl:
                    tlines += wrap_text("- " + lbl, 8, right_w)
            if not tlines and note:
                tlines += wrap_text(note, 7.8, right_w)
            elif note:
                tlines += wrap_text(note, 7.6, right_w)
            if not tlines:
                tlines = wrap_text("(No specific techniques mapped from the analysis for this phase.)", 7.6, right_w)
            row_h = max(40, len(tlines) * 11 + 14)
            col = band if not items else _STAGE_COLORS[(si * 5 + pi) % len(_STAGE_COLORS)]
            prims.append({"t": "rect", "x": 40, "y": y, "w": lab_w, "h": row_h, "fill": col, "stroke": col, "rx": 5})
            for j, ln in enumerate(wrap_text(name, 8.8, lab_w - 16, True)[:4]):
                prims.append({"t": "text", "x": 48, "y": y + 8 + j * 11, "s": ln, "size": 8.8, "bold": True,
                              "color": (1, 1, 1), "maxw": lab_w - 16})
            ty = y + 8
            first = True
            for ln in tlines:
                is_note = note and not items
                prims.append({"t": "text", "x": right_x, "y": ty, "s": ln, "size": 7.8 if is_note else 8,
                              "color": _D_MUT if is_note else _D_INK, "maxw": right_w})
                ty += 11
                first = False
            centers.append(y + row_h / 2)
            y += row_h + 12
        y += 6
    H = y + 4
    for i in range(len(centers) - 1):
        _arrow(prims, spine_x, centers[i], spine_x, centers[i + 1] - 4, color=_D_ACC, lw=1.6)
    for cy in centers:
        prims.append({"t": "rect", "x": spine_x - 4, "y": cy - 4, "w": 8, "h": 8, "fill": _D_ACC, "stroke": _D_ACC, "rx": 4})
    return W, H, prims


def _c255(c):
    return f"rgb({int(c[0]*255)},{int(c[1]*255)},{int(c[2]*255)})"


def prims_to_svg(W, H, prims):
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.0f} {H:.0f}" '
           f'font-family="Helvetica,Arial,sans-serif" width="100%">',
           f'<rect x="0" y="0" width="{W:.0f}" height="{H:.0f}" fill="white"/>']
    for p in prims:
        t = p["t"]
        if t == "rect":
            rx = p.get("rx", 0)
            fill = _c255(p["fill"]) if p.get("fill") else "none"
            stroke = f' stroke="{_c255(p["stroke"])}" stroke-width="{p.get("lw",1)}"' if p.get("stroke") else ""
            out.append(f'<rect x="{p["x"]:.1f}" y="{p["y"]:.1f}" width="{p["w"]:.1f}" height="{p["h"]:.1f}" '
                       f'rx="{rx}" fill="{fill}"{stroke}/>')
        elif t == "line":
            dash = f' stroke-dasharray="{p["dash"][0]},{p["dash"][1]}"' if p.get("dash") else ""
            out.append(f'<line x1="{p["x1"]:.1f}" y1="{p["y1"]:.1f}" x2="{p["x2"]:.1f}" y2="{p["y2"]:.1f}" '
                       f'stroke="{_c255(p.get("stroke",(0,0,0)))}" stroke-width="{p.get("lw",1)}"{dash}/>')
        elif t == "poly":
            pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in p["pts"])
            fill = _c255(p["fill"]) if p.get("fill") else "none"
            tag = "polygon" if p.get("close") else "polyline"
            out.append(f'<{tag} points="{pts}" fill="{fill}" stroke="{_c255(p.get("stroke",(0,0,0)))}" '
                       f'stroke-width="{p.get("lw",1)}"/>')
        elif t == "text":
            s = _svg_esc(p["s"])
            size = p.get("size", 8)
            anchor = "start"
            x = p["x"]
            if p.get("align") == "c" and p.get("maxw"):
                anchor = "middle"; x = p["x"] + p["maxw"] / 2
            elif p.get("align") == "r" and p.get("maxw"):
                anchor = "end"; x = p["x"] + p["maxw"]
            weight = "bold" if p.get("bold") else "normal"
            y = p["y"] + size * 0.85
            out.append(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size:.1f}" text-anchor="{anchor}" '
                       f'font-weight="{weight}" fill="{_c255(p.get("color",(0,0,0)))}">{s}</text>')
    out.append("</svg>")
    return "".join(out)


def _svg_esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# --- Deterministic diagram synthesis (no model call) --------------------------
# If a model returns a perfect report but omits or malforms the diagram objects,
# we rebuild all three LOCALLY from the report's own content. This is instant,
# works offline, and never alters the narrative or tables.
def _dg_slug(s, i):
    out = []
    for ch in str(s or ""):
        out.append(ch if (ch.isalnum()) else "_")
    slug = "".join(out).strip("_").lower()
    while "__" in slug:
        slug = slug.replace("__", "_")
    return (slug or ("n%d" % i))[:26]


def _syn_threat(rep):
    sm = rep.get("system_model") if isinstance(rep.get("system_model"), dict) else {}
    comps = sm.get("components") or []
    ifaces = [i for i in (sm.get("interfaces") or []) if isinstance(i, dict)]
    dflows = [f for f in (sm.get("data_flows") or []) if isinstance(f, dict)]
    nodes, idmap, used = [], {}, set()
    for i, c in enumerate(comps):
        name = (c.get("name") or c.get("role")) if isinstance(c, dict) else str(c)
        name = name or ("Component %d" % (i + 1))
        nid = base = _dg_slug(name, i)
        k = 1
        while nid in used:
            nid = "%s_%d" % (base, k); k += 1
        used.add(nid); idmap[name] = nid
        nodes.append({"id": nid, "label": name})
    if not nodes:
        tgt = rep.get("target") or "System"
        nodes = [{"id": "system", "label": tgt}]; idmap[tgt] = "system"
    primary = nodes[0]["id"]
    external, entry, flows, ext_seen = [], [], [], set()
    for i, itf in enumerate(ifaces):
        exposure = (itf.get("exposure") or "").lower()
        name = itf.get("name") or itf.get("protocol") or ("Interface %d" % (i + 1))
        proto = itf.get("protocol") or itf.get("type") or name
        if exposure in ("external", "zone"):
            key = proto.lower()
            if key in ext_seen:
                continue
            ext_seen.add(key)
            eid = "ext_%d" % i
            lbl = ("External: %s" if exposure == "external" else "Peer: %s") % proto
            external.append({"id": eid, "label": lbl})
            flows.append({"from": eid, "to": primary, "label": name})
            entry.append({"to": primary, "label": name})
    for f in dflows:
        fa, fb = idmap.get(f.get("from")), idmap.get(f.get("to"))
        if fa and fb and fa != fb:
            flows.append({"from": fa, "to": fb, "label": f.get("protocol") or f.get("data") or ""})
    zname = "In-Scope Components" if len(nodes) > 1 else (rep.get("target") or "System")
    return {"zones": [{"name": zname, "nodes": nodes}],
            "external_nodes": external, "flows": flows, "attacker_entrypoints": entry}


def _syn_killchain(rep):
    rows = [r for r in (rep.get("attack_ics_table") or []) if isinstance(r, dict)]
    order = {name: i for i, (_id, name, _d) in enumerate(ATTACK_ICS_TACTICS)}
    groups, seen = {}, {}
    for r in rows:
        tac = (r.get("tactic") or "").strip() or "Other"
        g = groups.setdefault(tac, [])
        s = seen.setdefault(tac, set())
        tid = (r.get("technique_id") or "").strip()
        tname = (r.get("technique_name") or "").strip()
        key = (tid, tname)
        if (tid or tname) and key not in s:
            s.add(key); g.append({"id": tid, "name": tname})
    stages = []
    for tac in sorted(groups.keys(), key=lambda t: order.get(t, 999)):
        stages.append({"tactic": tac, "techniques": groups[tac]})
    return stages


def _syn_mindmap(rep):
    root = rep.get("target") or "Target"
    if not isinstance(root, str):
        root = str(root)
    order, branches = [], {}

    def add(domain, label, ids):
        domain = (domain or "General").strip() or "General"
        if domain not in branches:
            branches[domain] = []; order.append(domain)
        if label:
            branches[domain].append({"label": label, "ids": [x for x in (ids or []) if x]})

    for r in (rep.get("attify_surface") or []):
        if isinstance(r, dict):
            add(r.get("domain"), r.get("technique") or r.get("vector"), r.get("related_threat_ids"))
    if not any(branches.values()):
        order, branches = [], {}
        dm = rep.get("device_model_emb3d") if isinstance(rep.get("device_model_emb3d"), dict) else {}
        for p in (dm.get("properties") or []):
            if isinstance(p, dict):
                add(p.get("category"), p.get("feature_or_interface"),
                    [p.get("property_code")] if p.get("property_code") else [])
    if not any(branches.values()):
        order, branches = [], {}
        for r in (rep.get("threat_table_emb3d") or []):
            if isinstance(r, dict):
                add(r.get("emb3d_element") or "EMB3D Threats", r.get("threat_name"),
                    [r.get("threat_id")] if r.get("threat_id") else [])
    return {"root": root, "branches": [{"domain": d, "items": branches[d]} for d in order if branches[d]]}


# SANS ICS Cyber Kill Chain (Assante & Lee, SANS 2015) — a two-stage model.
# We map the analysis's MITRE ATT&CK for ICS tactics into the SANS phases so the
# diagram reflects THIS target, while preserving the canonical SANS structure.
_SANS_STAGE1 = "Stage 1 — Cyber Intrusion Preparation and Execution"
_SANS_STAGE2 = "Stage 2 — ICS Attack Development and Execution"
# ordered phases per stage, with a default descriptive note for phases that have
# no direct ATT&CK-for-ICS tactic mapping (recon/weaponization/validation).
_SANS_PHASES = [
    (_SANS_STAGE1, "Planning — Reconnaissance",
     "Adversary researches the target, its protocols, suppliers, and known vulnerabilities (often OSINT/IT-side)."),
    (_SANS_STAGE1, "Preparation — Weaponization & Targeting",
     "Exploits/malware are prepared and specific delivery targets selected."),
    (_SANS_STAGE1, "Cyber Intrusion — Delivery, Exploit, Install/Modify", ""),
    (_SANS_STAGE1, "Management & Enablement — C2", ""),
    (_SANS_STAGE1, "Sustainment, Entrenchment, Development & Execution", ""),
    (_SANS_STAGE2, "Attack Development & Tuning",
     "Adversary develops and refines the ICS-specific attack using knowledge gained in Stage 1."),
    (_SANS_STAGE2, "Validation",
     "Attack is tested against a mirrored or representative environment to ensure the intended physical effect."),
    (_SANS_STAGE2, "ICS Attack — Deliver, Install/Modify, Execute", ""),
]
# MITRE ATT&CK-for-ICS tactic -> SANS phase name it best supports.
_TACTIC_TO_SANS = {
    "Initial Access": "Cyber Intrusion — Delivery, Exploit, Install/Modify",
    "Execution": "Cyber Intrusion — Delivery, Exploit, Install/Modify",
    "Command and Control": "Management & Enablement — C2",
    "Persistence": "Sustainment, Entrenchment, Development & Execution",
    "Privilege Escalation": "Sustainment, Entrenchment, Development & Execution",
    "Evasion": "Sustainment, Entrenchment, Development & Execution",
    "Discovery": "Sustainment, Entrenchment, Development & Execution",
    "Lateral Movement": "Sustainment, Entrenchment, Development & Execution",
    "Collection": "Sustainment, Entrenchment, Development & Execution",
    "Inhibit Response Function": "ICS Attack — Deliver, Install/Modify, Execute",
    "Impair Process Control": "ICS Attack — Deliver, Install/Modify, Execute",
    "Impact": "ICS Attack — Deliver, Install/Modify, Execute",
}


def _syn_sans(rep):
    rows = [r for r in (rep.get("attack_ics_table") or []) if isinstance(r, dict)]
    phase_items, seen = {}, {}
    for r in rows:
        tac = (r.get("tactic") or "").strip()
        phase = _TACTIC_TO_SANS.get(tac)
        if not phase:
            continue
        tid = (r.get("technique_id") or "").strip()
        tname = (r.get("technique_name") or "").strip()
        label = (tid + " " + tname).strip() or tac
        s = seen.setdefault(phase, set())
        if label not in s:
            s.add(label)
            phase_items.setdefault(phase, []).append({"label": label + f"  ({tac})" if tac else label})
    stages, cur = [], {}
    for stage_name, phase_name, note in _SANS_PHASES:
        if stage_name not in cur:
            cur[stage_name] = {"stage": stage_name, "phases": []}
            stages.append(cur[stage_name])
        items = phase_items.get(phase_name, [])
        cur[stage_name]["phases"].append({"phase": phase_name, "items": items, "note": note})
    return {"stages": stages}


def synthesize_diagrams(rep):
    """Build all four diagrams from the report's own content (no model call)."""
    if not isinstance(rep, dict):
        return {}
    return {"threat_diagram": _syn_threat(rep), "kill_chain": _syn_killchain(rep),
            "attack_mindmap": _syn_mindmap(rep), "sans_kill_chain": _syn_sans(rep)}


def _diagram_missing(v, key):
    if not v:
        return True
    if key == "kill_chain":
        return not (isinstance(v, list) and len(v) > 0)
    if key == "threat_diagram":
        return not (isinstance(v, dict) and v.get("zones"))
    if key == "attack_mindmap":
        return not (isinstance(v, dict) and v.get("branches"))
    if key == "sans_kill_chain":
        return not (isinstance(v, dict) and v.get("stages"))
    return False


def ensure_diagrams(rep):
    """Fill any missing/empty/malformed diagram in-place from report content.
    Returns the list of diagram keys that were (re)built."""
    if not isinstance(rep, dict):
        return []
    filled, syn = [], None
    for key in ("threat_diagram", "kill_chain", "attack_mindmap", "sans_kill_chain"):
        if _diagram_missing(rep.get(key), key):
            if syn is None:
                syn = synthesize_diagrams(rep)
            cand = syn.get(key)
            if not _diagram_missing(cand, key):
                rep[key] = cand; filled.append(key)
    return filled


def report_svgs(rep):
    """Render the three diagrams to SVG. Missing/malformed diagrams are rebuilt
    from report content first, so a report never renders with blank diagrams.
    Each is isolated so one bad diagram never breaks the others or the report."""
    if not isinstance(rep, dict):
        return {}
    try:
        ensure_diagrams(rep)
    except Exception:  # noqa: BLE001
        pass
    svgs = {}
    for key, layout, field in (("threat", layout_threat, "threat_diagram"),
                               ("killchain", layout_killchain, "kill_chain"),
                               ("sans", layout_sans, "sans_kill_chain"),
                               ("mindmap", layout_mindmap, "attack_mindmap")):
        data = rep.get(field)
        if not data:
            continue
        try:
            W, H, pr = layout(data)
            svgs[key] = prims_to_svg(W, H, pr)
        except Exception:  # noqa: BLE001
            pass  # skip a malformed diagram rather than failing the whole render
    return svgs


def report_to_pdf(rep, meta=None):
    meta = meta or {}
    try:
        ensure_diagrams(rep)  # rebuild any missing diagram from report content
    except Exception:  # noqa: BLE001
        pass
    g = _g
    target = g(rep, "target") or meta.get("target", "Target")
    pdf = ReportPDF(target)
    pdf.heading(f"ICS/OT/IoT Threat Model", 0)
    pdf.paragraph(target, size=13, bold=True, color=pdf.C_HEAD, gap_after=2)
    prov = f"{meta.get('provider','')} / {meta.get('model','')}".strip(" /")
    pdf.kv_meta(f"Generated {meta.get('generated_at','')}" + (f"  ·  Model: {prov}" if prov else ""))
    pdf.callout("Frameworks: MITRE EMB3D · MITRE ATT&CK for ICS · ISA/IEC 62443 (3-3, 4-2, 4-1, 2-1) · "
                "ISA-TR84.00.09 · Attify IoT.  Identifiers marked * are model-supplied (not from the embedded reference set).")

    if g(rep, "executive_summary"):
        pdf.heading("Executive Summary", 1)
        pdf.paragraph(g(rep, "executive_summary"))

    sm = g(rep, "system_model", default={})
    if sm:
        pdf.heading("1. System Model", 1)
        if g(sm, "description"):
            pdf.paragraph(g(sm, "description"))
        comps = g(sm, "components", default=[])
        if comps:
            pdf.heading("Components", 3)
            pdf.table(["Component", "Role", "Sub-components"],
                      [[g(c, "name"), g(c, "role"), ", ".join(g(c, "sub_components", default=[]))] for c in comps],
                      weights=[2, 2.4, 2.6])
        ifs = g(sm, "interfaces", default=[])
        if ifs:
            pdf.heading("Interfaces", 3)
            pdf.table(["Interface", "Type", "Protocol", "Exposure"],
                      [[g(i, "name"), g(i, "type"), g(i, "protocol"), g(i, "exposure")] for i in ifs],
                      weights=[2.4, 1.4, 2.2, 1.4])
        fl = g(sm, "data_flows", default=[])
        if fl:
            pdf.heading("Data Flows", 3)
            pdf.table(["From", "To", "Data", "Protocol", "Crosses boundary"],
                      [[g(f, "from"), g(f, "to"), g(f, "data"), g(f, "protocol"),
                        "Yes" if g(f, "trust_boundary_crossed", default=False) else "No"] for f in fl],
                      weights=[2, 2, 2.4, 1.6, 1.2])
        zc = g(sm, "zones_conduits", default=[])
        if zc:
            pdf.heading("Security Zones & Conduits (62443)", 3)
            pdf.table(["Zone", "Assets", "Conduit to", "Controls"],
                      [[g(z, "zone"), ", ".join(g(z, "assets", default=[])), g(z, "conduit_to"), g(z, "controls")] for z in zc],
                      weights=[1.8, 2.6, 1.8, 2.4])

    dm = g(rep, "device_model_emb3d", default={})
    props = g(dm, "properties", default=[]) if dm else []
    if props:
        pdf.heading("2. Device Model — EMB3D Properties", 1)
        pdf.table(["Property", "Category", "Feature / Interface", "Present", "Notes"],
                  [[g(p, "property_code"), g(p, "category"), g(p, "feature_or_interface"),
                    "Yes" if g(p, "present", default=True) else "No", g(p, "notes")] for p in props],
                  weights=[1.4, 1.6, 2.2, 0.8, 3])

    tt = g(rep, "threat_table_emb3d", default=[])
    if tt:
        pdf.heading("3. EMB3D Threat -> Mitigation Table", 1)
        pdf.table(["Element", "TID", "Threat", "Lik.", "Imp.", "Mitigations", "Summary"],
                  [[g(t, "emb3d_element"), g(t, "threat_id"), g(t, "threat_name"), g(t, "likelihood"),
                    g(t, "impact"), ", ".join(g(t, "mitigation_ids", default=[])), g(t, "mitigation_summary")] for t in tt],
                  weights=[1.8, 1.0, 2.0, 0.7, 0.7, 1.6, 2.6])

    at = g(rep, "attack_ics_table", default=[])
    if at:
        pdf.heading("4. MITRE ATT&CK for ICS", 1)
        pdf.table(["Tactic", "Technique ID", "Technique", "Applicability", "Related EMB3D"],
                  [[g(a, "tactic"), g(a, "technique_id"), g(a, "technique_name"), g(a, "applicability"),
                    ", ".join(g(a, "related_threat_ids", default=[]))] for a in at],
                  weights=[1.6, 1.1, 1.8, 3.0, 1.4])

    af = g(rep, "attify_surface", default=[])
    if af:
        pdf.heading("5. Attify IoT Reverse-Engineering / Attack Surface", 1)
        pdf.table(["Domain", "Vector", "Technique", "Finding / Hypothesis", "Related EMB3D"],
                  [[g(x, "domain"), g(x, "vector"), g(x, "technique"), g(x, "finding_or_hypothesis"),
                    ", ".join(g(x, "related_threat_ids", default=[]))] for x in af],
                  weights=[1.7, 1.5, 1.8, 3.0, 1.3])

    iec = g(rep, "iec62443", default={})
    if iec:
        pdf.heading("6. ISA/IEC 62443 Requirements Mapping", 1)
        p42 = g(iec, "part_4_2_component", default=[])
        if p42:
            pdf.heading("6.1 62443-4-2 Component Requirements", 3)
            pdf.table(["Req ID", "Name", "Design Mitigation", "Addresses"],
                      [[g(r, "req_id"), g(r, "name"), g(r, "design_mitigation"), ", ".join(g(r, "addresses_threats", default=[]))] for r in p42],
                      weights=[1.4, 2.0, 3.2, 1.4])
        p33 = g(iec, "part_3_3_system", default=[])
        if p33:
            pdf.heading("6.2 62443-3-3 System Requirements", 3)
            pdf.table(["Req ID", "Name", "System Control"],
                      [[g(r, "req_id"), g(r, "name"), g(r, "system_control")] for r in p33], weights=[1.2, 2, 4])
        p41 = g(iec, "part_4_1_lifecycle", default=[])
        if p41:
            pdf.heading("6.3 62443-4-1 Secure Development Lifecycle", 3)
            pdf.table(["Practice", "Name", "Recommendation"],
                      [[g(r, "practice"), g(r, "name"), g(r, "recommendation")] for r in p41], weights=[1, 2, 4])
        p21 = g(iec, "part_2_1_program", default=[])
        if p21:
            pdf.heading("6.4 62443-2-1 Asset-Owner Program", 3)
            pdf.table(["Element", "Recommendation"], [[g(r, "element"), g(r, "recommendation")] for r in p21], weights=[1.6, 4])

    isa = g(rep, "isa84_safety", default={})
    if isa:
        pdf.heading("7. ISA-TR84.00.09 Safety / Hazard / Consequence", 1)
        pdf.paragraph(f"Applicable: {'Yes' if g(isa,'applicable',default=False) else 'No'}   ·   "
                      f"SIS/SIF: {g(isa,'sis_sif')}", size=9)
        hs = g(isa, "hazard_scenarios", default=[])
        if hs:
            pdf.table(["Scenario", "Attack Path", "Consequence", "Severity", "Defeats IPLs", "Countermeasures"],
                      [[g(h, "scenario"), g(h, "attack_path"), g(h, "consequence"), g(h, "severity"),
                        "Yes" if g(h, "defeats_protection_layers", default=False) else "No", g(h, "countermeasures")] for h in hs],
                      weights=[2.4, 2.0, 2.0, 1.0, 0.9, 2.4])

    rr = g(rep, "risk_register", default=[])
    if rr:
        pdf.heading("8. Risk Register", 1)
        pdf.table(["ID", "Risk", "Threats", "ATT&CK", "L", "I", "Level", "Recommendation", "Requirements"],
                  [[g(r, "id"), g(r, "risk"), ", ".join(g(r, "threat_ids", default=[])), ", ".join(g(r, "attack_ids", default=[])),
                    g(r, "likelihood")[:1], g(r, "impact")[:1], g(r, "risk_level"), g(r, "recommendation"),
                    ", ".join(g(r, "mapped_requirements", default=[]))] for r in rr],
                  weights=[0.5, 2.4, 1.3, 1.1, 0.4, 0.4, 0.9, 2.8, 1.6])

    # Diagrams — each isolated so a malformed shape can't break the PDF
    def _diagram(title, layout, data):
        if not data:
            return
        pdf.heading(title, 1)
        try:
            W, H, pr = layout(data)
            pdf.place_diagram(W, H, pr)
        except Exception:  # noqa: BLE001
            pdf.paragraph("(Diagram could not be rendered for this report.)", size=9, color=pdf.C_MUT)

    _diagram("9. Threat Model Diagram", layout_threat, g(rep, "threat_diagram", default=None))
    _diagram("10. ATT&CK for ICS Kill Chain", layout_killchain, g(rep, "kill_chain", default=None))
    _diagram("11. SANS ICS Cyber Kill Chain", layout_sans, g(rep, "sans_kill_chain", default=None))
    _diagram("12. Attack Mind Map", layout_mindmap, g(rep, "attack_mindmap", default=None))

    if g(rep, "assumptions", default=[]):
        pdf.heading("Assumptions", 2)
        for a in g(rep, "assumptions", default=[]):
            pdf.bullet(a)
    if g(rep, "references", default=[]):
        pdf.heading("References", 2)
        for r in g(rep, "references", default=[]):
            pdf.bullet(r)
    return pdf.save_bytes()


# =============================================================================
#  SECTION 7 — SQLite persistence
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
        conn.execute("""CREATE TABLE IF NOT EXISTS threat_model (
            id TEXT PRIMARY KEY, title TEXT, target TEXT, scope TEXT, provider TEXT, model TEXT,
            report_json TEXT, report_md TEXT, mermaid TEXT, created_at TEXT)""")
        conn.commit()
        conn.close()


def db_save(target, scope, provider, model, rep, md):
    tm_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _db_lock:
        conn = db_conn()
        conn.execute("INSERT INTO threat_model VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (tm_id, rep.get("target") or target, target, scope or "", provider, model,
                      json.dumps(rep), md, rep.get("diagram_mermaid", ""), now))
        conn.commit()
        conn.close()
    return tm_id


def db_update(tm_id, rep, md):
    with _db_lock:
        conn = db_conn()
        conn.execute("UPDATE threat_model SET report_json=?, report_md=?, mermaid=? WHERE id=?",
                     (json.dumps(rep), md, rep.get("diagram_mermaid", ""), tm_id))
        conn.commit()
        conn.close()


def db_list():
    conn = db_conn()
    rows = conn.execute("SELECT id,title,target,provider,model,created_at FROM threat_model ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def db_get(tm_id):
    conn = db_conn()
    row = conn.execute("SELECT * FROM threat_model WHERE id=?", (tm_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["report"] = json.loads(d.get("report_json") or "{}")
    return d


def db_delete(tm_id):
    with _db_lock:
        conn = db_conn()
        conn.execute("DELETE FROM threat_model WHERE id=?", (tm_id,))
        conn.commit()
        conn.close()


# =============================================================================
#  SECTION 8 — HTTP server (stdlib http.server)
# =============================================================================

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run_analysis(payload, progress=None):
    """Shared analysis flow used by both the streaming and non-streaming endpoints.
    Distills every artifact (nothing dropped), builds the prompt, generates the
    complete report with completeness-retry, saves it, and returns the response dict.
    `progress(msg)` is called with human-readable status lines during distillation."""
    progress = progress or (lambda _m: None)
    target = (payload.get("target") or "").strip()
    if not target:
        raise ValueError("target required")
    scope = payload.get("scope") or ""
    arts = payload.get("artifacts") or []
    provider = payload["provider"]
    model = payload["model"]
    api_key = payload.get("api_key")
    base_url = payload.get("base_url")
    prov = PROVIDERS.get(provider, {})
    vision_ok = bool(prov.get("vision"))

    # Distill large documents so the ENTIRE content is analysed (nothing truncated away).
    artifact_ctx, images, notes = build_analysis_context(
        arts, provider, model, api_key, base_url, vision_ok, progress)
    if not vision_ok:
        img_names = [a["filename"] for a in arts if a.get("is_image")]
        if img_names:
            artifact_ctx += ("\n\n[Note: image artifacts (" + ", ".join(img_names) +
                             ") were provided but the selected model is not vision-capable. "
                             "Reason about them from any accompanying text, or the user should pick a vision model.]")
    # Drop any image a vision model can't process (CMYK/corrupt/oversized/unsupported)
    # BEFORE calling the API, so one bad picture never fails the whole analysis.
    images, dropped = sanitize_images(images)
    if dropped:
        progress(f"Skipped {dropped} image(s) that a vision model can't read (CMYK, corrupt, or oversized).")
    for nt in notes:
        progress(nt)

    progress("Analyzing against all frameworks and building the report + diagrams…")
    user = build_user_prompt(target, scope, artifact_ctx, payload.get("online_notes", ""))
    rep = generate_report(provider, model, SYSTEM_PROMPT, user, images,
                          api_key, base_url, payload.get("max_tokens", 20000))
    built = ensure_diagrams(rep)  # never persist a report with blank diagrams
    if built:
        progress("Diagrams built from the report content: " + ", ".join(built))
    meta = {"target": target, "provider": provider, "model": model, "generated_at": _now()}
    md = report_to_markdown(rep, meta)
    tm_id = db_save(target, scope, provider, model, rep, md)
    return {"id": tm_id, "report": rep, "markdown": md, "report_html": md_to_html(md),
            "risk_counts": risk_counts(rep), "svgs": report_svgs(rep), "notes": notes}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # quiet

    # ---- helpers ----
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, status=200, ctype="text/html; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse_start(self):
        # Close the connection when the stream ends so the client gets a clean EOF
        # (no Content-Length is sent for an event stream).
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

    def _sse(self, event, data):
        try:
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            raise

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
            return self._json({"providers": provider_catalog()})
        if path == "/api/frameworks/stats":
            return self._json(framework_stats())
        if path.startswith("/api/frameworks/"):
            return self._framework(path.rsplit("/", 1)[-1])
        if path == "/api/health":
            return self._json({"status": "ok", "version": APP_VERSION, "frameworks": framework_stats()})
        if path == "/api/models":
            return self._json({"models": db_list()})
        if path.startswith("/api/models/") and path.endswith("/pdf"):
            tm_id = path[len("/api/models/"):-len("/pdf")]
            return self._model_pdf(tm_id)
        if path.startswith("/api/models/"):
            tm_id = path.rsplit("/", 1)[-1]
            m = db_get(tm_id)
            if not m:
                return self._json({"error": "not found"}, 404)
            try:
                m["svgs"] = report_svgs(m.get("report") or {})
            except Exception:
                m["svgs"] = {}
            m["report_html"] = md_to_html(m.get("report_md") or "")
            return self._json(m)
        return self._json({"error": "not found"}, 404)

    def _model_pdf(self, tm_id):
        m = db_get(tm_id)
        if not m:
            return self._json({"error": "not found"}, 404)
        rep = m.get("report") or {}
        meta = {"target": m.get("target"), "provider": m.get("provider"),
                "model": m.get("model"), "generated_at": m.get("created_at")}
        try:
            pdf = report_to_pdf(rep, meta)
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"PDF generation failed: {e}"}, 500)
        fname = (m.get("title") or "threat_model").replace(" ", "_").replace("/", "-")[:60] + ".pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(pdf)))
        self.end_headers()
        self.wfile.write(pdf)

    def _framework(self, name):
        data = {
            "emb3d_properties": _idx_props, "emb3d_threats": _idx_threats, "emb3d_mitigations": _idx_mits,
            "attack_ics_tactics": _idx_tactics, "attack_ics_techniques": _idx_techniques,
            "attack_ics_mitigations": _idx_attack_mits,
        }
        if name in data:
            return self._json({"data": data[name]()})
        if name == "iec62443":
            return self._json({"data": {
                "part_3_3": [{"id": i, "fr": fr, "name": n, "summary": s} for i, fr, n, s in IEC62443["part_3_3"]],
                "part_4_2": [{"id": i, "fr": fr, "name": n, "summary": s} for i, fr, n, s in IEC62443["part_4_2"]],
                "part_4_1": [{"id": i, "name": n, "summary": s} for i, n, s in IEC62443["part_4_1"]],
                "part_2_1": [{"id": i, "name": n, "summary": s} for i, n, s in IEC62443["part_2_1"]],
            }})
        if name == "isa84":
            return self._json({"data": {
                "concepts": [{"id": i, "term": t, "description": d} for i, t, d in ISA84["concepts"]],
                "impact_scale": [{"level": lv, "safety": s, "environment": e, "operational": o} for lv, s, e, o in ISA84["impact_scale"]],
                "hazard_workflow": ISA84["hazard_workflow"],
            }})
        if name == "attify":
            return self._json({"data": [{"domain": d, "node": n, "techniques": t, "maps_emb3d": e} for d, n, t, e in ATTIFY_MINDMAP]})
        return self._json({"error": "unknown framework"}, 404)

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            if path == "/api/validate_key":
                pl = self._read_json()
                return self._json(validate_key(pl.get("provider"), pl.get("api_key"), pl.get("base_url")))
            if path == "/api/artifacts/parse":
                return self._parse_artifacts()
            if path == "/api/generate":
                return self._generate()
            if path == "/api/refine":
                return self._refine()
            if path == "/api/generate/stream":
                return self._generate_stream()
            if path == "/api/chat/stream":
                return self._chat_stream()
            if path.startswith("/api/models/") and path.endswith("/rebuild_diagrams"):
                return self._rebuild_diagrams(path[len("/api/models/"):-len("/rebuild_diagrams")])
            return self._json({"error": "not found"}, 404)
        except Exception as e:  # noqa: BLE001
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/api/models/"):
            db_delete(path.rsplit("/", 1)[-1])
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)

    def _parse_artifacts(self):
        payload = self._read_json()
        out = []
        for f in payload.get("files", []):
            out.append(ingest_artifact(f.get("filename", "file"), f.get("b64", "")))
        return self._json({"artifacts": out})

    def _generate(self):
        p = self._read_json()
        try:
            out = run_analysis(p)
        except ValueError as e:
            msg = str(e)
            if msg == "target required":
                return self._json({"error": msg}, 400)
            return self._json({"error": f"Model did not return valid JSON: {e}"}, 422)
        except ProviderError as e:
            return self._json({"error": str(e)}, 502)
        return self._json(out)

    def _refine(self):
        p = self._read_json()
        tm_id = p.get("id")
        row = db_get(tm_id) if tm_id else None
        if not row:
            return self._json({"error": "report not found"}, 404)
        instruction = (p.get("instruction") or "").strip()
        if not instruction:
            return self._json({"error": "instruction required"}, 400)
        current = row.get("report") or {}
        # If the user attached new artifacts with the refinement, distill them too so
        # nothing they upload mid-conversation gets dropped.
        arts = p.get("artifacts") or []
        images = None
        extra_ctx = ""
        if arts:
            prov = PROVIDERS.get(p["provider"], {})
            extra_ctx, imgs, _notes = build_analysis_context(
                arts, p["provider"], p["model"], p.get("api_key"), p.get("base_url"),
                bool(prov.get("vision")), lambda _m: None)
            imgs, _dropped = sanitize_images(imgs)
            images = imgs or None
        user = build_refine_prompt(current, instruction)
        if extra_ctx:
            user += "\n\n# NEWLY PROVIDED ARTIFACTS (extracted — incorporate these)\n" + extra_ctx
        try:
            rep = generate_report(p["provider"], p["model"], REFINE_SYSTEM_PROMPT, user, images,
                                  p.get("api_key"), p.get("base_url"), p.get("max_tokens", 20000))
        except ProviderError as e:
            return self._json({"error": str(e)}, 502)
        except ValueError as e:
            return self._json({"error": f"Model did not return valid JSON: {e}"}, 422)
        ensure_diagrams(rep)  # never persist a report with blank diagrams
        meta = {"target": rep.get("target") or row.get("target"), "provider": p["provider"],
                "model": p["model"], "generated_at": _now()}
        md = report_to_markdown(rep, meta)
        db_update(tm_id, rep, md)
        return self._json({"id": tm_id, "report": rep, "markdown": md, "report_html": md_to_html(md),
                           "risk_counts": risk_counts(rep), "svgs": report_svgs(rep)})

    def _rebuild_diagrams(self, tm_id):
        """Rebuild the three diagrams locally from the saved report content — no
        model call. Instant, offline, and it never touches the narrative/tables."""
        row = db_get(tm_id)
        if not row:
            return self._json({"error": "report not found"}, 404)
        rep = row.get("report") or {}
        # Force a rebuild of ALL three from report content, then persist.
        rep["threat_diagram"] = _syn_threat(rep)
        rep["kill_chain"] = _syn_killchain(rep)
        rep["attack_mindmap"] = _syn_mindmap(rep)
        rep["sans_kill_chain"] = _syn_sans(rep)
        meta = {"target": rep.get("target") or row.get("target"), "provider": row.get("provider"),
                "model": row.get("model"), "generated_at": row.get("created_at")}
        md = report_to_markdown(rep, meta)
        db_update(tm_id, rep, md)
        return self._json({"id": tm_id, "svgs": report_svgs(rep),
                           "risk_counts": risk_counts(rep)})

    def _generate_stream(self):
        p = self._read_json()
        if not (p.get("target") or "").strip():
            return self._json({"error": "target required"}, 400)
        self._sse_start()
        # Progress callback streams distillation/analysis status to the browser so the
        # user sees each large document being read section-by-section (nothing dropped).
        def progress(msg):
            self._sse("progress", {"message": msg})
        try:
            out = run_analysis(p, progress)
        except ProviderError as e:
            return self._sse("error", {"message": str(e)})
        except ValueError as e:
            return self._sse("error", {"message": f"Model did not return valid JSON: {e}"})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001 — never leave the client with an empty stream
            return self._sse("error", {"message": f"Analysis error: {e}"})
        try:
            self._sse("done", out)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _chat_stream(self):
        p = self._read_json()
        convo = ""
        for m in (p.get("history") or []):
            convo += f"\n{m.get('role','user').upper()}: {m.get('content','')}"
        user = ""
        if p.get("context"):
            user += f"CURRENT THREAT MODEL CONTEXT:\n{p['context']}\n\n"
        if convo:
            user += f"CONVERSATION SO FAR:{convo}\n\n"
        user += f"USER: {p.get('message','')}\n\nReference context:\n{build_reference_context()}"
        self._sse_start()
        try:
            for delta in stream_model(p["provider"], p["model"], CHAT_SYSTEM_PROMPT, user, None,
                                      p.get("api_key"), p.get("base_url"), 4000, None):
                self._sse("token", {"t": delta})
            self._sse("done", {})
        except ProviderError as e:
            self._sse("error", {"message": str(e)})
        except (BrokenPipeError, ConnectionResetError):
            return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# =============================================================================
#  SECTION 9 — embedded web UI (single-page app; CSS + JS inline)
# =============================================================================
INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ICS/OT/IoT Threat Modeler</title>
<style>
:root{--bg:#0e1420;--panel:#151d2e;--panel2:#1b2438;--line:#28324a;--ink:#e7edf6;--muted:#93a1b8;--accent:#3d9be0;--accent2:#0b3d63;--ok:#3ecf8e;--crit:#ff5b6e;--high:#ff8a5b;--med:#f4b942;--low:#5bb7ff}
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
.badge{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:20px;padding:5px 12px;font-size:11px}
main{max-width:1060px;margin:0 auto;padding:26px 20px 60px}
/* wizard */
.wizard{max-width:720px;margin:20px auto}
.steps{display:flex;gap:8px;justify-content:center;margin-bottom:22px}
.stepdot{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12.5px;font-weight:600}
.stepdot .num{width:26px;height:26px;border-radius:50%;border:2px solid var(--line);display:flex;align-items:center;justify-content:center;font-size:12px}
.stepdot.active{color:var(--ink)}.stepdot.active .num{border-color:var(--accent);background:var(--accent);color:#fff}
.stepdot.done .num{border-color:var(--ok);color:var(--ok)}
.stepsep{width:34px;height:2px;background:var(--line);align-self:center}
.wstep{display:none;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:30px}
.wstep.active{display:block;animation:fade .2s ease}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1}}
.wstep h2{font-size:22px;margin-bottom:6px}.wstep .sub{color:var(--muted);margin-bottom:18px}
.wstep .opt{color:var(--muted);font-size:15px;font-weight:400}
.field-label{display:block;font-size:12px;color:var(--muted);margin:16px 0 6px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.wnav{display:flex;justify-content:space-between;align-items:center;margin-top:22px}
.drop{border:2px dashed var(--line);border-radius:12px;padding:34px;text-align:center;color:var(--muted);cursor:pointer;transition:.15s}
.drop.hover{border-color:var(--accent);color:var(--accent);background:rgba(61,155,224,.06)}
.artifacts{list-style:none;margin:14px 0 0;padding:0}
.artifacts li{display:flex;align-items:center;gap:10px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 12px;margin-bottom:7px;font-size:13px;flex-wrap:wrap}
.artifacts .k{color:var(--accent);font-size:10px;text-transform:uppercase;border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.artifacts .rm{color:var(--crit);cursor:pointer;background:none;border:none;font-size:17px;margin-left:auto}
.artifacts .warn{color:var(--med);font-size:11.5px;flex-basis:100%}
.spinner{width:34px;height:34px;border:4px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:spin 1s linear infinite;margin:12px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.stream{background:#0a0f18;border:1px solid var(--line);border-radius:10px;padding:14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;white-space:pre-wrap;color:#9fe0c0;max-height:44vh;overflow:auto;margin-top:14px}
.status{font-size:13px;color:var(--muted);margin-top:12px;text-align:center;min-height:18px}.status.err{color:var(--crit)}.status.ok{color:var(--ok)}
/* results */
.results-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.results-head h2{font-size:22px}.results-head .meta{color:var(--muted);font-size:12.5px;margin-top:4px}
.racts{display:flex;gap:8px;flex-wrap:wrap}
.riskbar{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
.riskchip{flex:1;min-width:110px;border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center;background:var(--panel)}
.riskchip .n{font-size:26px;font-weight:800;display:block}.riskchip .l{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.5px}
.riskchip.Critical .n{color:var(--crit)}.riskchip.High .n{color:var(--high)}.riskchip.Medium .n{color:var(--med)}.riskchip.Low .n{color:var(--low)}
.report{max-width:100%}
.report h1{font-size:23px;margin:6px 0 10px;color:#fff}.report h2{font-size:18px;margin:24px 0 8px;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:5px}
.report h3{font-size:14.5px;margin:16px 0 6px;color:#cfe0f2}.report p{color:#d2dcea}
.report blockquote{background:var(--panel);border-left:3px solid var(--accent);margin:12px 0;padding:8px 14px;color:var(--muted);border-radius:0 8px 8px 0}
.report code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12.5px}
.report table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12.5px}
.report th,.report td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
.report th{background:var(--accent2);color:#fff}.report tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.diagrams h2{font-size:18px;margin:26px 0 8px;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:5px}
.dg{background:#fff;border-radius:12px;padding:14px;overflow:auto}
.askbox{margin-top:30px;border-top:1px solid var(--line);padding-top:18px}
.askbox h3{margin-bottom:10px}
.chatlog{display:flex;flex-direction:column;gap:10px;margin-bottom:12px}
.msg{padding:10px 14px;border-radius:10px;max-width:88%;white-space:pre-wrap}.msg.user{align-self:flex-end;background:var(--accent2);color:#eaf3fb}
.msg.assistant{align-self:flex-start;background:var(--panel);border:1px solid var(--line)}
.msg.assistant table{border-collapse:collapse;margin:6px 0}.msg.assistant th,.msg.assistant td{border:1px solid var(--line);padding:4px 7px}
.chat-input{display:flex;gap:8px}.chat-input textarea{flex:1}.chat-input button{width:auto;padding:0 22px}
/* saved + modal */
.savedpanel{position:fixed;top:0;right:0;height:100vh;width:420px;max-width:92vw;background:var(--panel);border-left:1px solid var(--line);z-index:40;padding:20px;overflow:auto;box-shadow:-8px 0 30px rgba(0,0,0,.4)}
.savedpanel h3{margin-bottom:12px;display:flex;justify-content:space-between}
.saved{list-style:none;margin:0;padding:0}
.saved li{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 13px;margin-bottom:8px}
.saved b{font-size:13.5px}.saved .meta{color:var(--muted);font-size:11.5px;margin:3px 0 8px}.saved .acts{display:flex;gap:6px}
.saved .acts button{padding:6px 10px;font-size:12px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:50}
.modal-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px;width:480px;max-width:92vw;max-height:90vh;overflow:auto}
.modal-card h3{margin-bottom:6px}.modal-card .sub{color:var(--muted);font-size:12.5px;margin-bottom:12px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}
.mrow{margin:10px 0}.mrow label{font-size:12px;color:var(--muted);display:block;margin-bottom:5px;font-weight:600}
</style></head><body>
<header class="topbar">
 <div class="brand"><span class="logo">◈</span><div><h1>ICS / OT / IoT Threat Modeler</h1>
 <p class="tag">EMB3D · ATT&amp;CK for ICS · IEC 62443 · ISA-TR84.00.09 · Attify IoT</p></div></div>
 <div class="top-right"><span id="fw-badge" class="badge">frameworks…</span>
  <button id="savedBtn" class="ghost">Saved</button><button id="settingsBtn" class="ghost">⚙ AI Settings</button></div>
</header>
<main>
 <!-- WIZARD -->
 <div id="wizard" class="wizard">
  <div class="steps">
   <div class="stepdot active" data-dot="1"><span class="num">1</span> AI Model</div>
   <div class="stepsep"></div>
   <div class="stepdot" data-dot="2"><span class="num">2</span> Describe</div>
   <div class="stepsep"></div>
   <div class="stepdot" data-dot="3"><span class="num">3</span> Artifacts</div>
   <div class="stepsep"></div>
   <div class="stepdot" data-dot="4"><span class="num">4</span> Analyze</div>
  </div>
  <div class="wstep active" id="w1">
   <h2>Choose your AI model &amp; enter your key</h2>
   <p class="sub">Pick which AI performs the analysis and paste an API key for that provider (stored only in this browser). Or point at a local model (Ollama / LM Studio) — no key needed.</p>
   <label class="field-label">AI provider</label><select id="provider"></select>
   <label class="field-label">Model</label><select id="model"></select>
   <input id="customModel" style="margin-top:6px" placeholder="…or type a custom model id"/>
   <div id="localRow" style="display:none"><label class="field-label">Base URL (local / OpenAI-compatible)</label><input id="baseUrl" placeholder="http://localhost:11434/v1"/></div>
   <label class="field-label">API key <span id="keyState" class="opt"></span></label>
   <input id="apiKey" type="password" placeholder="paste your API key"/>
   <p class="sub" id="providerNotes" style="margin-top:8px"></p>
   <div id="keyMsg" class="status"></div>
   <div class="wnav"><button class="ghost" id="clearKey">Clear saved key</button><button class="primary" id="aiNext">Verify &amp; continue →</button></div>
  </div>
  <div class="wstep" id="w2">
   <h2>What are we threat modeling?</h2>
   <p class="sub">Name the component, device, or system under evaluation. Include the model number and notable interfaces if you know them.</p>
   <textarea id="target" rows="3" placeholder="e.g. Siemens S7-1500 PLC (CPU 1516-3 PN/DP), PROFINET, integrated web server"></textarea>
   <label class="field-label">Scope / context (optional)</label>
   <textarea id="scope" rows="2" placeholder="Deployment, safety relevance (does it run a Safety Instrumented Function?), boundaries, assumptions…"></textarea>
   <div class="wnav"><button class="ghost" data-back="1">← Back</button><button class="primary" data-next="3" id="descNext">Continue →</button></div>
  </div>
  <div class="wstep" id="w3">
   <h2>Add artifacts <span class="opt">(optional, recommended)</span></h2>
   <p class="sub">Upload datasheets, product manuals, functional design specs, P&amp;IDs, PFDs, SysML/UML. The AI reads them to model the <i>real</i> device — its interfaces, protocols, firmware, and safety functions.</p>
   <div id="drop" class="drop">Drag &amp; drop files here, or click to browse</div>
   <input id="fileInput" type="file" multiple class="hidden" accept=".pdf,.docx,.txt,.md,.csv,.xml,.json,.uml,.sysml,.puml,.xmi,.png,.jpg,.jpeg,.gif,.webp,.svg"/>
   <ul id="artifactList" class="artifacts"></ul>
   <div class="wnav"><button class="ghost" data-back="2">← Back</button><button class="primary" id="analyzeBtn">⚡ Analyze</button></div>
  </div>
  <div class="wstep" id="w4">
   <h2>Analyzing…</h2>
   <p class="sub">The AI is modeling <b id="a-target"></b> against every framework and your uploaded artifacts, then building the report, mapping tables, and diagrams.</p>
   <div class="spinner"></div>
   <div id="status" class="status">Contacting the model…</div>
   <div id="streamView" class="stream hidden"></div>
  </div>
 </div>

 <!-- RESULTS -->
 <div id="results" class="hidden">
  <div class="results-head">
   <div><h2 id="r-title">Threat Model</h2><div class="meta" id="r-meta"></div></div>
   <div class="racts">
    <button id="pdfBtn" class="primary">⬇ Download full PDF report</button>
    <button id="rebuildBtn" class="ghost" title="Rebuild the three diagrams from this report — instant, no AI call">⟳ Rebuild diagrams</button>
    <button id="newBtn" class="ghost">+ Start new threat model</button>
   </div>
  </div>
  <div id="riskbar" class="riskbar"></div>
  <article id="report" class="report"></article>
  <section class="diagrams">
   <h2>Threat Model Diagram</h2><div id="dg-threat" class="dg"></div>
   <h2>ATT&CK for ICS Kill Chain</h2><div id="dg-kill" class="dg"></div>
   <h2>SANS ICS Cyber Kill Chain</h2><div id="dg-sans" class="dg"></div>
   <h2>Attack Mind Map</h2><div id="dg-mind" class="dg"></div>
  </section>
  <section class="askbox">
   <h3>Refine this analysis</h3>
   <p class="muted" style="margin:-4px 0 10px;font-size:13px">Ask for changes and the report, tables, diagrams, and PDF update in place. e.g. "add more EMB3D threats", "remove the firewall/zones content", "expand the 62443-4-2 mapping", "focus on the OS web client".</p>
   <div id="chatLog" class="chatlog"></div>
   <div class="chat-input"><textarea id="chatMsg" rows="2" placeholder="Describe the change to make… (Ctrl/Cmd+Enter)"></textarea><button id="chatSend" class="primary">Update report</button></div>
  </section>
 </div>
</main>

<div id="savedPanel" class="savedpanel hidden">
 <h3>Saved reports <button class="ghost" id="closeSaved" style="padding:4px 10px">×</button></h3>
 <div style="display:flex;gap:8px;margin-bottom:10px"><button id="cmpBtn" class="ghost" style="padding:6px 10px">Compare selected</button><span class="muted" style="font-size:11.5px;align-self:center">tick 2+ to compare</span></div>
 <ul id="savedList" class="saved"></ul></div>

<div id="compareView" class="hidden"><div class="results-head"><div><h2>Compare components</h2><div class="meta">Side-by-side risk posture across selected threat models</div></div><button id="cmpClose" class="ghost">Close</button></div><div id="cmpBody" class="report"></div></div>

<div id="newModal" class="modal hidden"><div class="modal-card">
 <h3>Start a new threat model</h3>
 <p class="sub">You're set up with <b id="nm-model"></b>.</p>
 <p class="muted">Keep using this model for the next component, or switch to a different one? Your current report stays saved (find it under <b>Saved</b>).</p>
 <div class="modal-actions">
   <button class="ghost" id="nmCancel">Cancel</button>
   <button class="ghost" id="nmChange">Change model</button>
   <button class="primary" id="nmKeep">Keep &amp; describe →</button>
 </div>
</div></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js"></script>
<script>
"use strict";
const $=s=>document.querySelector(s),$$=s=>Array.from(document.querySelectorAll(s));
const LS_KEYS="itm_keys",LS_BASE="itm_bases",LS_SEL="itm_sel";
let PROVIDERS=[],artifacts=[],currentReport=null,chatHistory=[];
const md=t=>(typeof marked!=="undefined")?marked.parse(t||""):"<pre>"+esc(t||"")+"</pre>";
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function getKeys(){try{return JSON.parse(localStorage.getItem(LS_KEYS)||"{}")}catch{return{}}}
function setKeys(k){localStorage.setItem(LS_KEYS,JSON.stringify(k))}
function getBases(){try{return JSON.parse(localStorage.getItem(LS_BASE)||"{}")}catch{return{}}}
function setBases(b){localStorage.setItem(LS_BASE,JSON.stringify(b))}
function getSel(){try{return JSON.parse(localStorage.getItem(LS_SEL)||"{}")}catch{return{}}}
function setSel(s){localStorage.setItem(LS_SEL,JSON.stringify(s))}

async function init(){await loadProviders();await loadStats();wire();}
async function loadProviders(){const r=await fetch("/api/providers").then(x=>x.json());PROVIDERS=r.providers;
 const sel=getSel();$("#provider").innerHTML=PROVIDERS.map(p=>`<option value="${p.id}">${p.label}</option>`).join("");
 if(sel.provider)$("#provider").value=sel.provider;onProv();if(sel.model)$("#model").value=sel.model;}
async function loadStats(){try{const s=await fetch("/api/frameworks/stats").then(x=>x.json());
 const tot=Object.values(s).reduce((a,b)=>a+b,0);$("#fw-badge").textContent=tot+" framework records";}catch{}}
function curP(){return PROVIDERS.find(p=>p.id===$("#provider").value)}
function onProv(){const p=curP();if(!p)return;$("#model").innerHTML=p.models.map(m=>`<option value="${m.id}">${m.label}</option>`).join("");
 $("#providerNotes").textContent=p.notes||"";$("#localRow").style.display=(p.id==="local"||p.base_url.includes("localhost"))?"block":"none";
 const bs=getBases();$("#baseUrl").value=bs[p.id]||p.base_url||"";const ks=getKeys();$("#apiKey").value=ks[p.id]||"";
 $("#keyState").textContent=p.server_key?"(server key available)":"";}
function saveAiStep(){const p=curP();if(!p)return false;const ks=getKeys(),bs=getBases();
 if($("#apiKey").value.trim())ks[p.id]=$("#apiKey").value.trim();else delete ks[p.id];
 if($("#baseUrl").value.trim())bs[p.id]=$("#baseUrl").value.trim();
 setKeys(ks);setBases(bs);setSel({provider:p.id,model:$("#customModel").value.trim()||$("#model").value});return true;}
function aiReady(){const p=curP();if(!p)return false;const ks=getKeys();
 const hasKey=!!($("#apiKey").value.trim()||ks[p.id]);return p.id==="local"||p.server_key||hasKey;}
function wire(){
 $("#provider").addEventListener("change",()=>{onProv();keyMsg("");});
 $("#apiKey").addEventListener("input",()=>keyMsg(""));
 $("#aiNext").addEventListener("click",verifyAndContinue);
 $("#clearKey").addEventListener("click",clearSavedKey);
 $$("[data-next]").forEach(b=>b.addEventListener("click",()=>{
   if(b.id==="descNext"&&!$("#target").value.trim()){flash("Enter what you want to threat model.");return;}
   goStep(+b.dataset.next);}));
 $$("[data-back]").forEach(b=>b.addEventListener("click",()=>goStep(+b.dataset.back)));
 const drop=$("#drop"),fi=$("#fileInput");drop.addEventListener("click",()=>fi.click());fi.addEventListener("change",()=>handleFiles(fi.files));
 ["dragover","dragenter"].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add("hover")}));
 ["dragleave","drop"].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove("hover")}));
 drop.addEventListener("drop",ev=>handleFiles(ev.dataTransfer.files));
 $("#analyzeBtn").addEventListener("click",analyze);
 $("#pdfBtn").addEventListener("click",()=>{if(currentReport&&currentReport.id)window.open("/api/models/"+currentReport.id+"/pdf","_blank")});
 $("#rebuildBtn").addEventListener("click",()=>rebuildDiagrams(false));
 $("#newBtn").addEventListener("click",startNew);
 $("#nmCancel").addEventListener("click",()=>$("#newModal").classList.add("hidden"));
 $("#nmKeep").addEventListener("click",()=>{$("#newModal").classList.add("hidden");clearInputs();showWizard();goStep(2);});
 $("#nmChange").addEventListener("click",()=>{$("#newModal").classList.add("hidden");clearInputs();showWizard();goStep(1);});
 $("#cmpBtn").addEventListener("click",compareSelected);
 $("#cmpClose").addEventListener("click",()=>{$("#compareView").classList.add("hidden");$("#wizard").classList.remove("hidden");});
 $("#chatSend").addEventListener("click",sendRefine);
 $("#chatMsg").addEventListener("keydown",e=>{if(e.key==="Enter"&&(e.metaKey||e.ctrlKey))sendRefine()});
 $("#settingsBtn").addEventListener("click",gotoAiStep);
 $("#savedBtn").addEventListener("click",openSaved);$("#closeSaved").addEventListener("click",()=>$("#savedPanel").classList.add("hidden"));
}
function gotoAiStep(){$("#results").classList.add("hidden");$("#wizard").classList.remove("hidden");goStep(1);}
function keyMsg(m,ok){const s=$("#keyMsg");s.textContent=m||"";s.className="status "+(m?(ok?"ok":"err"):"");}
async function verifyAndContinue(){const p=curP();if(!p)return;const btn=$("#aiNext");
 const key=$("#apiKey").value.trim();
 btn.disabled=true;const old=btn.textContent;btn.textContent="Checking key…";keyMsg("Verifying your key with "+p.label+"…",true);
 try{
  const r=await fetch("/api/validate_key",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({provider:p.id,api_key:key||null,base_url:$("#baseUrl").value.trim()||null})}).then(x=>x.json());
  if(r.ok){
    // only NOW do we persist the key — a bad key is never stored
    saveAiStep();
    if(r.models&&r.models.length){const cur=$("#customModel").value.trim()||$("#model").value;
      if(cur&&!r.models.includes(cur)&&!r.models.some(m=>cur.indexOf(m)>=0||m.indexOf(cur)>=0)){
        keyMsg("Key works. Note: model '"+cur+"' isn't in your account's list — if analysis fails with a model error, pick another in Step 1.",true);
        setTimeout(()=>goStep(2),1200);return;}}
    keyMsg("Key verified ✓",true);setTimeout(()=>goStep(2),450);
  }else{keyMsg(r.message||"Key could not be verified.");}
 }catch(e){keyMsg("Could not verify key: "+e.message);}
 finally{btn.disabled=false;btn.textContent=old;}}
function clearSavedKey(){const p=curP();if(!p)return;const ks=getKeys();delete ks[p.id];setKeys(ks);
 $("#apiKey").value="";keyMsg("Saved key cleared. Enter a new key and verify.",true);}
function goStep(n){$$(".wstep").forEach(s=>s.classList.remove("active"));$("#w"+n).classList.add("active");
 $$(".stepdot").forEach(d=>{const k=+d.dataset.dot;d.classList.toggle("active",k===n);d.classList.toggle("done",k<n)});}
function flash(m){alert(m);}
function b64(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result.split(",")[1]);r.onerror=rej;r.readAsDataURL(file)})}
async function handleFiles(fl){const files=Array.from(fl);if(!files.length)return;
 const payload={files:[]};for(const f of files)payload.files.push({filename:f.name,b64:await b64(f)});
 try{const r=await fetch("/api/artifacts/parse",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}).then(x=>x.json());
  r.artifacts.forEach(a=>artifacts.push(a));renderArtifacts();}catch(e){alert("Artifact parse failed: "+e)}}
function renderArtifacts(){$("#artifactList").innerHTML=artifacts.map((a,i)=>`<li><span class="k">${a.kind}</span>
 <span>${esc(a.filename)}</span><span class="muted">${a.is_image?"image":((a.text_excerpt||"").length+" chars)")}</span>
 <button class="rm" data-i="${i}">×</button>${(a.warnings&&a.warnings.length)?`<span class="warn">⚠ ${esc(a.warnings.join("; "))}</span>`:""}</li>`).join("");
 $$("#artifactList .rm").forEach(b=>b.addEventListener("click",()=>{artifacts.splice(+b.dataset.i,1);renderArtifacts()}));}
function reqBody(){const p=curP(),custom=$("#customModel").value.trim(),ks=getKeys(),bs=getBases();
 return{provider:p.id,model:custom||$("#model").value,target:$("#target").value.trim(),scope:$("#scope").value.trim(),
  api_key:$("#apiKey").value.trim()||ks[p.id]||null,base_url:$("#baseUrl").value.trim()||bs[p.id]||null,artifacts:artifacts};}
function isKeyError(m){return /401|403|authentication|invalid.*(x-api-key|api key)|unauthor/i.test(m||"");}
function isModelError(m){return /not_found|does not exist|no such model|model.*(not|unavailable)|unknown model|404/i.test(m||"")&&/model/i.test(m||"");}
function keyError(){const p=curP();if(p){const ks=getKeys();delete ks[p.id];setKeys(ks);$("#apiKey").value="";}
 gotoAiStep();keyMsg("That API key was rejected and has been cleared. Paste a valid key and click Verify & continue.");}
function modelError(){gotoAiStep();keyMsg("The selected model isn't available on your account. Pick a different model in Step 1 (or type a valid model id from your provider), then Analyze again.");}
function handleErr(msg){if(isKeyError(msg)){keyError();return true;}if(isModelError(msg)){modelError();return true;}return false;}
async function analyze(){const p=curP();
 if(!p||!aiReady()){gotoAiStep();keyMsg("Enter an API key (Step 1) before analyzing, or choose the Local provider.");return;}
 const b=reqBody();
 setSel({provider:b.provider,model:b.model});
 goStep(4);$("#a-target").textContent=b.target;$("#streamView").classList.add("hidden");
 const nArt=(b.artifacts||[]).length;
 setStatus(nArt?("Reading "+nArt+" artifact"+(nArt>1?"s":"")+" in full — large documents are processed section by section so nothing is dropped…")
               :"Analyzing against all frameworks and building the report + diagrams…");
 let done=false;
 try{const resp=await fetch("/api/generate/stream",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
  if(!resp.ok){const t=await resp.text();if(handleErr(t))return;let m=t;try{m=JSON.parse(t).error||t;}catch{}setStatus("Error: "+m,"err");return;}
  await readSSE(resp,{
    progress:o=>{if(!done)setStatus(o.message||"Working…");},
    done:o=>{done=true;showResults(o);},
    error:o=>{done=true;const m=o.message||"Analysis failed";if(handleErr(m))return;setStatus("Error: "+m,"err");}
  });
  if(!done)setStatus("Analysis ended unexpectedly. Please try again.","err");
 }catch(e){if(handleErr(e.message))return;setStatus("Analysis failed: "+e.message,"err");}}
function setStatus(m,c=""){const s=$("#status");s.textContent=m;s.className="status "+c;}
function showResults(d){currentReport=d;chatHistory=[];
 $("#wizard").classList.add("hidden");$("#results").classList.remove("hidden");
 $("#r-title").textContent=(d.report&&d.report.target)||"Threat Model";
 const p=curP();$("#r-meta").textContent=(p?p.label:"")+" / "+($("#customModel").value.trim()||$("#model").value);
 renderRisk(d.risk_counts);$("#report").innerHTML=d.report_html||md(d.markdown);
 paintDiagrams(d.svgs||{});
 window.scrollTo(0,0);
 // Belt-and-suspenders: if the model omitted any diagram and the server copy
 // somehow lacked it, rebuild locally (instant) so diagrams never show blank.
 const s=d.svgs||{};
 if(currentReport&&currentReport.id&&(!s.threat||!s.killchain||!s.sans||!s.mindmap))rebuildDiagrams(true);}
function paintDiagrams(s){s=s||{};
 $("#dg-threat").innerHTML=s.threat||'<p class="muted">No diagram.</p>';
 $("#dg-kill").innerHTML=s.killchain||'<p class="muted">No kill chain.</p>';
 $("#dg-sans").innerHTML=s.sans||'<p class="muted">No SANS kill chain.</p>';
 $("#dg-mind").innerHTML=s.mindmap||'<p class="muted">No mind map.</p>';}
async function rebuildDiagrams(silent){
 if(!currentReport||!currentReport.id){if(!silent)alert("Generate or open a report first.");return;}
 const btn=$("#rebuildBtn");const old=btn?btn.textContent:"";if(btn){btn.disabled=true;btn.textContent="⟳ Rebuilding…";}
 try{const r=await fetch("/api/models/"+currentReport.id+"/rebuild_diagrams",{method:"POST"});
  const d=await r.json();
  if(r.ok){paintDiagrams(d.svgs||{});if(d.risk_counts)renderRisk(d.risk_counts);
    if(currentReport)currentReport.svgs=d.svgs;
    if(btn){btn.textContent="✓ Diagrams rebuilt";setTimeout(()=>{btn.textContent=old;btn.disabled=false;},2200);}}
  else{if(btn){btn.textContent=old;btn.disabled=false;}if(!silent)alert("Rebuild failed: "+(d.error||"unknown"));}
 }catch(e){if(btn){btn.textContent=old;btn.disabled=false;}if(!silent)alert("Rebuild failed: "+e.message);}}
function renderRisk(c){c=c||{};$("#riskbar").innerHTML=["Critical","High","Medium","Low"].map(k=>`<div class="riskchip ${k}"><span class="n">${c[k]||0}</span><span class="l">${k}</span></div>`).join("");}
function clearInputs(){artifacts=[];renderArtifacts();$("#target").value="";$("#scope").value="";
 currentReport=null;$("#chatLog").innerHTML="";}
function showWizard(){$("#results").classList.add("hidden");$("#compareView").classList.add("hidden");$("#wizard").classList.remove("hidden");}
function startNew(){
 if(aiReady()){$("#nm-model").textContent=(curP()?curP().label:"")+" / "+($("#customModel").value.trim()||$("#model").value);
   $("#newModal").classList.remove("hidden");}
 else{clearInputs();gotoAiStep();}}
async function compareSelected(){
 const ids=$$("#savedList input[type=checkbox]:checked").map(c=>c.dataset.id);
 if(ids.length<2){alert("Tick at least two saved reports to compare.");return;}
 const reps=[];for(const id of ids){try{reps.push(await fetch("/api/models/"+id).then(x=>x.json()));}catch{}}
 renderCompare(reps);$("#savedPanel").classList.add("hidden");$("#wizard").classList.add("hidden");
 $("#results").classList.add("hidden");$("#compareView").classList.remove("hidden");window.scrollTo(0,0);}
function renderCompare(rows){
 const cnt=r=>{const c={Critical:0,High:0,Medium:0,Low:0};((r.report||{}).risk_register||[]).forEach(x=>{if(c[x.risk_level]!==undefined)c[x.risk_level]++});return c;};
 const topRisk=r=>{const rr=((r.report||{}).risk_register||[]);const hit=rr.find(x=>x.risk_level==="Critical")||rr.find(x=>x.risk_level==="High")||rr[0];return hit?(hit.risk||hit.id||""):"";};
 const H=["Component","Critical","High","Medium","Low","EMB3D threats","ATT&CK techniques","62443-4-2 reqs","Top risk"];
 let h="<table><thead><tr>"+H.map(x=>`<th>${esc(x)}</th>`).join("")+"</tr></thead><tbody>";
 rows.forEach(r=>{const c=cnt(r);const rep=r.report||{};
   h+="<tr>"+[esc((rep.target||r.title||"")),c.Critical,c.High,c.Medium,c.Low,
     (rep.threat_table_emb3d||[]).length,(rep.attack_ics_table||[]).length,
     (((rep.iec62443||{}).part_4_2_component)||[]).length,esc(topRisk(r))]
     .map(v=>`<td>${v}</td>`).join("")+"</tr>";});
 h+="</tbody></table>";
 $("#cmpBody").innerHTML=h;}
async function sendRefine(){const msg=$("#chatMsg").value.trim();if(!msg)return;
 if(!currentReport||!currentReport.id){addChat("assistant","Generate a report first, then request changes.");return;}
 const b=reqBody();addChat("user",msg);$("#chatMsg").value="";
 const el=addChat("assistant","Updating the report, diagrams and PDF…");const btn=$("#chatSend");btn.disabled=true;
 try{const resp=await fetch("/api/refine",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({id:currentReport.id,provider:b.provider,model:b.model,instruction:msg,api_key:b.api_key,base_url:b.base_url})});
  const t=await resp.text();
  if(!resp.ok){let m=t;try{m=JSON.parse(t).error||t;}catch{}if(handleErr(m)){return;}el.textContent="Update failed: "+m;return;}
  const d=JSON.parse(t);
  // re-render the report, tables and diagrams in place; PDF (served from the saved report) is now updated too
  const savedId=currentReport.id;showResults(d);currentReport.id=savedId;
  el.textContent="✓ Report, diagrams and PDF updated. Use Download full PDF report for the new version.";
 }catch(e){if(handleErr(e.message))return;el.textContent="Update failed: "+e.message;}
 finally{btn.disabled=false;}}
function addChat(role,text){const d=document.createElement("div");d.className="msg "+role;d.innerHTML=role==="assistant"?md(text||"…"):esc(text);$("#chatLog").appendChild(d);return d;}
async function openSaved(){$("#savedPanel").classList.remove("hidden");
 const r=await fetch("/api/models").then(x=>x.json());
 $("#savedList").innerHTML=r.models.length?r.models.map(m=>`<li><label style="display:flex;gap:8px;align-items:flex-start"><input type="checkbox" data-id="${m.id}" style="width:auto;margin-top:3px"/><span style="flex:1"><b>${esc(m.title)}</b><div class="meta">${esc(m.provider||"")} / ${esc(m.model||"")} · ${m.created_at}</div></span></label>
  <div class="acts"><button class="ghost" data-open="${m.id}">Open</button><button class="primary" data-pdf="${m.id}" style="padding:6px 10px">PDF</button><button class="ghost" data-del="${m.id}">Delete</button></div></li>`).join(""):'<p class="muted">No saved reports yet.</p>';
 $$("#savedList [data-open]").forEach(b=>b.addEventListener("click",()=>loadSaved(b.dataset.open)));
 $$("#savedList [data-pdf]").forEach(b=>b.addEventListener("click",()=>window.open("/api/models/"+b.dataset.pdf+"/pdf","_blank")));
 $$("#savedList [data-del]").forEach(b=>b.addEventListener("click",async()=>{await fetch("/api/models/"+b.dataset.del,{method:"DELETE"});openSaved();}));}
async function loadSaved(id){const m=await fetch("/api/models/"+id).then(x=>x.json());
 $("#savedPanel").classList.add("hidden");
 currentReport={id,report:m.report,markdown:m.report_md,report_html:m.report_html,svgs:m.svgs||{},risk_counts:rc(m.report)};
 showResults(currentReport);$("#r-meta").textContent=(m.provider||"")+" / "+(m.model||"")+" · "+(m.created_at||"");}
function rc(rep){const c={Critical:0,High:0,Medium:0,Low:0};((rep||{}).risk_register||[]).forEach(r=>{if(c[r.risk_level]!==undefined)c[r.risk_level]++});return c;}
async function readSSE(resp,h){const rd=resp.body.getReader(),dec=new TextDecoder();let buf="";
 while(true){const{value,done}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});
  const evs=buf.split("\n\n");buf=evs.pop();
  for(const ev of evs){let name="message",data="";for(const ln of ev.split("\n")){if(ln.startsWith("event:"))name=ln.slice(6).trim();else if(ln.startsWith("data:"))data+=ln.slice(5).trim();}
   if(!data)continue;let o;try{o=JSON.parse(data)}catch{continue}if(h[name])h[name](o);}}}
init();
</script></body></html>'''


# =============================================================================
#  SECTION 10 — entrypoint
# =============================================================================

def main():
    global DB_PATH
    ap = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Examples:\n  python3 ics_threat_modeler.py\n"
                                        "  python3 ics_threat_modeler.py --port 9000 --open\n"
                                        "  ANTHROPIC_API_KEY=sk-... python3 ics_threat_modeler.py")
    ap.add_argument("--host", default=os.environ.get("ITM_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("ITM_PORT", "8000")))
    ap.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path for saved models")
    ap.add_argument("--open", action="store_true", help="Open the UI in a browser on start")
    ap.add_argument("--stats", action="store_true", help="Print embedded framework counts and exit")
    args = ap.parse_args()

    DB_PATH = args.db
    if args.stats:
        for k, v in framework_stats().items():
            print(f"  {k:26} {v}")
        total = sum(framework_stats().values())
        print(f"  {'TOTAL records':26} {total}")
        return

    try:
        db_init()
    except Exception as e:  # noqa: BLE001
        print(f"\n[ERROR] Could not initialize the database at {DB_PATH}:\n  {e}\n"
              f"  Try a writable location, e.g.:  python ics_threat_modeler.py --db threatmodeler.db")
        _pause_if_windowed()
        return

    # Bind the server; if the port is busy, automatically try the next few.
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
        print(f"\n[ERROR] Could not bind to {args.host} on ports {args.port}-{args.port + 20}.\n"
              f"  Another program (or a previous run of this tool) may be using them.\n"
              f"  Close it, or start on a specific free port:  python ics_threat_modeler.py --port 8090")
        _pause_if_windowed()
        return

    url = f"http://{args.host}:{port}"
    print("=" * 66)
    print(f"  {APP_NAME}  v{APP_VERSION}")
    print(f"  Embedded framework records: {sum(framework_stats().values())}")
    print(f"  Serving at:  {url}")
    if port != args.port:
        print(f"  (requested port {args.port} was busy — using {port} instead)")
    print(f"  Saved models DB:  {DB_PATH}")
    print("  Press Ctrl+C to stop.")
    print("=" * 66)
    if args.open:
        threading.Thread(target=lambda: (time.sleep(1), webbrowser.open(url)), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


def _pause_if_windowed():
    """If launched by double-click on Windows, keep the window open so the error is readable."""
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
        print("\nIf this persists, copy the lines above and send them for support.")
        _pause_if_windowed()
        sys.exit(1)