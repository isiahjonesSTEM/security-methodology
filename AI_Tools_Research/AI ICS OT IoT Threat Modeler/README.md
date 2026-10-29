# AI ICS OT IoT Threat Modeler

`ics_threat_modeler.py` is a single-file, open-source, model-agnostic threat modeling tool for industrial control systems (ICS), operational technology (OT) and IoT devices, components, applications and systems. It runs a local web UI, works with any AI provider or a local / air-gapped model, and needs only the Python standard library. It is the successor to the original Agent.ai agent (`IoT_OT_ICS_ThreatModeler`).

## What it does

Describe a target (for example "Siemens S7-1500 PLC"), optionally attach engineering artifacts (P&ID, PFD, datasheets, manuals, functional design specifications, SysML/UML), choose an AI model, and it produces a threat model mapped to:

- **MITRE EMB3D** — device properties (PID), threats (TID) and mitigations (MID)
- **MITRE ATT&CK for ICS** — tactics, techniques (T0xxx) and mitigations (M0xxx)
- **ISA/IEC 62443** — 3-3 system, 4-2 component, 4-1 lifecycle and 2-1 program requirements
- **ISA-TR84.00.09** — safety, hazard and consequence (SIS/SIF) analysis
- **Attify IoT** — reverse engineering and attack-surface methodology

Output is a report with mapping tables and four diagrams: threat model / data flow, MITRE ATT&CK for ICS kill chain, SANS ICS Cyber Kill Chain, and an Attify attack mind map.

## Quick start

```
python3 ics_threat_modeler.py            # serves on http://127.0.0.1:8000
python3 ics_threat_modeler.py --port 9000 --open
python3 ics_threat_modeler.py --help
```

## Files

| File | Description |
|---|---|
| `ics_threat_modeler.py` | The tool. |
| `ICS_Threat_Modeler_User_Manual.pdf` | User manual. |
| `ABB_2600T_Series_Model_266_WirelessHART_Pressure_Transmitter_ThreatModelerReport.pdf` | Sample report — ABB 266 WirelessHART pressure transmitter. |
| `Rockwell_Automation_Allen-Bradley_ControlLogix_5580_PLC_ThreatModelerReport.pdf` | Sample report — ControlLogix 5580 PLC. |
| `Schneider_Electric_EcoStruxure_Panel_Server_PAS600_(Panel_Se.pdf` | Sample report — Schneider EcoStruxure Panel Server PAS600. |
| `Siemens_SIMATIC_PCS_7_Process_Control_System_(DCS)_ThreatModelerReport.pdf` | Sample report — Siemens SIMATIC PCS 7 DCS. |
| `AI Threat Modeler` | Overview of the original Agent.ai version of the tool and how to access it. |
| `AI ThreatModeling_BinaryAnalysisReport_Prompt.md` | Prompt for AI-assisted binary analysis, threat modeling and bug bounty report writing. |

## Folders

- [`agents`](./agents) — export of the original Agent.ai agent definition, plus a conversion for HubSpot Agent Hub.
- [`agent_runs`](./agent_runs) — logs of runs of the original Agent.ai agent.
