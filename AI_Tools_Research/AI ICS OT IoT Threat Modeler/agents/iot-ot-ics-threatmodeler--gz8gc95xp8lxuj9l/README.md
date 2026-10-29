# IoT_OT_ICS_ThreatModeler agent

The original Agent.ai threat modeling agent (agent ID `gz8gc95xp8lxuj9l`, public, created January 2025). It walks a user through describing a device, component, application or system, accepts design and engineering documents, and produces a threat model analysis using MITRE EMB3D, MITRE ATT&CK for ICS, ISA/IEC 62443-3-3 and 4-2, and ISA-TR84.00.09.

## Files

- `agent.json` — full Agent.ai agent definition (workflow actions, prompts, inputs and outputs).
- `hubspot-agent-hub.json` — the same agent converted for HubSpot Agent Hub (importable definition).
- `hubspot-agent-hub.md` — readable version of the HubSpot Agent Hub instructions.

The current, standalone version of this tool is [`ics_threat_modeler.py`](../../ics_threat_modeler.py).
