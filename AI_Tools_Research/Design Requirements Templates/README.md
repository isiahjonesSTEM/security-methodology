# Design Requirements Templates

Linked lifecycle specification templates for a modular chilled-water cooling plant integrated with a building management system (BMS), targeting ISA/IEC 62443 Security Level 3 (SL-T 3). Each document is a template with a worked data center example and traces to the one before it:

**URS → FRS → SDS and HDS**

## Files

| Document | Word | PDF | What it covers |
|---|---|---|---|
| User Requirement Specification (URS) | [`.docx`](./URS_Modular_Cooling_Plant_SL3.docx) | [`.pdf`](./URS_Modular_Cooling_Plant_SL3.pdf) | Process and operational requirements, consequence and threat basis (MITRE ATT&CK for ICS), zones, conduits and protocols, every ISA/IEC 62443-3-3 system requirement, ISA/IEC 62443-4-2 component requirements, supplier and verification requirements. |
| Functional Requirement Specification (FRS) | [`.docx`](./FRS_Modular_Cooling_Plant_SL3.docx) | [`.pdf`](./FRS_Modular_Cooling_Plant_SL3.pdf) | Testable, configurable and programmable functions traced to every functional URS requirement: sequences, fail states, alarms and historian, interfaces, boundary functions, security functions, component realization and the Secure PLC Coding Top 20 as programming requirements. |
| System Design Specification (SDS) | [`.docx`](./SDS_Modular_Cooling_Plant_SL3.docx) | [`.pdf`](./SDS_Modular_Cooling_Plant_SL3.pdf) | Design decisions, network and addressing, conduit rule register, control software, BMS and historian design, security services, per-product baselines, role matrix, ISA/IEC 62443-3-3 allocation and ISA/IEC 62443-4-2 SAR requirements for all software. |
| Hardware Design Specification (HDS) | [`.docx`](./HDS_Modular_Cooling_Plant_SL3.docx) | [`.pdf`](./HDS_Modular_Cooling_Plant_SL3.pdf) | Equipment list, control panels, hardwired I/O, fail positions, network, power, hosts, physical security and ISA/IEC 62443-4-2 requirements for every EDR, HDR and NDR device. |

## Worked example

Data center chilled-water plant: Trane Symbio 800 chiller modules, Rockwell ControlLogix 5580 plant control, Siemens Desigo CC as the primary BMS path and Kepware historian as the secondary, long-term site and campus-wide store. Secure protocol variants (OPC UA, BACnet/SC, CIP Security) are used where both ends support them; BACnet/IP, BACnet MS/TP, Modbus TCP/RTU, EtherNet/IP, PROFINET and PROFIBUS are used where real subsystems require them, confined and compensated.

## Using the templates

- Black text is the template requirement; blue italic text is the worked example; bracketed blue text is a project fill-in.
- SL-A 3 is achieved by the configured system — zones and conduits, system-level countermeasures, secure configuration and component capabilities together — not by product certification alone.
- Product capabilities, certifications and advisories are as of 28 October 2026; confirm them at FAT, SAT and handover.
- The "Business Confidential" marking is an example of applying a data classification label; replace it with your own.

Open source.
