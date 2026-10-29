# Product Checklist Cheat Sheets

Per-product ISA/IEC 62443 security testing checklists ("cheat sheets") at Security Level 3, plus the tool that generates them. Each PDF maps every applicable ISA/IEC 62443-3-3 system requirement and 4-2 component requirement for one product, one requirement per row, with:

- the product's own menu paths, commands and evidence to collect for each requirement;
- pass criteria that let an assessor mark each row Pass, Fail, Partial, N/A or Deferred;
- compensating controls where a product cannot meet a requirement natively;
- session setup and capture instructions for that product (backup and export files, logs, screenshots).

The default posture is read-only. Steps that change configuration or stress a device are only for isolated or representative systems with written authorization.

Component types follow ISA/IEC 62443-4-2: **EDR** embedded device, **HDR** host device, **NDR** network device, **SAR** software application.

## Checklist generator

- `ics_62443_sl3_checklist_generator.py` — single-file, model-agnostic tool with a local web UI that builds a product-specific SL-3 cheat sheet PDF in the same format. Describe a product, add sources (AI web search, product URLs or uploaded manuals), and choose any AI model. Run `python3 ics_62443_sl3_checklist_generator.py` and open http://127.0.0.1:8010.
- `ICS_62443_SL3_Checklist_Generator_User_Manual.pdf` — user manual for the generator.

## Checklists (68)

### Controllers and RTUs

| Product | Type | File |
|---|---|---|
| AutomationDirect DL06 PLC | EDR | `AutomationDirect_DL06_62443_SL3_CheatSheet.pdf` |
| AutomationDirect Productivity2000 (P2-550) PLC | EDR | `AutomationDirect_Productivity2000_P2550_62443_SL3_CheatSheet.pdf` |
| Emerson PACSystems RX3i | EDR | `Emerson_PACSystems_RX3i_62443_SL3_CheatSheet.pdf` |
| Rockwell 1734 / 1738-AENTR adapters | EDR | `Rockwell_1734_1738_AENTR_62443_SL3_CheatSheet.pdf` |
| Rockwell 1769-AENTR adapter | EDR | `Rockwell_1769_AENTR_62443_SL3_CheatSheet.pdf` |
| Rockwell CompactLogix 5380 | EDR | `CompactLogix5380_62443_SL3_CheatSheet.pdf` |
| Rockwell ControlLogix 5570 (1756-L7x) | EDR | `Rockwell_ControlLogix_5570_1756L7_62443_SL3_CheatSheet.pdf` |
| Rockwell ControlLogix 5580 | EDR | `ControlLogix5580_62443_SL3_CheatSheet.pdf` |
| SEL-3350 RTAC | EDR | `SEL_RTAC_3350_62443_SL3_CheatSheet.pdf` |
| SEL-3505 RTAC | EDR | `SEL_3505_RTAC_62443_SL3_CheatSheet.pdf` |
| Schneider Modicon M340 | EDR | `Schneider_Modicon_M340_62443_SL3_CheatSheet.pdf` |
| Schneider Modicon M580 | EDR | `SchneiderM580_62443_SL3_CheatSheet.pdf` |
| Siemens S7-1500 / S7-1200 PLC | EDR | `Siemens_S7_PLC_62443_SL3_CheatSheet.pdf` |

### Drives

| Product | Type | File |
|---|---|---|
| ABB ACS580 / ACH580 / ACQ580 drives | EDR | `ABB_ACS580_ACH580_ACQ580_VFD_62443_SL3_CheatSheet.pdf` |
| Benshaw RSi H2 drive | EDR | `Benshaw_RSi_H2_VFD_62443_SL3_CheatSheet.pdf` |
| Rockwell PowerFlex 525 | EDR | `PowerFlex525_62443_SL3_CheatSheet.pdf` |
| Rockwell PowerFlex 527 | EDR | `PowerFlex527_62443_SL3_CheatSheet.pdf` |
| Rockwell PowerFlex 6000T medium-voltage drive | EDR | `PowerFlex6000T_MV_62443_SL3_CheatSheet.pdf` |
| Rockwell PowerFlex 753 / 755 | EDR | `PowerFlex753_755_62443_SL3_CheatSheet.pdf` |
| Rockwell PowerFlex 755T | EDR | `PowerFlex755T_62443_SL3_CheatSheet.pdf` |

### Protection relays

| Product | Type | File |
|---|---|---|
| Siemens SIPROTEC 5 7SJ85 relay | EDR | `Siemens_SIPROTEC5_7SJ85_62443_SL3_CheatSheet.pdf` |
| Siemens SIPROTEC 5 7UM85 relay | EDR | `Siemens_SIPROTEC5_7UM85_62443_SL3_CheatSheet.pdf` |
| Siemens SIPROTEC 5 7UT85 relay | EDR | `Siemens_SIPROTEC5_7UT85_62443_SL3_CheatSheet.pdf` |

### Instruments and meters

| Product | Type | File |
|---|---|---|
| ABB 2600T Series 266 WirelessHART pressure transmitter | EDR | `ABB_2600T_Series_266_WirelessHART_Pressure_Transmitter_62443_SL3_CheatSheet.pdf` |
| Endress+Hauser Proline Promag P300 / P500 flowmeters | EDR | `Endress_Hauser_Promag_P300_P500_62443_SL3_CheatSheet.pdf` |
| Schneider PowerLogic ION7650 meter | EDR | `PowerLogic_ION7650_62443_SL3_CheatSheet.pdf` |
| Schneider PowerLogic ION9000 meter | EDR | `ION9000_62443_SL3_CheatSheet.pdf` |
| Schneider PowerLogic PM5560 meter | EDR | `PowerLogic_PM5560_62443_SL3_CheatSheet.pdf` |
| Schneider PowerLogic PM8000 meter | EDR | `PM8000_62443_SL3_CheatSheet.pdf` |
| Square D / Schneider PowerLogic Model 98 / 98A transformer temperature controller | EDR | `Schneider_SquareD_PowerLogic_Model98A_Temp_Controller_62443_SL3_CheatSheet.pdf` |

### Building controls and gateways

| Product | Type | File |
|---|---|---|
| Innotech OMWEB02 (Omni / Vaisala) | EDR | `Innotech_OMWEB02_Omni_Vaisala_62443_SL3_CheatSheet.pdf` |
| ProSoft MVI56E-MCM / MCMXT Modbus module | EDR | `ProSoft_MVI56E-MCM_MCMXT_62443_SL3_CheatSheet.pdf` |
| ProSoft MVI56E-MNET / MNETXT Modbus TCP module | EDR | `ProSoft_MVI56E-MNET_MNETXT_62443_SL3_CheatSheet.pdf` |
| ProSoft PLX3x / PLX32 gateway | EDR | `ProSoft_PLX3x_PLX32_62443_SL3_CheatSheet.pdf` |
| Schneider EcoStruxure Panel Server PAS600 | EDR | `PanelServerPAS600_62443_SL3_CheatSheet.pdf` |
| Siemens Desigo PXC | EDR | `Siemens_DesigoPXC_62443_SL3_CheatSheet.pdf` |

### Network devices

| Product | Type | File |
|---|---|---|
| Cisco Catalyst 9300 | NDR | `CiscoCatalyst9300_62443_SL3_CheatSheet.pdf` |
| Cisco Catalyst IE3300 | NDR | `Cisco_IE3300_62443_SL3_CheatSheet.pdf` |
| Cisco IE4010 | NDR | `Cisco_IE4010_62443_SL3_CheatSheet.pdf` |
| Fortinet FortiGate (OT) | NDR | `Fortinet_FortiGate_OT_62443_SL3_CheatSheet.pdf` |
| Moxa EDS / MDS switches | NDR | `Moxa_EDS_MDS_62443_SL3_CheatSheet.pdf` |
| Red Lion N-Tron 700 switches | NDR | `RedLion_NTron_700_62443_SL3_CheatSheet.pdf` |
| Red Lion N-Tron NT24k switches | NDR | `RedLion_NTron_NT24k_62443_SL3_CheatSheet.pdf` |
| Rockwell Stratix 2000 (unmanaged) | NDR | `Rockwell_Stratix_2000_Unmanaged_62443_SL3_CheatSheet.pdf` |
| Rockwell Stratix 5400 | NDR | `Rockwell_Stratix_5400_62443_SL3_CheatSheet.pdf` |
| Rockwell Stratix 5700 / 5200 | NDR | `Stratix5700_5200_62443_SL3_CheatSheet.pdf` |
| Rockwell Stratix 5800 | NDR | `Stratix5800_62443_SL3_CheatSheet.pdf` |

### Hosts and hypervisors

| Product | Type | File |
|---|---|---|
| Ubuntu Linux LTS | HDR | `Ubuntu_Linux_62443_SL3_CheatSheet.pdf` |
| VMware ESXi 8 | HDR | `VMware_ESXi8_62443_SL3_CheatSheet.pdf` |
| Windows 11 | HDR | `Windows11_62443_SL3_CheatSheet.pdf` |
| Windows Server 2026 | HDR | `WindowsServer2026_62443_SL3_CheatSheet.pdf` |

### SCADA, HMI, BMS and engineering software

| Product | Type | File |
|---|---|---|
| AVEVA System Platform | SAR | `AVEVA_SystemPlatform_62443_SL3_CheatSheet.pdf` |
| AutomationDirect DirectSOFT | SAR | `AutomationDirect_DirectSOFT_62443_SL3_CheatSheet.pdf` |
| AutomationDirect Productivity Suite | SAR | `AutomationDirect_Productivity_Suite_62443_SL3_CheatSheet.pdf` |
| Inductive Automation Ignition 8.1 / 8.3 | SAR | `Ignition_8.1_8.3_62443_SL3_TestCheatSheet.pdf` |
| PTC Kepware KEPServerEX | SAR | `PTC_Kepware_KEPServerEX_62443_SL3_CheatSheet.pdf` |
| Red Lion N-View | SAR | `RedLion_NView_62443_SL3_CheatSheet.pdf` |
| Rockwell FactoryTalk | SAR | `Rockwell_FactoryTalk_62443_SL3_CheatSheet.pdf` |
| Rockwell Studio 5000 Logix Designer | SAR | `Rockwell_Studio5000_LogixDesigner_62443_SL3_CheatSheet.pdf` |
| SEL AcSELerator RTAC (SEL-5033) | SAR | `SEL_acSELerator_RTAC_5033_62443_SL3_CheatSheet.pdf` |
| Schneider EcoStruxure Control Expert | SAR | `Schneider_EcoStruxure_ControlExpert_Software_62443_SL3_CheatSheet.pdf` |
| Schneider EcoStruxure Power Monitoring Expert (PME) | SAR | `Schneider_EcoStruxure_Power_Monitoring_Expert_PME_62443_SL3_CheatSheet.pdf` |
| Schneider EcoStruxure Power SCADA Operation | SAR | `Schneider_EcoStruxure_PowerSCADA_Operation_62443_SL3_CheatSheet.pdf` |
| Schneider PowerLogic ION Setup | SAR | `Schneider_PowerLogic_ION_Setup_62443_SL3_CheatSheet.pdf` |
| Siemens APOGEE Insight | SAR | `Siemens_APOGEE_Insight_62443_SL3_CheatSheet.pdf` |
| Siemens DIGSI 5 | SAR | `Siemens_DIGSI5_62443_SL3_CheatSheet.pdf` |
| Siemens Desigo CC | SAR | `Siemens_DesigoCC_62443_SL3_CheatSheet.pdf` |
| Siemens WinCC | SAR | `Siemens_WinCC_62443_SL3_CheatSheet.pdf` |
