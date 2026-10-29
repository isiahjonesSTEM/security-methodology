# Security Research

Vulnerability research, bug bounty tooling and research artifacts.

## Tools (public releases)

| File | Description |
|---|---|
| `deephunter_publicrelease.txt` | Public release of `deephunterv2.py`, a bug bounty recon and scanning orchestrator. |
| `deephunterv3.1_publicrelease.txt` | Public release of `deephunterv3.1.py`, a cross-platform bug bounty scanner written in pure Python standard library (Windows, Linux, macOS; Python 3.8+). |
| `elite_hunter_publicrelease.txt` | Public release of `elite_hunter.py`, a separate bug bounty scanning script. |
| `binaryreverseAPKv3_publicrelease.txt` | Android APK reverse engineering and binary analysis automation script (uses JADX and related tools; set your own tool paths). |

Rename a `.txt` release to `.py` to run it, and only test targets you are authorized to test.

## Android research (Google Play Services APK v26.09.64)

| File | Description |
|---|---|
| `GooglePlayServicesAPKv26.09.64_PathTraversal_FileApkChimeraService_ACE_RCE.pdf` | Research report: path traversal in FileApkChimeraService. |
| `GooglePlayServicesAPKv26.09.64_RecaptchaChimeraActivity_RCE_datatheft.pdf` | Research report: RecaptchaChimeraActivity. |
| `RecaptchaExploit.zip` | Proof-of-concept Android app project (Gradle) for the RecaptchaChimeraActivity report. |
| `deepseek_mermaid_*.mermaid`, `.svg`, `.png` | Attack-flow and sequence diagrams for the reports (Mermaid source and rendered images), including MITRE EMB3D mapping. |

## Web and API research

| File | Description |
|---|---|
| `HackerOne_Cryptodotcom_500InternalServerError_report.docx` | Bug bounty report submitted through HackerOne. |
| `Crypto-Critical-Attacks.postman_collection.json` | Postman collection of API test requests used in that research. |
| `Crypto-Critical-Environment.postman_environment.json` | Matching Postman environment (variables only). |
| `crypto-endpoints.json` | List of API endpoints tested. |
| `burp file crypto-2026-02-17T07_00_39Z.json` | Burp Suite export from the same research. |
| `GoogleDorkTactics.docx` | Google dork search tactics for reconnaissance. |

## Folders

- [`DeepHunter_https___pentest-ground.com_20260417_163618`](./DeepHunter_https___pentest-ground.com_20260417_163618) — example DeepHunter V3 output from a scan of pentest-ground.com, a public practice target.
