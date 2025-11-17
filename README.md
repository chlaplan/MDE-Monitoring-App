# Microsoft makes no guarantees—no warranties, support, maintenance, performance assurances, or commitments regarding security, compliance, or fitness for a particular purpose.

# MDE Monitoring App (WPF / .NET 8)

Lightweight desktop dashboard for quickly inspecting Microsoft Defender / endpoint security posture (local or remote).

## Core Features
- Overview: Defender versions, realtime protection, signature ages, tamper & cloud states.
- Device Control: USB / storage allow & deny events.
- Firewall: Recent DROP packets with fast text filter.
- Defender Logs: Operational events (severity color coded).
- Policies: Interpreted registry + ASR rule expansion, exclusions summaries.
- WDAC Policies: Auto-discovery (local & remote), summary counts, per‑policy XML export (single or all), large FileRules lazy/paged loading.
- Compliance Snapshot: JSON-driven policy baseline → pass/fail %.
- WFP Summary: Filter counts + top rule names.
- App Control (CI / AppLocker) Events.
- PDF Report Export: Full snapshot (optional remote capability annotation).
- Remote Mode: UNC / WinRM / optional PsExec fallback for WDAC, WFP, policies.
- Performance: Background collection, UI virtualization, deferred heavy detail loading.

## Quick Start
Download latest ZIP file from releases https://aka.ms/MDETool

## WDAC Workflow
- Press Reload WDAC Policies
- Expand a policy row to view first slice of FileRules
- Click Show All for full enumeration
- Export selected or all XML

## Export
- PDF: Toolbar button (includes WDAC XML, compliance, filters)
- WDAC XML: Buttons (selected / all)

## Remote Collection Tips
- Set target host, toggle PsExec if admin share blocked
- Ensure Remote Registry / WinRM enabled for richer data

## Screenshots
![Overview](Screenshots/Overview.jpg)
![Policies Placeholder](Screenshots/MDEPolicies.jpg)
![WDAC Placeholder](Screenshots/WDAC.jpg)
![Compliance Placeholder](Screenshots/Compliance.jpg)


## Configuration Files
- `Data/DefenderPolicyDefinitions.json` (policy interpretation)
- `CompliancePolicy.config.json` (baseline rules)

## Minimal Troubleshooting
| Symptom | Hint |
|---------|------|
| Empty WDAC list | No *.cip in CodeIntegrity\CiPolicies\Active or access denied |
| Missing ASR rules | `ASRRules` value not deployed |
| High WFP count warning | >10K filters (investigate layering) |
| PDF missing sections | Load data first (Refresh) |
