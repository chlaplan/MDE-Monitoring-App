# MDE Monitoring App

A Windows (.NET 8 WPF) desktop dashboard providing a consolidated operational view of Microsoft Defender for Endpoint (MDE) state on the local machine. It surfaces Defender status metadata, Device Control activity, Firewall drop events, and applied Defender policy settings (with human-readable interpretation). Designed for administrators, support engineers, and security operations to quickly validate configuration & runtime posture.

---

## Key Capabilities

### 1. Overview Tab
Displays core Microsoft Defender for Endpoint status:
- Product / Engine versions
- Running mode
- Real‑Time Protection state
- Signature age metrics
- Device Control enforcement state
- Current user, machine name, IP, join type (Domain / Azure AD / Hybrid / Workgroup)

### 2. Device Control Tab
Parses Defender Device Control log lines (MPDeviceControl-*.log) from:
Shows:
- Timestamp
- Instance Path Id
- Vendor/Product IDs (VID / PID)
- Granted vs. Denied access sets

### 3. Firewall Tab
Reads a snapshot copy of the Windows Defender Firewall log:
(Optionally copied to `C:\Windows\Logs` to avoid locking issues.)  
Displays only DROP packets with:
- Timestamp, Action, Protocol
- Source/Destination IP / Ports
- Size
- Info / PID / Path
Includes:
- Horizontal + vertical scrolling
- Global keyword filter (searches all visible columns)
- Clear (X) filter button

### 4. Logs Tab
Pulls recent Defender Operational event log entries:
Maps numeric event levels to: Critical, Error, Warning, Info, Verbose (where applicable) and color‑codes severity. Supports level filter.

### 5. Policies Tab
Interprets Defender policy registry values under:
Features:
- Data‑driven interpretation via `Data\DefenderPolicyDefinitions.json`
- Detection of legacy Disable* flags and modern Allow* CSP style keys
- Attack Surface Reduction (ASR) rule expansion (`ASRRules` multi-value -> one row per GUID with friendly name and state)
- Summaries of:
  - ASR global exclusions
  - ASR per‑rule exclusions
  - Allowed Applications pattern list
  - Threat severity default action mappings
- Risk highlighting (e.g. disabled real‑time protection, ASR rule disabled, “Allow” action for high severity)

### 6. Policy Definition Extensibility
`DefenderPolicyDefinitions.json`:
- Defines: name, display name, description, kind (disableFlag | allowFlag | enum | percent | integer | raw), and optional enum maps.
- Unknown registry values appear as “Unmapped Defender policy value” until added.
- Supports rapid enrichment without recompiling.

### 7. ASR Rule Friendly Name Mapping
Static in code with optional (best‑effort) runtime enrichment from Microsoft reference page:

---

## Screenshots (Placeholder)
| Tab | Description |
|-----|-------------|
| Overview | Core Defender status summary |
| Device Control | USB / device access events |
| Firewall | Dropped packet table with filter |
| Policies | Interpreted policy matrix |
| Logs | Defender operational events |

(Add real screenshots before publishing.)

---

## Architecture

| Layer | Purpose |
|-------|--------|
| WPF (XAML) UI | Presentation (Tabs / DataGrids / Filters) |
| ViewModels (`MainViewModel`) | MVVM binding, refresh orchestration, filtering |
| Services | Data acquisition (Defender status, logs, firewall, policy registry, device control) |
| Models | Strongly typed DTOs (LogEntry, DeviceControlEvent, FirewallLogEntry, PolicySetting, DefenderStatus, SystemInfo) |
| JSON Definitions | External mapping for policy interpretation |

Data flow:
[Services] -> [ObservableCollection] -> [CollectionView/Filters] -> [DataGrid Bindings]

Threading:
- Background collection via `Task.Run` → marshalled to UI dispatcher.
- Snapshot read (copy) before parsing log files to avoid locking/partial read issues.

---

## Build & Run

### Prerequisites
- Windows 10 / 11
- .NET 8 SDK
- Visual Studio 2022 (with .NET desktop development workload)
- Administrator rights (recommended) for:
  - Reading firewall log
  - Accessing some Defender registry policy keys
  - Copying logs under `C:\Windows\Logs`
  - Accessing Device Control support directory

### Steps
1. Clone repository
2. Ensure `Data\DefenderPolicyDefinitions.json` is marked to “Copy to Output (PreserveNewest)"
3. Build solution in VS 2022
4. Run **as Administrator** (UAC prompt) to enable full feature set

### Optional Manifest Elevation
The project references an application manifest (`app.manifest`) requesting elevation (requireAdministrator). Remove or alter execution level if you want on-demand elevation only.

---

## Permissions & Fallback Behavior

| Feature | Requires Elevation? | Fallback |
|---------|---------------------|---------|
| Firewall Log | Yes (file read) | Error row with diagnostic |
| Policy Registry | Often (HKLM) | “Unmapped” or “Missing Key” |
| Device Control Log | Usually not (read support dir) | Empty list / error sentinel |
| Event Log (Defender) | No (standard user allowed) | Error sentinel |

If definitions JSON fails to load → single “Definitions File Not Loaded” row including attempted paths & parse errors.

---

## Filtering & Performance

- CollectionView filters (in-memory) for logs and firewall events.
- DataGrids use virtualization—avoid wrapping in external ScrollViewers.
- Large list fields (AllowedApplications, exclusions) are summarized to prevent UI bloat.

---

## Extending Policy Support

1. Capture unknown keys (look for “Unmapped Defender policy value” rows).
2. Add entries to `Data\DefenderPolicyDefinitions.json`:
{ "Name": "NewPolicyKey", "DisplayName": "Friendly Name", "Description": "Short description.", "Kind": "enum", "EnumMap": { "0": "Off", "1": "On" } }

3. Rebuild (or just restart: file is loaded at service construction).

Kinds:
- disableFlag: Registry 1 = Feature Disabled (risk mapping)
- allowFlag: Registry 1 = Feature Enabled
- enum: Map numeric/string codes
- percent: Display value + “%”
- integer: Raw numeric (special formatting optionally applied)
- raw: Leave as-is (or summarized by custom parser)

---

## ASR Rule Updates

The service includes optional method:
````````csharp
public void RefreshASRRuleMappings()
{
    // Attempts to scrape updated GUID/name pairs from Microsoft reference
    // Failures are silently ignored
}
````````

You can call this (e.g., on a button) to attempt scraping updated GUID/name pairs. Failures are silently ignored.

---

## Security Considerations

- Running elevated increases exposure; prefer least privilege if you do not need firewall/policy details.
- Avoid distributing customized policy definition files that could misrepresent security posture.
- No outbound network calls except optional ASR refresh (HTTPS to Microsoft docs).

---

## Logging & Diagnostics

Current design surfaces errors inline (error rows). For deeper diagnostics you may add:
- A dedicated “Diagnostics” tab
- Structured logging (Serilog / ETW)
- Trace output while debugging

---

## Roadmap Ideas

| Feature | Status |
|---------|--------|
| Export (CSV/JSON) for policies & events | Planned |
| Auto-tail firewall log / real-time updates | Planned |
| Policy delta comparison (baseline vs current) | Planned |
| Command-line “snapshot” mode (headless) | Planned |
| Filtering for Policies tab (search box) | Planned |
| Expand / drill-down views for long lists | Planned |

---

## Contributing

1. Fork
2. Create feature branch
3. Follow existing C# style conventions (nullable enabled, expression-bodied where concise)
4. Keep JSON definitions alphabetical where possible
5. Submit PR with concise description + test notes

---

## Testing Checklist

| Area | Test |
|------|------|
| Startup | All tabs populate without crash (non-elevated & elevated) |
| Firewall | Drop entries appear; filter works |
| Policies | Known keys interpreted; unknown visible as “Unmapped” |
| ASR | Multi-rule parsing expands each GUID correctly |
| Device Control | Latest log parsed; timestamps descending |
| Logs | Level filter cycles (All/Info/Warning/Error/Critical) |
| Refresh | Repeated refresh releases file handles & updates counts |
| JSON Missing | Shows “Definitions File Not Loaded” row with attempted paths |

---

## Troubleshooting

| Symptom | Cause | Action |
|---------|-------|--------|
| “Definitions File Not Loaded” | JSON missing / invalid | Validate JSON (no comments) & CopyToOutput |
| Empty Firewall tab | Not elevated or log disabled | Run as admin; ensure firewall logging enabled |
| Policy rows all “Unmapped” | Wrong hive path / no policies | Confirm key exists & elevation |
| ASR rows absent | ASRRules value not present | Confirm policy deployment |
| Large AllowedApplications raw text | Normal | Summarized preview; open JSON or registry for full list |

---

## License



---

## Disclaimer

This tool provides *read-only* visibility. It does **not** guarantee complete security coverage nor replace official Defender or MDE management consoles. Always validate interpretations against current Microsoft documentation, especially after platform updates.

---

## Acknowledgements

- Microsoft Defender for Endpoint documentation.
- Windows Eventing and Registry APIs.
- Community best practices for WPF MVVM + log parsing.

---

## Quick Start (TL;DR)