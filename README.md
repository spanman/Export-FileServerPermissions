# Export-FileServerPermissions

Scan Windows file servers for share and NTFS permissions, map every principal through its Active Directory
group chain, and turn the result into an **Obsidian vault**: one note per server, share, folder, user and group,
wikilinked so Obsidian's Graph View shows who can reach what and through which groups. Precomputed security
reports, a dashboard, and a change log come with it.

```
.\Export-FileServerPermissions.ps1 -ServerName fs01.example.com
```

Then open `.\vault` in Obsidian and start at `Home.md`.

## What you get

| In the vault | What it shows |
|---|---|
| `Home.md`, `Dashboard.canvas` | Coverage stats, findings summary with deltas, top-5 lists, scan health, recent changes |
| `Servers/`, `Shares/`, `Folders/` | Share ACLs, NTFS ACLs (explicit vs inherited, Deny first), owners, broken inheritance, "who can reach this" tables |
| `Users/`, `Groups/` | AD attributes as Obsidian properties, direct and transitive group membership, direct grants, effective access with the group chain, Mermaid access-path diagrams |
| `WellKnown/`, `Orphaned/` | Everyone / Authenticated Users / SYSTEM etc., and SIDs that no longer resolve |
| `Reports/` | 15 numbered reports: broad exposure, Deny ACEs, broken inheritance, direct user ACEs, disabled and stale accounts with access, orphaned SIDs, over-permissioned users and groups, group hygiene (empty, circular, deeply nested, ownerless), Full Control anywhere, privileged grants to non-admins, department access matrix, share-vs-NTFS limiter, scan health |
| `Reports/Changes - <server>.md`, `Reports/Changelog.md` | What changed since the previous scan: grants added/removed/changed, membership changes, inheritance flips, renamed or disabled accounts |
| `*.base` | Native Obsidian Bases views (sortable, filterable tables over the note properties) |
| `_meta/snapshots/` | One gzipped JSON snapshot per scan; the vault is regenerated from these |

Graph View is pre-configured: users green, groups blue, shares orange, servers red, orphaned SIDs magenta,
disabled accounts gray, recently changed entities orange. Folders, well-known principals and huge groups are
hidden by default so the graph stays readable; open a share note and use Local Graph to drill in.

## How it works

```
Collector (WinRM + ADSI)  ──▶  snapshot .json.gz  ──▶  Analytics  ──▶  Render (Obsidian vault)
```

1. **Scan** connects to the server over WinRM with the credential you supply, enumerates non-administrative
   shares and their SMB ACLs, walks each share to `-Depth` levels and records only folders whose ACL *diverges*
   from the parent (inheritance disabled or explicit ACEs). Every SID is resolved once through ADSI with full
   enrichment (display name, enabled, last logon, department, title, manager, group type, managedBy), group
   membership is expanded (direct, nested, primary group, and server-local groups such as
   `BUILTIN\Administrators`), and the result is saved as a snapshot.
2. **Render** merges the newest snapshot of every server in the vault, computes transitive membership and
   effective rights (share level ∩ NTFS level, canonical Deny/Allow order), runs the reports, diffs each server
   against its previous snapshot, and regenerates all generated notes. Files under `Notes/` are yours and are
   never touched; everything else the tool wrote is replaced or removed.

## Requirements

- Workstation: Windows, PowerShell 7.x, domain-joined (AD is queried via ADSI, no RSAT needed).
- Target servers: WinRM enabled; Windows PowerShell 5.1 or later on the server is fine.
- Server credential: a local Administrator or Backup Operator on the target (prompted; never stored).
- Obsidian 1.9 or later (Bases and Canvas are core plugins). No community plugins required.
- Docker (Linux containers) only if you want to run the test suite.

## Usage

```powershell
# Scan one server one level deep and render the vault (prompts for server credentials)
.\Export-FileServerPermissions.ps1 -ServerName fs01.example.com

# Deeper walk of two shares, verbose, no folder walk first to check the share list
.\Export-FileServerPermissions.ps1 -ServerName fs01.example.com -DryRun -Verbose
.\Export-FileServerPermissions.ps1 -ServerName fs01.example.com -Depth 3 -IncludeShare Finance,HR

# Fleet: scan several servers with one credential, render once
$cred = Get-Credential DOMAIN\svc_scan
'fs01','fs02','fs03' | ForEach-Object { .\Export-FileServerPermissions.ps1 -ServerName $_ -Credential $cred -SkipRender }
.\Export-FileServerPermissions.ps1 -RenderOnly

# Tune the analysis
.\Export-FileServerPermissions.ps1 -RenderOnly -StaleDays 60 -NestingDepthThreshold 2 -TopN 50
```

| Parameter | Default | Purpose |
|---|---|---|
| `-ServerName` | | Server to scan (FQDN preferred) |
| `-Credential` | prompt | WinRM identity for the server |
| `-AdCredential` / `-AdServer` | logged-on user | Override the identity / DC used for AD lookups |
| `-VaultPath` | `.\vault` | Obsidian vault folder |
| `-Depth` | 1 | Folder levels below each share root (0 = roots only) |
| `-IncludeShare` / `-ExcludeShare` | | Wildcard share filters |
| `-IncludeHiddenShares` | off | Include `Name$` shares (administrative shares are always excluded) |
| `-DryRun` | off | Shares and share ACLs only |
| `-SkipRender` / `-RenderOnly` | | Split the two phases |
| `-StaleDays`, `-PasswordAgeDays`, `-NestingDepthThreshold`, `-TopN`, `-RowCap`, `-LargeGroupThreshold`, `-AdminPrincipal` | 90, 365, 3, 25, 500, 500, built-ins | Report thresholds |
| `-MaxHistory` | 10 | Snapshots per server loaded for the change log |
| `-InstallPlugins` | off | Download the Dataview community plugin into the vault (optional) |

## Effective rights: how they are computed, and the caveats

For each principal a pseudo-token is built (itself, all transitive groups, plus Everyone, Authenticated Users and
NETWORK). ACEs are evaluated per bit in Windows canonical order: explicit Deny, explicit Allow, inherited Deny,
inherited Allow; inherit-only ACEs are skipped. An explicit Allow therefore beats an inherited Deny, as it does on
the server. The effective level is the lower of the share level and the NTFS level, on the scale
`None < List < Read < Write < Modify < Full`.

Not modelled: logon-type SIDs beyond NETWORK, claims and Central Access Policies, owner implicit rights,
backup/restore privileges, files, and folders below `-Depth`. Broad principals (Everyone, Domain Users, …) are
never expanded into "all users"; reports show them as a single row and count reach "excluding broad grants"
separately so the signal is not drowned.

## Change tracking

Each run keeps its snapshot. `Reports/Changes - <server>.md` compares the two newest snapshots of that server;
`Reports/Changelog.md` lists every consecutive pair. Both are derived, so re-running is idempotent. If two scans
used different `-Depth` values the diff is limited to the shallower depth and says so. Entities that changed in
the latest run get the `#changed` tag (orange in the graph).

## Development and tests

The analytics and renderer are pure PowerShell and are tested on Linux in Docker with Pester 5 and
PSScriptAnalyzer; the Windows-only collector is parse-checked and unit-tested for its pure helpers.

```powershell
./build/build.ps1 -Task Image      # build the fsperm-test image once
./build/build.ps1 -Task Test       # Pester suite (fixture snapshots in tests/fixtures)
./build/build.ps1 -Task Analyze    # PSScriptAnalyzer
./build/build.ps1 -Task Lint       # render fixtures to build/out/fixture-vault and run markdownlint
./build/build.ps1 -Task Mermaid    # validate every Mermaid block with mermaid-cli
./build/build.ps1 -Task All
```

Open `build/out/fixture-vault` in Obsidian to see the output for the synthetic two-server dataset.
See `docs/contracts.md` for the layer interfaces and `docs/snapshot-schema.md` for the snapshot format.

## Limitations

- Folders only; files are not scanned. Folders below `-Depth` and non-divergent folders have no note.
- DFS namespaces, reparse points and junctions are skipped (counted in Scan Health).
- Cross-forest principals appear as unresolved unless the trusting domain is reachable.
- `lastLogonTimestamp` is only replicated every 9–14 days; do not set `-StaleDays` below 14.
- The vault contains account names, SIDs and access data. Keep it out of source control (`vault/` is ignored).

## License

MIT. See `LICENSE`.
