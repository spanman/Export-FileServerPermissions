# Layer contracts

This file pins the interfaces between the four layers of the `FsPerm` module so they can be
built and tested independently. Model is finished and is the source of truth for shapes; read
`FsPerm/Model/*.ps1` before anything else.

```
Collector  ──writes──▶  snapshot .json.gz  ──Import-FsSnapshotHistory / Merge-FsModel──▶  $Model
$Model ──▶ Analytics (closure, effective rights, reports, diff) ──▶ Render (Obsidian vault)
```

## Rules for Model / Analytics / Render code (enforced by tests/Compat.Tests.ps1)

- Pure and cross-platform: no `Get-CimInstance`, `Invoke-Command`, `Get-Acl`, `[adsisearcher]`,
  `Get-LocalGroupMember`, `Get-SmbShare`. Those live only in `FsPerm/Collector/`.
- Never `Sort-Object` on data; use `Get-FsSorted` / `Get-FsSortedKeys` (ordinal, deterministic).
- Never `Split-Path` / `[IO.Path]` on UNC or local-path *data*; use `FsPerm/Model/Unc.ps1` helpers.
  Filesystem output paths use `Join-Path`.
- Never `Get-Date` for content; take `-Now` (analytics) or read `$Model.generatedAt`.
- Files are written with `[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))`, LF endings.
- Hex literals that use bit 31 are Int32 in PowerShell (`0xFFFFFFFF -eq -1`). Use `$script:FsMask32` etc.
- Never name a variable `$pid`, `$input`, `$host`, `$error`, `$args`, `$matches` (automatic variables).
- Functions are named `Verb-Fs<Noun>` with approved verbs.

## $Model (output of Merge-FsModel) — everything is hashtables/OrderedHashtable and arrays

```
$Model.generatedAt              ISO UTC string
$Model.servers[name]            @{ name fqdn machineSid domainRole scanId lastScanned completedAt durationSeconds scope status stats
                                   credentialUser previousScanId previousScanned snapshotCount shareIds(string[]) errorCount }
$Model.shares[shareId]          share hashtable  (see New-FsShare)   aces[] are share ACEs (accessRight Full|Change|Read|Custom, accessMask, accessControlType)
$Model.folders[folderId]        folder hashtable (see New-FsFolder)  aces[] are NTFS ACEs (rights, rightsMask, simpleRights, accessControlType, isInherited, inheritanceFlags, propagationFlags, appliesTo)
                                isShareRoot=true folders carry the share-root ACL; they get NO note of their own (the Share note shows their ACL)
$Model.principals[id]           principal hashtable (see New-FsPrincipal); may have ad{} or local{}; `_servers` = servers where seen
$Model.memberships              list of @{ groupId memberId kind(Direct|PrimaryGroup|LocalDirect) source }
$Model.errors                   list of error hashtables with server + scanId added
$Model.snapshots[server]        snapshots newest first (for diffs); [0] is the one the facts came from
$Model.domainSids               string list; $Model.domains[sid] = name; $Model.machineSids[server] = sid
$Model.index                    acesByPrincipal[pid] -> list of @{ resourceId resourceKind(Share|Folder) server ace layer(Share|NTFS) }
                                acesByResource[rid] -> ace[]; membersByGroup[gid] -> string[]; groupsByMember[mid] -> string[]
                                foldersByShare[shareId] -> folderIds (incl. root); childrenByFolder[fid] -> divergent children;
                                rootFolderByShare[shareId] -> fid; sharesByServer[srv] -> shareIds; referencedPrincipalIds (HashSet)
Get-FsModelPrincipal -Model -Id   never returns $null (synthesizes OrphanedSid/unknown)
Get-FsResource -Model -Id         @{ kind='Share'|'Folder'; record } or $null
```

Rights levels: `None=0 < List=1 < Read=2 < Write=3 < Modify=4 < Full=5` via `Get-FsLevelOrdinal`, `Get-FsLevelName`,
`Get-FsMinLevel`, `Get-FsMaskLevel`, `Get-FsShareRightLevel`.

## Analytics API (FsPerm/Analytics/*.ps1) — consumed by Render

All functions take `-Model` and memoize into `$Model.cache` (create `$Model['cache'] = @{}` lazily).

```
Get-FsAnalysisOptions [-StaleDays 90] [-PasswordAgeDays 365] [-NestingDepthThreshold 3] [-TopN 25] [-RowCap 500]
                      [-LargeGroupThreshold 500] [-AdminPrincipalIds string[]] [-Now datetime] [-SnapshotAgeWarnDays 14]
    -> options hashtable. Default -Now = [datetime]::Parse($Model.generatedAt) (so output is deterministic per model).

Get-FsTransitiveGroups   -Model -PrincipalId                -> string[] group ids reachable via membership (excl. self; cycle-safe)
Get-FsGroupChain         -Model -PrincipalId -GroupId       -> string[] shortest path of ids from principal to group (inclusive), or @()
Get-FsTransitiveMembers  -Model -GroupId [-UsersOnly]       -> string[] member ids (excl. self; cycle-safe). Broad/well-known groups are NOT expanded to "all users".
Get-FsGroupNestingDepth  -Model -GroupId                    -> int (longest simple path upward through parent groups, cap 20)
Get-FsGroupCycles        -Model                             -> string[][] each cycle canonicalised to start at its ordinal-smallest id
Get-FsToken              -Model -PrincipalId                -> HashSet[string]: self + transitive groups + Everyone/Authenticated Users/NETWORK for User|Computer|Group|LocalGroup kinds
Get-FsEffectiveMask      -Aces -Token                       -> long. Per-bit first-match: explicit Deny, explicit Allow, inherited Deny, inherited Allow; InheritOnly ACEs skipped.
Get-FsEffectiveLevel     -Model -PrincipalId -ResourceId    -> @{ level; shareLevel; ntfsLevel; shareId; hasDeny(bool) }
                                                                For a Folder: share level from its primaryShareId share ACL; ntfs from folder aces.
                                                                For a Share: ntfs from the root folder aces. level = min(share, ntfs).
Get-FsEffectiveAccess    -Model -PrincipalId [-ExcludeBroad] -> rows @{ resourceId resourceKind server level shareLevel ntfsLevel via(string[] group ids, @() = direct) layer }
                                                                One row per grant point (share or divergent folder) where the token matches an Allow ACE. Sorted by server, resourceId.
Get-FsResourceReachers   -Model -ResourceId                 -> rows @{ principalId kind isBroad shareLevel ntfsLevel effectiveLevel via(string[]) userCount }  one per principal in the resource's ACLs (and share ACL), not expanded to users
Get-FsBroadPrincipalIds  -Model                             -> string[] ids of principals with isBroad, plus groups that transitively contain a broad principal
Get-FsInsightTags        -Model -Options                    -> hashtable entityId -> string[] from the fixed vocabulary:
                                                                users: disabled stale never-logged-on direct-ace; groups: empty-group nested-deep large-group;
                                                                resources: deny inheritance-broken broad-access broad-write direct-ace orphaned-ace; servers: scan-error
Get-FsReportCatalog                                          -> ordered list of @{ key number title question severity(high|medium|low|info) fileName }
Invoke-FsReports         -Model -Options                    -> ordered hashtable key -> @{ definition; columns(string[]); rows(object[] of ordered hashtables keyed by column);
                                                                 summary(string); appendixRows; appendixTitle; truncated(bool); csvRows }
                                                                Also sets $Model.findings[entityId] = list of @{ reportKey; count } (reverse index for Findings sections)
Compare-FsSnapshots      -Previous -Latest                  -> @{ server fromScanId toScanId fromTimestamp toTimestamp depthCompared banners(string[])
                                                                 summary(@{ added removed modified ... }); shares; folders; aces; memberships; principals } each a list of row hashtables
                                                                 with a `verdict` column. Returns $null when -Previous is $null.
Get-FsChangeSets         -Model                             -> hashtable server -> list of Compare-FsSnapshots results for consecutive pairs, newest first
Get-FsChangedEntityIds   -Model                             -> HashSet[string] entity ids in the newest diff per server (for the `changed` tag)
Get-FsHomeStats          -Model -Reports -Options           -> hashtable of counts and top lists used by Home.md and Dashboard.canvas
```

Report row cell values: scalars, `New-FsRef -Kind Principal|Resource|Server|Report -Id`, `New-FsCode 'text'`, or arrays of these.
Column headers are the row keys in order. Rows already sorted and capped at `RowCap` (`truncated` set; `csvRows` holds all rows).

## Render API (FsPerm/Render/*.ps1)

```
Export-FsVault -Model -VaultPath [-Options] [-PrimaryDomain] [-WhatIf] -> summary @{ written skipped deleted warnings }
```
Everything else in Render is internal. Render never touches `Notes/` or existing `.obsidian/*` files.

## Collector API (FsPerm/Collector/*.ps1, Windows only)

```
Invoke-FsScan -ServerName -Credential [-Depth] [-IncludeShare] [-ExcludeShare] [-IncludeHiddenShares] [-MaxFoldersPerShare]
              [-ChunkSize] [-NoGroupExpansion] [-MaxGroupDepth] [-SkipAdEnrichment] [-AdServer] [-AdCredential]
              [-SeedSnapshot string[]] [-DryRun] [-TimeoutSeconds]  -> snapshot object (New-FsSnapshot shape, populated)
```
The entry script then calls `Export-FsSnapshot -Snapshot $snap -Directory "<vault>/_meta/snapshots"`.

## Fixtures

`tests/fixtures/New-Fixtures.ps1` builds three snapshots with the Model factories and writes plain JSON
(`tests/fixtures/*.json`). Regenerate with the Docker command in `build/build.ps1 -Task Fixtures`. Tests import them
with `Import-FsSnapshot` and merge with `Merge-FsModel`.

## Running anything

Windows application control blocks `pwsh` from reading `.ps1` files on this workstation, so all development runs happen
in the Linux container (repo mounted at /work):

```bash
docker run --rm -v "<repo>:/work" -w /work fsperm-test -File ./build/Invoke-Tests.ps1            # all tests
docker run --rm -v "<repo>:/work" -w /work fsperm-test -File ./build/Invoke-Tests.ps1 -Path tests/Closure.Tests.ps1
docker run --rm -v "<repo>:/work" -w /work fsperm-test -Command 'Import-Module ./FsPerm/FsPerm.psd1; <ad hoc>'
```
Use `MSYS_NO_PATHCONV=1` and `$(pwd -W)` from Git Bash. Do not pass PowerShell code containing backslashes through a
bash heredoc (the tool layer collapses `\\`); write scratch scripts with the Write tool instead.

## Pester v5 gotchas hit while writing tests/*.Tests.ps1

- **Exactly one root-level `BeforeAll` per file.** A second `BeforeAll {}` placed outside any `Describe` (even
  right after the first one) makes Pester silently skip *both* — every test in the file fails as if nothing
  ever ran, with no error surfaced anywhere (not even `-Verbosity Diagnostic`). Put every root-level fixture
  and helper-function definition in the *one* top-level `BeforeAll`.
- Plain variable/function assignments written directly in a `Describe` body (not inside `BeforeAll`) run only
  during Pester's Discovery pass and are **not** reliably available when `It` blocks run later. Use `BeforeAll`
  for anything an `It` needs, and use plain top-level script code (before any `Describe`) only for building
  `-TestCases`/`-ForEach` arrays, which genuinely need Discovery-time values.
- `$x = if (cond) { $arrayA } else { $arrayB }` silently collapses to a bare scalar when the executing branch's
  array has exactly one element (the branch's own output stream unrolls it). Constrain the left-hand side:
  `[object[]] $x = if (cond) { $arrayA } else { $arrayB }`.
- `return , $x` at the end of a function forces the *entire* return value to be one pipeline object; a caller
  that does `@(Get-Thing)` then gets a single element whose value is the whole array, not each item. Prefer a
  plain `return $x` (letting the array unroll one level, which callers already wrap in `@()`) unless you
  specifically want the whole thing treated as one atomic object.
