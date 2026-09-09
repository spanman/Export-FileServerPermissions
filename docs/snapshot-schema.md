# Snapshot schema (v1.0)

One snapshot = one scan of one server, written by `Export-FsSnapshot` as gzipped JSON to
`<vault>/_meta/snapshots/<SERVER>/<yyyyMMdd-HHmmss>-<scanId8>.json.gz` (UTC timestamp). The renderer
merges the newest snapshot per server (`Merge-FsModel`) and uses older ones only for change tracking.
The factories in `FsPerm/Model/Snapshot.ps1` and `Principal.ps1` are the authoritative definition;
`tests/fixtures/*.json` are complete examples.

## Top level

| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | string | `"1.0"`. Major version must match the tool. |
| `scanId` | GUID string | Unique per run. First 8 hex chars appear in the file name. |
| `toolVersion` | string | Module version. |
| `timestamp` / `completedAt` | ISO-8601 UTC | Start / end. |
| `durationSeconds` | number | |
| `server` | object | `name` (upper-case NetBIOS), `fqdn`, `machineSid`, `domainRole` (3 = member server, 4/5 = DC), `osVersion`, `remotePsVersion`, `scannedFrom` |
| `domain` | object | `name`, `sid` of the server's domain |
| `credentialUser` | string | Account used for WinRM. Never a secret. |
| `scope` | object | `depth`, `includeShare[]`, `excludeShare[]`, `includeHiddenShares`, `maxFoldersPerShare`, `dryRun`, `groupExpansion`, `maxGroupDepth` |
| `status` | object | `partial` (bool), `phases` (name -> Ok/Partial/Failed/Skipped) |
| `stats` | object | Counters used by the Scan Health report |
| `shares[]` | array | See below |
| `folders[]` | array | Divergent folders plus every share root |
| `principals{}` | object | Keyed by principal id |
| `memberships[]` | array | Direct edges |
| `errors[]` | array | `timestamp, phase, scope, path, depth, kind, message, exceptionType` |

## Ids

| Entity | Id | Example |
|---|---|---|
| Share | `SERVER\ShareName` | `FS01\Finance` |
| Folder | `SERVER:<local path>` | `FS01:D:\Shares\Finance\Budgets` |
| Domain / well-known / orphaned principal | SID | `S-1-5-21-…-1105`, `S-1-5-11` |
| Server-local principal (incl. BUILTIN groups) | `SERVER\Name` | `FS01\Administrators` |

BUILTIN SIDs are identical on every machine but their membership is per machine, so local groups carry the
server name in the id and keep the SID as a property.

## Share

`id, name, server, localPath, uncPath, description, isHidden, rootFolderId, aces[], walk{}`

Share ACE: `principalId, sid, nameOnServer, accessRight (Full|Change|Read|Custom), accessMask, accessControlType (Allow|Deny)`

`walk`: `foldersVisited, foldersReturned, truncated, maxDepthReached, seconds, status`

## Folder

`id, server, localPath, shareNames[], primaryShareId, uncPath, relativePath, depth, parentId, nearestDivergentAncestorId,
isShareRoot, isProtected, ownerPrincipalId, childFolderCount, reparsePointsSkipped, explicitAceCount, aces[], error`

Only folders whose ACL diverges from the parent are recorded (inheritance disabled, or at least one explicit ACE),
plus every share root (`isShareRoot = true`). The full ACE list including inherited entries is stored, so the
renderer never reconstructs inheritance. `nearestDivergentAncestorId` links the divergent tree even when
intermediate folders were filtered out.

NTFS ACE: `index, principalId, sid, nameOnServer, rights, rightsMask, simpleRights (level), accessControlType,
isInherited, inheritanceFlags, propagationFlags, appliesTo`

## Principal

`id, kind, sid, domain, name, ntAccount, displayName, server, isWellKnown, isBroad, resolution, resolutionError,
memberCount, membershipResolved, membershipNote, fetchedAt, sourceScanId, ad{}, local{}`

| kind | Meaning |
|---|---|
| `User`, `Group`, `Computer` | Domain objects resolved in AD |
| `LocalGroup`, `LocalUser` | Server-local (SAM) accounts, id `SERVER\Name` |
| `WellKnown` | Everyone, Authenticated Users, SYSTEM, … (`isBroad` marks the ones that mean "anyone") |
| `Foreign` | Trusted-domain principal that could not be enumerated (`resolution = LookupFailed`) |
| `OrphanedSid` | `S-1-5-21-*` SID not found in AD and not translatable |

`ad` (users): `userPrincipalName, mail, enabled, userAccountControl, lastLogonTimestamp, pwdLastSet, accountExpires,
department, title, description, manager{dn,sam,sid}, whenCreated, distinguishedName, primaryGroupId`
`ad` (groups): `description, groupType, groupCategory, groupScope, mail, whenCreated, managedBy{dn,sam,sid}, distinguishedName`
`local`: `description`, plus `enabled`, `lastLogin` for local users.

Dates are ISO-8601 UTC strings; FILETIME `0` / never is `null`. `lastLogonTimestamp` replicates with 9–14 day
granularity, which is why the default stale threshold is 90 days.

## Membership

`groupId, memberId, kind (Direct | PrimaryGroup | LocalDirect), source (AD | Local:SERVER)`

Users never appear in their primary group's `member` attribute, so a `PrimaryGroup` edge is emitted for every
user and computer. Broad groups (Domain Users, Authenticated Users) are not enumerated; the renderer treats them as
implicit membership and never expands them into "all users".

## Merge rules (Merge-FsModel)

- Shares, folders, memberships: from each server's newest snapshot only.
- Principals: by id across servers; a resolved record beats an orphaned one; otherwise newest `fetchedAt` wins.
  `_servers` lists where the principal was seen.
- Memberships: union, deduplicated by (groupId, memberId, kind).
- Errors: appended with `server` and `scanId`.
