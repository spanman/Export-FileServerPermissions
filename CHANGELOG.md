# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - Unreleased

### Added

- `FsPerm` PowerShell module split into Collector, Model, Analytics and Render layers.
- Group membership collection: direct and nested AD group members, primary-group
  membership, and server-local group members (BUILTIN\Administrators etc.).
- Full Active Directory enrichment of users and groups via ADSI (no RSAT required).
- Configurable `-Depth` folder scanning that records only folders whose ACL diverges
  from the parent.
- Gzipped JSON snapshots per scan run, stored inside the vault under `_meta/snapshots/`.
- Obsidian vault renderer: notes for servers, shares, folders, users, groups,
  well-known and orphaned principals; wikilinks form the graph.
- Precomputed security reports (broad exposure, deny ACEs, broken inheritance,
  direct user ACEs, disabled/stale accounts, orphaned SIDs, over-permissioned
  principals, group hygiene, full control, privileged grants, department access,
  share vs NTFS limiter, scan health).
- Change tracking between snapshots (`Changes - <server>` and `Changelog` notes).
- Home dashboard note, JSON Canvas dashboard, and Obsidian Bases views.
- Pester 5 test suite with fixture snapshots, run in Docker.

### Changed

- Output format is an Obsidian vault instead of Cypher.
- Share enumeration uses `Get-SmbShare` with SDDL parsing (SIDs) instead of
  `Get-WmiObject` and `Get-SmbShareAccess`.
- `gitignore` renamed to `.gitignore` (it was inactive before).

### Removed

- Cypher / Neo4j output.

## [1.0.0] - 2025-02-11

### Added

- Initial script: enumerate shares, share permissions and top-level NTFS
  permissions on one file server; emit Cypher.
