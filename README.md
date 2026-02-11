# Export-FileServerPermissions

PowerShell script that enumerates Windows file server shares and NTFS permissions, outputting Cypher code for graph database import (Neo4j, Memgraph, etc.).

## What It Does

This script connects to a Windows file server and maps the permission structure into a graph database format:

- **Server nodes**: The file server itself
- **Share nodes**: SMB/CIFS shares on the server  
- **Folder nodes**: Top-level folders within each share
- **User/Group nodes**: Active Directory principals with access
- **Relationships**: Who has what permissions where

The output is Cypher code (Neo4j's query language) that can be imported into any graph database supporting Cypher.

## Why Graph Databases?

Traditional permission audits give you flat lists. Graph databases let you:
- Visualize complex permission inheritance
- Query "who has access to what" across multiple servers
- Find over-permissioned accounts
- Track permission sprawl over time
- Answer questions like "show me all paths from User X to Share Y"

## Requirements

- PowerShell 5.1 or later
- Credentials with read access to target file server(s)
- WinRM/PowerShell Remoting enabled on target server
- Active Directory module (for user/group type detection)

## Usage

Basic usage:
```powershell
.\Export-FileServerPermissions.ps1 -ServerName FS01
```

Specify output file:
```powershell
.\Export-FileServerPermissions.ps1 -ServerName FS01 -OutputFile C:\temp\permissions.cypher
```

The script will prompt for credentials to access the target server.

## What Gets Scanned

- All non-hidden shares (excludes administrative shares like C$, ADMIN$)
- Share-level permissions (SMB access rights)
- NTFS permissions on top-level folders within each share
- Account type detection (User vs Group) via Active Directory

## Output Format

The script generates Cypher code with these node types:

**Server**
```cypher
MERGE (server:Server {name: "FS01"})
```

**Share**  
```cypher
MERGE (share:Share {name: "Finance", server: "FS01"})
MERGE (server)-[:HOSTS]->(share)
```

**Folder**
```cypher
MERGE (folder:Folder {path: "\\\\FS01\\Finance\\Budgets"})
MERGE (share)-[:CONTAINS]->(folder)
```

**User/Group Access**
```cypher
MERGE (user:User {samAccountName: "jsmith"})
MERGE (user)-[r:HAS_NTFS_ACCESS]->(folder)
```

## Importing to Neo4j

1. Run the script to generate `.cypher` file
2. Open Neo4j Browser or use `cypher-shell`
3. Load and execute the file:

```cypher
:source /path/to/FileServerPermissions_FS01_20250211_143022.cypher
```

Or via `cypher-shell`:
```bash
cat permissions.cypher | cypher-shell -u neo4j -p password
```

## Features

- **Retry logic**: Handles transient file write failures with exponential backoff
- **Remote execution**: All ACL enumeration happens on the target server to avoid WinRM serialization issues
- **Character escaping**: Properly escapes backslashes and quotes for Cypher syntax
- **OneDrive warning**: Alerts if output path is in OneDrive (which can cause locking issues)
- **Progress indicators**: Shows real-time progress through shares and folders

## Example Queries

After importing, try these Cypher queries:

Find all users with direct access to a specific share:
```cypher
MATCH (u:User)-[r]->(s:Share {name: "Finance"})
RETURN u.samAccountName, type(r), r.permissions
```

Find over-permissioned accounts (access to 5+ shares):
```cypher
MATCH (p)-[r:HAS_SHARE_ACCESS]->(s:Share)
WITH p, count(DISTINCT s) as shareCount
WHERE shareCount >= 5
RETURN p.fullName, shareCount
ORDER BY shareCount DESC
```

Visualize all paths from a user to folders:
```cypher
MATCH path = (u:User {samAccountName: "jsmith"})-[*..3]->(f:Folder)
RETURN path
```

## Limitations

- Only scans top-level folders (not recursive through entire directory tree)
- Requires WinRM/PowerShell Remoting on target servers
- AD lookups may be slow for domains with many accounts
- Built-in accounts (BUILTIN\\, NT AUTHORITY\\) default to "Group" type

## Contributing

Pull requests welcome! Areas for improvement:
- Recursive folder scanning (with depth limits)
- Support for DFS namespaces
- Parallel processing for multiple servers
- CSV/JSON output options alongside Cypher

## License

MIT License - See LICENSE file for details

## Author

Created for mapping enterprise file server permissions into graph databases for security auditing and access analysis.
