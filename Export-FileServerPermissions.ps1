<#
.SYNOPSIS
    Enumerates file server shares and NTFS permissions, outputting Cypher code for graph database import.

.DESCRIPTION
    Connects to a file server, enumerates shares, and documents share-level and NTFS permissions.
    Outputs Cypher code to create nodes and relationships for Server, Share, User, and Group entities.

.PARAMETER ServerName
    The name of the file server to enumerate.

.PARAMETER OutputFile
    The path to the output file for Cypher code. Defaults to .\FileServerPermissions.cypher

.EXAMPLE
    .\Export-FileServerPermissions.ps1 -ServerName FS01 -OutputFile C:\temp\permissions.cypher
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = ".\FileServerPermissions_$($ServerName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').cypher"
)

# Get credentials
$cred = Get-Credential -Message "Enter credentials to access $ServerName"

# Initialize output file
if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
}

# Function to write Cypher code with retry logic
function Write-CypherCode {
    param([string]$cypher)
    
    $maxRetries = 5
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            Add-Content -Path $OutputFile -Value $cypher -Encoding UTF8 -ErrorAction Stop
            Add-Content -Path $OutputFile -Value "" -Encoding UTF8 -ErrorAction Stop
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Start-Sleep -Milliseconds (100 * $retryCount)  # Exponential backoff
            }
            else {
                Write-Host "      ERROR: Failed to write to file after $maxRetries attempts: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
        }
    }
}

# Function to extract domain\username or just username
function Get-AccountInfo {
    param([string]$identityReference)
    
    if ($identityReference -match '^(.+?)\\(.+)$') {
        return @{
            Domain = $Matches[1]
            SamAccountName = $Matches[2]
            FullName = $identityReference
        }
    } else {
        return @{
            Domain = ""
            SamAccountName = $identityReference
            FullName = $identityReference
        }
    }
}

# Function to determine if account is a group or user
function Get-AccountType {
    param([string]$samAccountName, [string]$domain)
    
    try {
        if ($domain -and $domain -ne "BUILTIN" -and $domain -ne "NT AUTHORITY") {
            $searcher = [adsisearcher]"(samAccountName=$samAccountName)"
            $result = $searcher.FindOne()
            if ($result) {
                $objectClass = $result.Properties["objectclass"]
                if ($objectClass -contains "group") {
                    return "Group"
                } elseif ($objectClass -contains "user") {
                    return "User"
                }
            }
        }
    } catch {
        # If AD lookup fails, make educated guess
    }
    
    # Default assumptions for built-in accounts
    if ($samAccountName -match "group|users|admins|administrators") {
        return "Group"
    }
    
    return "User"  # Default to User
}

Write-Host "`n=== File Server Permission Enumeration ===" -ForegroundColor Cyan
Write-Host "Server: $ServerName" -ForegroundColor Yellow
Write-Host "Output: $OutputFile`n" -ForegroundColor Yellow

# If output file is in OneDrive, warn user
if ($OutputFile -match "OneDrive") {
    Write-Host "WARNING: Output file is in OneDrive folder. Consider using a local path to avoid file locking issues." -ForegroundColor Yellow
    Write-Host "Press Enter to continue or Ctrl+C to cancel..." -ForegroundColor Yellow
    Read-Host
}

# Create Server node
Write-Host "[1/4] Creating Server node..." -ForegroundColor Green
$serverCypher = @"
// ============================================
// CREATE SERVER NODE
// ============================================
MERGE (server:Server {name: "$ServerName"})
ON CREATE SET server.created = datetime()
ON MATCH SET server.lastScanned = datetime();
"@

Write-CypherCode -cypher $serverCypher

# Get shares using WMI with credentials
Write-Host "[2/4] Enumerating shares..." -ForegroundColor Green
try {
    $shares = Get-WmiObject -Class Win32_Share -ComputerName $ServerName -Credential $cred | 
              Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '\$$' }
    
    Write-Host "    Found $($shares.Count) shares" -ForegroundColor Gray
} catch {
    Write-Host "    ERROR: Failed to enumerate shares - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Create CIM session for share permissions
Write-Host "    Creating CIM session..." -ForegroundColor Gray
try {
    $cimSession = New-CimSession -ComputerName $ServerName -Credential $cred
} catch {
    Write-Host "    ERROR: Failed to create CIM session - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$shareCount = 0
$totalShares = $shares.Count

# Process each share
Write-Host "[3/4] Processing share permissions..." -ForegroundColor Green
foreach ($share in $shares) {
    $shareCount++
    $shareName = $share.Name
    $sharePath = $share.Path
    $uncPath = "\\$ServerName\$shareName"
    
    Write-Host "    [$shareCount/$totalShares] Processing share: $shareName" -ForegroundColor Gray
    
    # Escape for Cypher - do it RIGHT HERE inline
    $safeShareName = $shareName.Replace('\', '\\').Replace('"', '\"')
    $safeSharePath = $sharePath.Replace('\', '\\').Replace('"', '\"')
    $safeUncPath = $uncPath.Replace('\', '\\').Replace('"', '\"')
    
    # Create Share node and link to Server
    $shareCypher = @"
// ============================================
// SHARE: $shareName
// ============================================
MERGE (share:Share {name: "$safeShareName", server: "$ServerName"})
ON CREATE SET
    share.path = "$safeSharePath",
    share.uncPath = "$safeUncPath",
    share.created = datetime()
ON MATCH SET share.lastScanned = datetime();

MATCH (server:Server {name: "$ServerName"})
MATCH (share:Share {name: "$safeShareName", server: "$ServerName"})
MERGE (server)-[:HOSTS]->(share);
"@
    
    Write-CypherCode -cypher $shareCypher
    
    # Get share-level permissions using CIM
    try {
        $shareAccess = Get-SmbShareAccess -Name $shareName -CimSession $cimSession -ErrorAction Stop
        
        foreach ($perm in $shareAccess) {
            $accountName = $perm.AccountName
            $accountInfo = Get-AccountInfo -identityReference $accountName
            $accountType = Get-AccountType -samAccountName $accountInfo.SamAccountName -domain $accountInfo.Domain
            
            $permissionString = $perm.AccessRight.ToString()
            $accessType = $perm.AccessControlType.ToString()
            
            # Escape inline
            $safeSamAccountName = $accountInfo.SamAccountName.Replace('\', '\\').Replace('"', '\"')
            $safeDomain = $accountInfo.Domain.Replace('\', '\\').Replace('"', '\"')
            $safeFullName = $accountInfo.FullName.Replace('\', '\\').Replace('"', '\"')
            
            # Create User/Group node and relationship
            $principalCypher = @"
// Share Permission: $accountName -> $shareName
MERGE (principal:$accountType {samAccountName: "$safeSamAccountName"})
ON CREATE SET
    principal.domain = "$safeDomain",
    principal.fullName = "$safeFullName",
    principal.created = datetime();

MATCH (principal:$accountType {samAccountName: "$safeSamAccountName"})
MATCH (share:Share {name: "$safeShareName", server: "$ServerName"})
MERGE (principal)-[r:HAS_SHARE_ACCESS]->(share)
ON CREATE SET
    r.permissions = "$permissionString",
    r.accessType = "$accessType",
    r.discovered = datetime()
ON MATCH SET
    r.permissions = "$permissionString",
    r.accessType = "$accessType",
    r.lastSeen = datetime();
"@
            
            Write-CypherCode -cypher $principalCypher
        }
    } catch {
        Write-Host "      WARNING: Could not retrieve share permissions for $shareName - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Process NTFS permissions for top-level folders
Write-Host "[4/4] Processing NTFS permissions for top-level folders..." -ForegroundColor Green
$folderCount = 0

foreach ($share in $shares) {
    $shareName = $share.Name
    $uncPath = "\\$ServerName\$shareName"
    $sharePath = $share.Path
    
    Write-Host "    Processing share: $shareName" -ForegroundColor Gray
    
    try {
        # Remote script that extracts all ACL info before returning
        $remoteScript = {
            param($sharePath, $shareName)
            
            # Create a result object that we'll always return
            $result = [PSCustomObject]@{
                Success = $false
                ShareError = $null
                Folders = @()
            }
            
            try {
                # Check if path exists
                if (-not (Test-Path -Path $sharePath)) {
                    $result.ShareError = "Path does not exist: $sharePath"
                    return $result
                }
                
                # Try to get folders
                $topFolders = Get-ChildItem -Path $sharePath -Directory -ErrorAction Stop
                
                if (-not $topFolders) {
                    $result.Success = $true
                    $result.ShareError = "No folders found in share"
                    return $result
                }
                
                foreach ($folder in $topFolders) {
                    $folderInfo = [PSCustomObject]@{
                        Name = $folder.Name
                        FullName = $folder.FullName
                        Permissions = @()
                        Error = $null
                    }
                    
                    try {
                        $acl = Get-Acl -Path $folder.FullName -ErrorAction Stop
                        
                        # Extract all ACL information into serializable format
                        foreach ($access in $acl.Access) {
                            $permissionInfo = [PSCustomObject]@{
                                IdentityReference = $access.IdentityReference.Value
                                FileSystemRights = $access.FileSystemRights.ToString()
                                AccessControlType = $access.AccessControlType.ToString()
                                IsInherited = $access.IsInherited
                                InheritanceFlags = $access.InheritanceFlags.ToString()
                                PropagationFlags = $access.PropagationFlags.ToString()
                            }
                            $folderInfo.Permissions += $permissionInfo
                        }
                    } catch {
                        $folderInfo.Error = $_.Exception.Message
                    }
                    
                    $result.Folders += $folderInfo
                }
                
                $result.Success = $true
                
            } catch {
                $result.ShareError = $_.Exception.Message
            }
            
            return $result
        }
        
        $remoteResult = Invoke-Command -ComputerName $ServerName -Credential $cred -ScriptBlock $remoteScript -ArgumentList $sharePath, $shareName -ErrorAction Stop
        
        # Check the result structure
        if (-not $remoteResult) {
            Write-Host "      WARNING: No result returned from remote command for share $shareName" -ForegroundColor Yellow
            continue
        }
        
        if ($remoteResult.ShareError) {
            Write-Host "      INFO: $($remoteResult.ShareError)" -ForegroundColor Gray
            continue
        }
        
        if (-not $remoteResult.Success) {
            Write-Host "      WARNING: Remote command failed for share $shareName" -ForegroundColor Yellow
            continue
        }
        
        $remoteFolders = $remoteResult.Folders
        
        if (-not $remoteFolders -or $remoteFolders.Count -eq 0) {
            continue
        }
        
        Write-Host "      Found $($remoteFolders.Count) folders" -ForegroundColor Gray
        
        foreach ($folderInfo in $remoteFolders) {
            $folderCount++
            $folderName = $folderInfo.Name
            $folderFullPath = "$uncPath\$folderName"
            
            # Escape inline
            $safeFolderName = $folderName.Replace('\', '\\').Replace('"', '\"')
            $safeFolderPath = $folderFullPath.Replace('\', '\\').Replace('"', '\"')
            $safeShareName = $shareName.Replace('\', '\\').Replace('"', '\"')
            
            # Create Folder node
            $folderCypher = @"
// ============================================
// FOLDER: $folderName in share $shareName
// ============================================
MERGE (folder:Folder {path: "$safeFolderPath"})
ON CREATE SET
    folder.name = "$safeFolderName",
    folder.share = "$safeShareName",
    folder.server = "$ServerName",
    folder.created = datetime()
ON MATCH SET folder.lastScanned = datetime();

MATCH (share:Share {name: "$safeShareName", server: "$ServerName"})
MATCH (folder:Folder {path: "$safeFolderPath"})
MERGE (share)-[:CONTAINS]->(folder);
"@
            
            Write-CypherCode -cypher $folderCypher
            
            # Process NTFS permissions
            if ($folderInfo.Permissions -and $folderInfo.Permissions.Count -gt 0) {
                foreach ($permission in $folderInfo.Permissions) {
                    $accountInfo = Get-AccountInfo -identityReference $permission.IdentityReference
                    $accountType = Get-AccountType -samAccountName $accountInfo.SamAccountName -domain $accountInfo.Domain
                    
                    $rights = $permission.FileSystemRights
                    $accessType = $permission.AccessControlType
                    $isInherited = $permission.IsInherited
                    
                    # Escape inline
                    $safeSamAccountName = $accountInfo.SamAccountName.Replace('\', '\\').Replace('"', '\"')
                    $safeDomain = $accountInfo.Domain.Replace('\', '\\').Replace('"', '\"')
                    $safeFullName = $accountInfo.FullName.Replace('\', '\\').Replace('"', '\"')
                    $safeRights = $rights.Replace('\', '\\').Replace('"', '\"')
                    
                    # Create User/Group node and relationship
                    $ntfsCypher = @"
// NTFS Permission: $($accountInfo.FullName) -> $folderName
MERGE (principal:$accountType {samAccountName: "$safeSamAccountName"})
ON CREATE SET
    principal.domain = "$safeDomain",
    principal.fullName = "$safeFullName",
    principal.created = datetime();

MATCH (principal:$accountType {samAccountName: "$safeSamAccountName"})
MATCH (folder:Folder {path: "$safeFolderPath"})
MERGE (principal)-[r:HAS_NTFS_ACCESS]->(folder)
ON CREATE SET
    r.permissions = "$safeRights",
    r.accessType = "$accessType",
    r.isInherited = $($isInherited.ToString().ToLower()),
    r.discovered = datetime()
ON MATCH SET
    r.permissions = "$safeRights",
    r.accessType = "$accessType",
    r.isInherited = $($isInherited.ToString().ToLower()),
    r.lastSeen = datetime();
"@
                    
                    Write-CypherCode -cypher $ntfsCypher
                }
            }
        }
        
    } catch {
        Write-Host "      WARNING: Could not process share $shareName - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Clean up CIM session
Remove-CimSession -CimSession $cimSession

Write-Host "`n=== Enumeration Complete ===" -ForegroundColor Cyan
Write-Host "Processed:" -ForegroundColor Yellow
Write-Host "  - 1 Server" -ForegroundColor Gray
Write-Host "  - $totalShares Shares" -ForegroundColor Gray
Write-Host "  - $folderCount Top-level Folders" -ForegroundColor Gray
Write-Host "`nCypher output saved to: $OutputFile" -ForegroundColor Green
Write-Host "`nYou can now import this file into your graph database.`n" -ForegroundColor Cyan
