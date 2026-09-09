<#
.obsidian/ seeding for a net-new vault.

Each file is written only when absent (Obsidian rewrites these itself) unless -Force. community-plugins.json
is never overwritten. Property types are global by name in Obsidian, so types.json pins every frontmatter
property the templates emit (a "Never"/null slipping into a datetime property would flip its type vault-wide).

Install-FsObsidianPlugin is an opt-in network helper (Dataview) and is never exercised by tests.
#>

$script:FsDataviewVersion = '0.5.68'   # latest non-beta Dataview release (2025-03-15); 0.5.70 is titled Beta on GitHub
$script:FsDataviewRepository = 'blacksmithgu/obsidian-dataview'

$script:FsObsidianGraphFilter = '-path:Folders/ -path:WellKnown/ -path:Effective/ -path:Reports/ -path:_meta/ -tag:#large-group'

# Graph colour groups, tag-first so entity state wins over location. Obsidian keeps the FIRST matching group.
$script:FsObsidianColorGroups = @(
    @{ query = 'tag:#orphaned'; rgb = @(255, 0, 255) }        # magenta
    @{ query = 'tag:#disabled'; rgb = @(128, 128, 128) }      # gray
    @{ query = 'tag:#changed'; rgb = @(255, 140, 0) }         # dark orange
    @{ query = 'tag:#local-group'; rgb = @(135, 206, 250) }   # light blue
    @{ query = 'path:WellKnown/'; rgb = @(155, 89, 182) }     # purple
    @{ query = 'path:Servers/'; rgb = @(220, 53, 69) }        # red
    @{ query = 'path:Shares/'; rgb = @(255, 165, 0) }         # orange
    @{ query = 'path:Folders/'; rgb = @(255, 215, 0) }        # yellow
    @{ query = 'path:Groups/'; rgb = @(52, 120, 246) }        # blue
    @{ query = 'path:Users/'; rgb = @(76, 175, 80) }          # green
    @{ query = 'path:Reports/'; rgb = @(0, 150, 136) }        # teal
)

# Frontmatter property -> Obsidian property type. Keep in sync with the templates.
$script:FsObsidianPropertyTypes = [ordered]@{
    aliases          = 'aliases'
    cssclasses       = 'multitext'
    tags             = 'tags'
    type             = 'text'
    generated        = 'checkbox'
    id               = 'text'
    # user
    samAccountName   = 'text'
    domain           = 'text'
    displayName      = 'text'
    upn              = 'text'
    mail             = 'text'
    enabled          = 'checkbox'
    lastLogon        = 'datetime'
    pwdLastSet       = 'datetime'
    whenCreated      = 'datetime'
    accountExpires   = 'datetime'
    neverLoggedOn    = 'checkbox'
    department       = 'text'
    title            = 'text'
    description      = 'text'
    manager          = 'text'
    memberOf         = 'multitext'
    directAceCount   = 'number'
    groupCount       = 'number'
    resourceCount    = 'number'
    # group
    groupScope       = 'text'
    groupCategory    = 'text'
    managedBy        = 'text'
    memberCount      = 'number'
    nestingDepth     = 'number'
    grantCount       = 'number'
    # share
    server           = 'text'
    shareName        = 'text'
    localPath        = 'text'
    uncPath          = 'text'
    owner            = 'text'
    protected        = 'checkbox'
    folderCount      = 'number'
    shareAceCount    = 'number'
    ntfsAceCount     = 'number'
    # folder
    share            = 'text'
    parent           = 'text'
    parentPath       = 'text'
    depth            = 'number'
    aceCount         = 'number'
    denyCount        = 'number'
    explicitAceCount = 'number'
    # report / server / home
    report           = 'text'
    severity         = 'text'
    rows             = 'number'
    servers          = 'multitext'
    scanIds          = 'multitext'
    generatedAt      = 'datetime'
    lastScanned      = 'datetime'
    scanId           = 'text'
    fqdn             = 'text'
    shareCount       = 'number'
    errorCount       = 'number'
    snapshotCount    = 'number'
}

function ConvertTo-FsGraphColor {
    <# Obsidian graph colour object from RGB components: { a: 1, rgb: <decimal 0xRRGGBB> }. #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [int] $R, [Parameter(Mandatory)] [int] $G, [Parameter(Mandatory)] [int] $B)
    return [ordered]@{ a = 1; rgb = (($R -band 0xFF) * 65536 + ($G -band 0xFF) * 256 + ($B -band 0xFF)) }
}

function Get-FsObsidianAppConfig {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    return [ordered]@{
        defaultViewMode       = 'preview'
        newLinkFormat         = 'absolute'
        useMarkdownLinks      = $false
        alwaysUpdateLinks     = $false
        showUnsupportedFiles  = $true
        attachmentFolderPath  = 'Notes/attachments'
        newFileLocation       = 'folder'
        newFileFolderPath     = 'Notes'
        userIgnoreFilters     = @('_meta/')
        readableLineLength    = $false
        strictLineBreaks      = $false
        showFrontmatter       = $false
        propertiesInDocument  = 'visible'
    }
}

function Get-FsObsidianGraphConfig {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    $groups = foreach ($g in $script:FsObsidianColorGroups) {
        [ordered]@{ query = $g.query; color = (ConvertTo-FsGraphColor -R $g.rgb[0] -G $g.rgb[1] -B $g.rgb[2]) }
    }
    return [ordered]@{
        'collapse-filter'       = $false
        search                  = $script:FsObsidianGraphFilter
        showTags                = $false
        showAttachments         = $false
        hideUnresolved          = $true
        showOrphans             = $false
        'collapse-color-groups' = $false
        colorGroups             = @($groups)
        'collapse-display'      = $true
        showArrow               = $true
        textFadeMultiplier      = 0
        nodeSizeMultiplier      = 1
        lineSizeMultiplier      = 1
        'collapse-forces'       = $true
        centerStrength          = 0.5
        repelStrength           = 12
        linkStrength            = 1
        linkDistance            = 250
        scale                   = 0.5
        close                   = $false
    }
}

function Get-FsObsidianTypesConfig {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    return [ordered]@{ types = $script:FsObsidianPropertyTypes }
}

function Get-FsObsidianCorePluginsConfig {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    $enabled = @('file-explorer', 'global-search', 'switcher', 'graph', 'backlink', 'canvas', 'outgoing-link', 'tag-pane',
        'properties', 'page-preview', 'bookmarks', 'outline', 'word-count', 'file-recovery', 'bases', 'command-palette')
    $all = @('file-explorer', 'global-search', 'switcher', 'graph', 'backlink', 'canvas', 'outgoing-link', 'tag-pane', 'footnotes',
        'properties', 'page-preview', 'daily-notes', 'templates', 'note-composer', 'command-palette', 'slash-command', 'editor-status',
        'bookmarks', 'markdown-importer', 'zk-prefixer', 'random-note', 'outline', 'word-count', 'slides', 'audio-recorder',
        'workspaces', 'file-recovery', 'publish', 'sync', 'bases', 'webviewer')
    $cfg = [ordered]@{}
    foreach ($p in $all) { $cfg[$p] = ($enabled -contains $p) }
    return $cfg
}

function Get-FsObsidianWorkspaceConfig {
    <# One markdown leaf on Home.md (preview), file-explorer/search/bookmarks left, backlink/outgoing/tag/outline/properties right. #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $HomeFile = 'Home.md')
    $wid = { param($k) Get-FsHexHash -Text ('fsperm:workspace:' + $k) -Length 16 }
    $leaf = {
        param($key, $type, $state, $icon, $title)
        [ordered]@{ id = (& $wid $key); type = 'leaf'; state = [ordered]@{ type = $type; state = $state; icon = $icon; title = $title } }
    }
    $mainLeaf = & $leaf 'main-leaf' 'markdown' ([ordered]@{ file = $HomeFile; mode = 'preview'; source = $false; backlinks = $false }) 'lucide-file' 'Home'
    return [ordered]@{
        main          = [ordered]@{
            id        = (& $wid 'main')
            type      = 'split'
            children  = @([ordered]@{ id = (& $wid 'main-tabs'); type = 'tabs'; children = @($mainLeaf) })
            direction = 'vertical'
        }
        left          = [ordered]@{
            id        = (& $wid 'left')
            type      = 'split'
            children  = @([ordered]@{
                    id       = (& $wid 'left-tabs'); type = 'tabs'
                    children = @(
                        (& $leaf 'left-files' 'file-explorer' ([ordered]@{ sortOrder = 'alphabetical'; autoReveal = $true; showSearch = $false; searchQuery = '' }) 'lucide-folder-closed' 'Files'),
                        (& $leaf 'left-search' 'search' ([ordered]@{ query = ''; matchingCase = $false; explainSearch = $false; collapseAll = $false; extraContext = $false; sortOrder = 'alphabetical' }) 'lucide-search' 'Search'),
                        (& $leaf 'left-bookmarks' 'bookmarks' ([ordered]@{ showSearch = $false; searchQuery = '' }) 'lucide-bookmark' 'Bookmarks')
                    )
                })
            direction = 'horizontal'
            width     = 300
        }
        right         = [ordered]@{
            id        = (& $wid 'right')
            type      = 'split'
            children  = @([ordered]@{
                    id       = (& $wid 'right-tabs'); type = 'tabs'
                    children = @(
                        (& $leaf 'right-backlink' 'backlink' ([ordered]@{ file = $HomeFile; collapseAll = $false; extraContext = $false; sortOrder = 'alphabetical'; showSearch = $false; searchQuery = ''; backlinkCollapsed = $false; unlinkedCollapsed = $true }) 'links-coming-in' 'Backlinks'),
                        (& $leaf 'right-outgoing' 'outgoing-link' ([ordered]@{ file = $HomeFile; linksCollapsed = $false; unlinkedCollapsed = $true }) 'links-going-out' 'Outgoing links'),
                        (& $leaf 'right-tags' 'tag' ([ordered]@{ sortOrder = 'alphabetical'; useHierarchy = $true; showSearch = $false; searchQuery = '' }) 'lucide-tags' 'Tags'),
                        (& $leaf 'right-outline' 'outline' ([ordered]@{ file = $HomeFile; followCursor = $false; showSearch = $false; searchQuery = '' }) 'lucide-list' 'Outline'),
                        (& $leaf 'right-properties' 'all-properties' ([ordered]@{ sortOrder = 'frequency'; showSearch = $false; searchQuery = '' }) 'lucide-archive' 'All properties')
                    )
                    currentTab = 0
                })
            direction = 'horizontal'
            width     = 360
        }
        'left-ribbon' = [ordered]@{ hiddenItems = [ordered]@{} }
        active        = $mainLeaf.id
        lastOpenFiles = @($HomeFile)
    }
}

function Initialize-FsObsidianConfig {
    <#
    .SYNOPSIS
        Seeds .obsidian/{app,graph,types,core-plugins,workspace}.json (each only when absent unless -Force) and
        community-plugins.json = [] (only when absent). Returns the vault-relative paths written.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $VaultPath,
        [switch] $Force,
        [string] $HomeFile = 'Home.md'
    )
    $files = [ordered]@{
        'app.json'          = (Get-FsObsidianAppConfig)
        'graph.json'        = (Get-FsObsidianGraphConfig)
        'types.json'        = (Get-FsObsidianTypesConfig)
        'core-plugins.json' = (Get-FsObsidianCorePluginsConfig)
        'workspace.json'    = (Get-FsObsidianWorkspaceConfig -HomeFile $HomeFile)
    }
    $written = [System.Collections.Generic.List[string]]::new()
    $dir = Join-Path $VaultPath '.obsidian'
    foreach ($name in $files.Keys) {
        $rel = '.obsidian/' + $name
        $full = Join-Path $dir $name
        if ((Test-Path -LiteralPath $full) -and -not $Force) { continue }
        if ($PSCmdlet.ShouldProcess($rel, 'Write Obsidian config')) {
            Write-FsVaultFile -Root $VaultPath -RelativePath $rel -Content (ConvertTo-FsJsonText -Value $files[$name] -Depth 20) | Out-Null
        }
        $written.Add($rel)
    }
    $community = Join-Path $dir 'community-plugins.json'
    if (-not (Test-Path -LiteralPath $community)) {
        if ($PSCmdlet.ShouldProcess('.obsidian/community-plugins.json', 'Write Obsidian config')) {
            Write-FsVaultFile -Root $VaultPath -RelativePath '.obsidian/community-plugins.json' -Content "[]`n" | Out-Null
        }
        $written.Add('.obsidian/community-plugins.json')
    }
    return [string[]]$written.ToArray()
}

function Install-FsObsidianPlugin {
    <#
    .SYNOPSIS
        NETWORK: downloads a community plugin's release assets (main.js, manifest.json, styles.css) from GitHub into
        .obsidian/plugins/<PluginId>/ and enables it in community-plugins.json. Opt-in; never called by tests.
    .PARAMETER Version
        Release tag to download. Default: the pinned Dataview release ($script:FsDataviewVersion).
    .PARAMETER Repository
        GitHub owner/repo. Default: blacksmithgu/obsidian-dataview.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $VaultPath,
        [string] $PluginId = 'dataview',
        [string] $Version = $script:FsDataviewVersion,
        [string] $Repository = $script:FsDataviewRepository
    )
    $pluginDir = Join-Path (Join-Path (Join-Path $VaultPath '.obsidian') 'plugins') $PluginId
    if (-not (Test-Path -LiteralPath $pluginDir)) { New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null }
    $written = [System.Collections.Generic.List[string]]::new()
    $baseUrl = 'https://github.com/{0}/releases/download/{1}/' -f $Repository, $Version
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('fsperm-plugin-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    try {
        foreach ($asset in 'manifest.json', 'main.js', 'styles.css') {
            $tmp = Join-Path $tmpDir $asset
            try {
                Invoke-WebRequest -Uri ($baseUrl + $asset) -OutFile $tmp -UseBasicParsing -ErrorAction Stop | Out-Null
            }
            catch {
                if ($asset -eq 'styles.css') { Write-Warning "Install-FsObsidianPlugin: no styles.css for $PluginId $Version (optional)."; continue }
                throw "Install-FsObsidianPlugin: download of $asset failed for $Repository $Version : $($_.Exception.Message)"
            }
            if ($asset -eq 'manifest.json') {
                $manifest = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tmp)) -AsHashtable
                if ([string]$manifest['version'] -ne $Version) { throw "Install-FsObsidianPlugin: manifest version '$($manifest['version'])' does not match requested '$Version'." }
                if ([string]$manifest['id'] -ne $PluginId) { throw "Install-FsObsidianPlugin: manifest id '$($manifest['id'])' does not match '$PluginId'." }
            }
        }
        foreach ($asset in 'manifest.json', 'main.js', 'styles.css') {
            $tmp = Join-Path $tmpDir $asset
            if (-not (Test-Path -LiteralPath $tmp)) { continue }
            $rel = '.obsidian/plugins/{0}/{1}' -f $PluginId, $asset
            if ($PSCmdlet.ShouldProcess($rel, 'Install plugin file')) {
                Copy-Item -LiteralPath $tmp -Destination (Join-Path $pluginDir $asset) -Force
            }
            $written.Add($rel)
        }
    }
    finally { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }

    $communityPath = Join-Path (Join-Path $VaultPath '.obsidian') 'community-plugins.json'
    $ids = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $communityPath) {
        try { foreach ($i in @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($communityPath)))) { if ($i) { $ids.Add([string]$i) } } } catch { Write-Warning "Install-FsObsidianPlugin: community-plugins.json unreadable; rewriting." }
    }
    if (-not $ids.Contains($PluginId)) {
        $ids.Add($PluginId)
        if ($PSCmdlet.ShouldProcess('.obsidian/community-plugins.json', 'Enable plugin')) {
            Write-FsVaultFile -Root $VaultPath -RelativePath '.obsidian/community-plugins.json' -Content (ConvertTo-FsJsonText -Value @($ids.ToArray()) -Depth 2) | Out-Null
        }
        $written.Add('.obsidian/community-plugins.json')
    }
    return [string[]]$written.ToArray()
}
