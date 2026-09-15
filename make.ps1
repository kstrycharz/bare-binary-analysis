<#
.SYNOPSIS
  Windows task runner. Mirrors the Makefile targets one-for-one.

.DESCRIPTION
  GNU make is not present on a default Windows install, and the project has to
  be developable there — the artifacts BARE analyses are mostly Windows
  binaries, so a Windows dev box is a first-class environment, not an
  afterthought.

  Every target here must match the Makefile target of the same name. If you add
  one there, add it here.

.EXAMPLE
  ./make.ps1 test
  ./make.ps1 sandbox-check
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target = 'help',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$RunRoot = if ($env:BARE_RUN_ROOT_HOST) { $env:BARE_RUN_ROOT_HOST }
           else { Join-Path $PSScriptRoot 'var\runs' }

$ComposeDev = @('compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    Write-Host "> $Exe $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe exited with $LASTEXITCODE" }
}

function Invoke-Uv { param([string[]]$Arguments) Invoke-Checked 'uv' (@('run') + $Arguments) }
function Invoke-Docker { param([string[]]$Arguments) Invoke-Checked 'docker' $Arguments }

function Get-AnalyzerTag {
    # Mirrors the Makefile's `BARE_ANALYZER_TAG ?= dev`, so the two build
    # entry points cannot drift. An exported-but-empty variable falls back to
    # the default rather than producing `bare/static:`, which the daemon
    # would reject with an error that says nothing about the cause.
    $tag = $env:BARE_ANALYZER_TAG
    if ([string]::IsNullOrWhiteSpace($tag)) { return 'dev' }
    return $tag.Trim()
}

function Build-Analyzer {
    # Compose owns the build context and dockerfile; this only has to make sure
    # the tag Compose sees is the one Get-AnalyzerTag resolved, including the
    # empty-string case that Compose's own `:-` default would not catch.
    param([string]$Service)
    $env:BARE_ANALYZER_TAG = Get-AnalyzerTag
    Invoke-Docker @('compose', 'build', $Service)
}

function Initialize-RunRoot {
    if (-not (Test-Path $RunRoot)) { New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null }
    # _HOST is the path the Docker daemon resolves; the plain variable is the
    # path inside the worker container. See docs/SETUP.md section 2.
    $env:BARE_RUN_ROOT_HOST = $RunRoot
    $env:BARE_RUN_ROOT = $RunRoot
    Write-Host "run root (host): $RunRoot" -ForegroundColor DarkGray
}

$Targets = [ordered]@{
    'install'          = { Invoke-Checked 'uv' @('sync', '--extra', 'dev') }
    'run-root'         = { Initialize-RunRoot }

    'dev'              = { Initialize-RunRoot; Invoke-Docker ($ComposeDev + @('up', '--build')) }
    'dev-detached'     = { Initialize-RunRoot; Invoke-Docker ($ComposeDev + @('up', '--build', '-d')) }
    'down'             = { Invoke-Docker ($ComposeDev + @('down', '--remove-orphans')) }
    'clean'            = { Invoke-Docker ($ComposeDev + @('down', '--remove-orphans', '--volumes')) }
    'logs'             = { Invoke-Docker ($ComposeDev + @('logs', '-f')) }

    'images'           = { & $PSCommandPath 'image-hello'; & $PSCommandPath 'image-static'; & $PSCommandPath 'image-unpack'; & $PSCommandPath 'image-ghidra' }
    # Delegated to Compose so each analyzer's build context and dockerfile are
    # defined in docker-compose.yml only; `docker compose up` builds all four.
    # The tag is passed through rather than baked into a -t, so Compose's
    # ${BARE_ANALYZER_TAG:-dev} resolves to the same value Get-AnalyzerTag
    # would have produced.
    'image-hello'      = { Build-Analyzer 'analyzer-hello' }
    'image-static'     = { Build-Analyzer 'analyzer-static' }
    'image-unpack'     = { Build-Analyzer 'analyzer-unpack' }
    'image-ghidra'     = { Build-Analyzer 'analyzer-ghidra' }
    'refresh-digests'  = {
        foreach ($image in @('python:3.12-slim-bookworm')) {
            Invoke-Docker @('pull', '-q', $image)
            $digest = & docker inspect --format '{{index .RepoDigests 0}}' $image
            '{0,-32} {1}' -f $image, $digest
        }
    }

    'test'             = { Invoke-Uv @('pytest', 'tests/unit', '-v') }
    'test-integration' = { Invoke-Uv @('pytest', 'tests/integration', '-v', '-m', 'integration') }
    'test-all'         = { Invoke-Uv @('pytest', '-v') }
    'lint'             = { Invoke-Uv @('ruff', 'check', '.'); Invoke-Uv @('ruff', 'format', '--check', '.') }
    'format'           = { Invoke-Uv @('ruff', 'format', '.'); Invoke-Uv @('ruff', 'check', '--fix', '.') }
    'typecheck'        = { Invoke-Uv @('mypy') }
    'secrets'          = {
        Invoke-Docker @('run', '--rm', '-v', "${PSScriptRoot}:/repo",
                        'zricethezav/gitleaks:latest', 'detect', '--source', '/repo', '--redact')
    }
    'check'            = { & $PSCommandPath 'lint'; & $PSCommandPath 'typecheck'; & $PSCommandPath 'test' }

    'sandbox-check'    = {
        & $PSCommandPath 'image-hello'
        Initialize-RunRoot
        Invoke-Uv @('bare', 'sandbox', 'health')
        Invoke-Uv @('bare', 'sandbox', 'hello')
    }

    'corpus'           = { Invoke-Uv @('python', 'tests/corpus/build_corpus.py') }
    'demo'             = {
        & $PSCommandPath 'images'
        & $PSCommandPath 'corpus'
        Initialize-RunRoot
        Invoke-Docker ($ComposeDev + @('up', '-d', '--build'))
        Invoke-Uv @('python', 'scripts/demo.py')
    }
    'screenshots'      = {
        & $PSCommandPath 'corpus'
        Invoke-Uv @('playwright', 'install', 'chromium')
        Invoke-Uv @('python', 'scripts/screenshots.py')
    }
    'airgap-bundle'    = { throw 'make airgap-bundle is not implemented yet; scheduled for M6 (see CLAUDE.md)' }
}

if ($Target -in @('help', '--help', '-h', '--list')) {
    Write-Host 'BARE targets:' -ForegroundColor Cyan
    $Targets.Keys | ForEach-Object { "  $_" }
    exit 0
}

if (-not $Targets.Contains($Target)) {
    Write-Error "unknown target '$Target'. Run ./make.ps1 help for the list."
    exit 1
}

& $Targets[$Target]
