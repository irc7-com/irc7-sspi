param(
    [Parameter(Mandatory=$true)]
    [string]$RID,
    [Parameter(Mandatory=$true)]
    [string]$Binary
)
$StagingDir = "staging/$RID"
New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null
Copy-Item "target/release/$Binary" "$StagingDir/$Binary"
Write-Host "Staged $Binary to $StagingDir"
