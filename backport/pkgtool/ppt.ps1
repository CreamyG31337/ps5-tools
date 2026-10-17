# Run the ProsperoPkgTool command line that ships, without a launcher, inside PS5 PKG Tool.
#   pwsh ppt.ps1 img_file_list <package.pkg>
#   pwsh ppt.ps1 img_extract <package.pkg[:/uroot/inner/path]> <out>
# Set up once with unbundle.py (see README.md): it fills .\unbundled\ next to this script.
$dir = Join-Path $PSScriptRoot 'unbundled'
if (-not (Test-Path (Join-Path $dir 'ProsperoPkgTool.dll'))) {
    Write-Error "ProsperoPkgTool.dll not found in $dir; run unbundle.py first (see README.md)"
    exit 2
}
$env:PATH = "$dir;$env:PATH"   # oo2core_9_win64.dll, the Kraken decoder
[AppDomain]::CurrentDomain.add_AssemblyResolve({
    param($s, $e)
    $p = Join-Path $dir (($e.Name -split ',')[0] + '.dll')
    if (Test-Path $p) { [Reflection.Assembly]::LoadFrom($p) } else { $null }
})
$asm = [Reflection.Assembly]::LoadFrom((Join-Path $dir 'ProsperoPkgTool.dll'))
$t = $asm.GetType('ProsperoPkgTool.CliApplication', $true)
$m = $t.GetMethod('RunAsync')
$target = if ($m.IsStatic) { $null } else { [Activator]::CreateInstance($t, $true) }
$task = $m.Invoke($target, @([string[]]$args, [Threading.CancellationToken]::None))
exit $task.GetAwaiter().GetResult()
