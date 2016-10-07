Write-Host "Creating Dlls..."
gcc -c -o iym-dll.o iym.c -lpsapi
gcc -o iym.dll -s -shared iym-dll.o -lpsapi
Remove-Item iym-dll.o -Force
Write-Host "Packing Dll shell code..."
$dllScode = Get-Content iym.dll -Encoding Byte | ForEach-Object {"\x$($_.ToString("X2"))"}
$dllSbuild = New-Object System.Text.StringBuilder
foreach($dllLine in $dllScode) {$dllSbuild.Append($dllLine) | Out-Null}
$cCode = Get-Content iym.c
$cBuild = New-Object System.Text.StringBuilder
foreach($cLine in $cCode) {$cBuild.Append("$cLine`r`n") | Out-Null}
Set-Content -Path iym-tmp.c -Value $cBuild.toString().Replace("|/|/", $dllSbuild.ToString()).Replace("-123456", $dllSbuild.Length/4)
Write-Host "Creating exe payload"
gcc iym-tmp.c -o iym.exe -lpsapi
Remove-Item iym-tmp.c
Start-Sleep -Seconds 5
