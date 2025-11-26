Write-Host "Test 1: Scan without fail condition (should exit 0)"
python scanner.py scan ubuntu:20.04 -o terminal
$code1 = $LASTEXITCODE
Write-Host "Exit code: $code1`n"

Write-Host "Test 2: Scan with --fail-threshold 1 (should exit 2 if vuln >= 1)"
python scanner.py scan ubuntu:20.04 -o terminal --fail-threshold 1
$code2 = $LASTEXITCODE
Write-Host "Exit code: $code2`n"

Write-Host "Test 3: Scan with --fail-severity CRITICAL (should exit 2 if any CRITICAL found)"
python scanner.py scan ubuntu:20.04 -o terminal --fail-severity CRITICAL
$code3 = $LASTEXITCODE
Write-Host "Exit code: $code3`n"

Write-Host "Test 4: Scan with --fail-severity HIGH (should exit 2 if HIGH or CRITICAL found)"
python scanner.py scan ubuntu:20.04 -o terminal --fail-severity HIGH
$code4 = $LASTEXITCODE
Write-Host "Exit code: $code4`n"

Write-Host "Test 5: Scan with -s MEDIUM (filter) + --fail-threshold 0 (should exit 0, no fail)"
python scanner.py scan ubuntu:20.04 -o terminal -s MEDIUM --fail-threshold 0
$code5 = $LASTEXITCODE
Write-Host "Exit code: $code5`n"