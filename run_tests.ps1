# Runs every test in the project with one command:
#
#   powershell -ExecutionPolicy Bypass -File .\run_tests.ps1
#
# Every test ends as PASS or FAIL. Anything that cannot run yet (the
# encryption code does not exist, Java is missing, no device) counts as FAIL.
#
# Steps:
#   1. Unit + widget tests (test/).
#   2. Encryption tests (test/crypto_test.dart).
#   3. Starts the Android emulator (window visible) if no Android device is
#      connected, and shuts it down again at the end.
#   4. Starts the Firebase emulators, runs integration_test/, then stops them.
#      Never touches the real database.
#
# Option: -UnitOnly   run only steps 1-2 (no emulators).

param([switch]$UnitOnly)

$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
# Pick up tools installed after this terminal was opened (e.g. Java).
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path', 'User')

$results = [ordered]@{}

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

function Fail($text) {
    Write-Host "  FAIL  $text" -ForegroundColor Red
    return "FAILED - $text"
}

# Runs a test command with the JSON reporter and prints one PASS/FAIL line
# per test. Returns 'PASSED (n tests)' or 'FAILED (x of n tests)'.
function Invoke-Tests([scriptblock]$command) {
    $names = @{}
    $errors = @{}
    $other = New-Object System.Collections.Generic.List[string]
    $stats = @{ pass = 0; fail = 0 }

    & $command | ForEach-Object {
        $line = "$_"
        $e = $null
        if ($line.StartsWith('{')) { try { $e = $line | ConvertFrom-Json } catch {} }
        if (-not $e) { $other.Add($line); return }

        switch ($e.type) {
            'testStart' { $names[$e.test.id] = $e.test.name }
            'error' {
                if (-not $errors.ContainsKey($e.testID)) { $errors[$e.testID] = "$($e.error)" }
            }
            'testDone' {
                $name = $names[$e.testID]
                if ($e.result -eq 'success' -and -not $e.skipped) {
                    if (-not $e.hidden) {
                        Write-Host "  PASS  $name" -ForegroundColor Green
                        $stats.pass++
                    }
                }
                else {
                    if ($name -like 'loading *') { $name = "could not load $($name.Substring(8))" }
                    $why = if ($e.skipped) { 'skipped' } else { $errors[$e.testID] }
                    Write-Host "  FAIL  $name" -ForegroundColor Red
                    "$why" -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 3 |
                        ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
                    $stats.fail++
                }
            }
        }
    }
    $exitCode = $LASTEXITCODE

    if ($stats.pass + $stats.fail -eq 0 -or ($exitCode -ne 0 -and $stats.fail -eq 0)) {
        Write-Host '  FAIL  the test run did not finish. Last output:' -ForegroundColor Red
        $other | Select-Object -Last 20 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
        $stats.fail++
    }

    $total = $stats.pass + $stats.fail
    if ($stats.fail -eq 0) { return "PASSED ($total tests)" }
    return "FAILED ($($stats.fail) of $total tests)"
}

# --- 1. Unit + widget tests -------------------------------------------------
Step 'Unit and widget tests'
$unitFiles = Get-ChildItem test -Filter *_test.dart |
    Where-Object { $_.Name -ne 'crypto_test.dart' } |
    ForEach-Object { "test/$($_.Name)" }
$results['Unit and widget tests'] = Invoke-Tests { flutter test @unitFiles -r json }

# --- 2. Encryption tests ----------------------------------------------------
Step 'Encryption tests'
if (-not (Test-Path lib/crypto)) {
    $results['Encryption tests'] = Fail 'lib/crypto/ does not exist yet (encryption not implemented)'
}
else {
    $results['Encryption tests'] = Invoke-Tests { flutter test test/crypto_test.dart -r json }
}

# --- 3 + 4. End-to-end tests --------------------------------------------------
Step 'End-to-end tests'
if ($UnitOnly) {
    Write-Host '  not run (-UnitOnly)' -ForegroundColor Yellow
    $results['End-to-end tests'] = 'NOT RUN (-UnitOnly)'
}
elseif (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    $results['End-to-end tests'] = Fail 'Java is not installed (winget install Microsoft.OpenJDK.21)'
}
else {
    function Get-AndroidDevice {
        $json = (flutter devices --machine 2>$null) -join "`n"
        $start = $json.IndexOf('[')
        if ($start -lt 0) { return $null }
        $devices = $json.Substring($start) | ConvertFrom-Json
        return $devices | Where-Object { $_.targetPlatform -like 'android*' } | Select-Object -First 1
    }

    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME }
           elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
           else { "$env:LOCALAPPDATA\Android\Sdk" }
    $adb = "$sdk\platform-tools\adb.exe"
    $startedEmulator = $false

    $device = Get-AndroidDevice
    if (-not $device) {
        # An emulator that is still booting shows in adb but not in flutter yet.
        $booting = (& $adb devices) -match '^emulator-\d+\s'
        if ($booting) {
            Write-Host '  An emulator is already starting, waiting for it ...'
        }
        else {
            $avd = & "$sdk\emulator\emulator.exe" -list-avds | Select-Object -First 1
            if ($avd) {
                # The emulator window shows, so you can watch the tests drive the app.
                Write-Host "  Starting emulator $avd ..."
                Start-Process "$sdk\emulator\emulator.exe" `
                    -ArgumentList '-avd', $avd, '-no-audio', '-no-boot-anim'
                $startedEmulator = $true
            }
        }

        if ($booting -or $startedEmulator) {
            $deadline = (Get-Date).AddMinutes(4)
            while (-not $device -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 5
                $device = Get-AndroidDevice
            }
            # Visible to flutter is not the same as finished booting.
            while ($device -and (Get-Date) -lt $deadline -and
                   "$(& $adb -s $device.id shell getprop sys.boot_completed)".Trim() -ne '1') {
                Start-Sleep -Seconds 3
            }
        }
    }

    if (-not $device) {
        $msg = if ($booting) {
            'the running emulator never finished booting. Close it (Task Manager > qemu-system-x86_64) and run again'
        } else {
            'no Android device (create an emulator in Android Studio > Device Manager)'
        }
        $results['End-to-end tests'] = Fail $msg
    }
    else {
        Write-Host "  Using $($device.name) ($($device.id)). Building the app takes a few minutes ..."
        $testCmd = "flutter test integration_test -d $($device.id) -r json"
        # emulators:exec starts auth + database, runs the tests, then shuts down.
        $results['End-to-end tests'] = Invoke-Tests {
            firebase emulators:exec --only auth,database --project personalnote-37151 $testCmd
        }
    }

    if ($startedEmulator -and $device) {
        & $adb -s $device.id emu kill | Out-Null
    }
}

# --- Results -----------------------------------------------------------------
Step 'Results'
foreach ($section in $results.Keys) {
    $value = $results[$section]
    $color = if ($value -like 'PASSED*') { 'Green' } elseif ($value -like 'FAILED*') { 'Red' } else { 'Yellow' }
    Write-Host ('  {0,-24}{1}' -f $section, $value) -ForegroundColor $color
}
if ($results.Values | Where-Object { $_ -like 'FAILED*' }) {
    Write-Host "`nOVERALL: FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "`nOVERALL: PASSED" -ForegroundColor Green
exit 0
