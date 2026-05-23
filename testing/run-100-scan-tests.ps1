param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$TestCasesPath = "$PSScriptRoot\test-cases-100.csv",
    [string]$OutputDirectory = "$PSScriptRoot\results"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $TestCasesPath)) {
    throw "Test case file not found: $TestCasesPath"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$testCases = Import-Csv -LiteralPath $TestCasesPath
$totalCases = @($testCases).Count
$caseNumber = 0
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputPath = Join-Path $OutputDirectory "scan-results-$timestamp.csv"

Write-Host "Running $totalCases scan tests against $BaseUrl ..."
Write-Host "Results will be saved to: $outputPath"

$results = foreach ($testCase in $testCases) {
    $caseNumber += 1
    $percentComplete = if ($totalCases -gt 0) { [math]::Round(($caseNumber / $totalCases) * 100, 0) } else { 0 }

    Write-Progress `
        -Activity "Ni Scam Ke? 100-case scan test" `
        -Status "Case $caseNumber/$totalCases: $($testCase.url)" `
        -PercentComplete $percentComplete

    Write-Host "[$caseNumber/$totalCases] Testing $($testCase.url)"

    $body = @{
        url = $testCase.url
        pageText = $testCase.pageText
        clientTimestamp = (Get-Date).ToString("o")
    } | ConvertTo-Json -Depth 4

    try {
        $response = Invoke-RestMethod `
            -Method Post `
            -Uri "$BaseUrl/api/v1/scan-url" `
            -ContentType "application/json" `
            -Body $body

        $actualDecision = [string]$response.decision
        $isCorrect = $actualDecision -eq $testCase.expectedDecision

        [pscustomobject]@{
            id = $testCase.id
            expectedDecision = $testCase.expectedDecision
            actualDecision = $actualDecision
            correct = $isCorrect
            riskScore = $response.riskScore
            confidence = $response.confidence
            reasons = ($response.reasons -join " | ")
            evidenceSources = $response.evidenceSources
            url = $testCase.url
            notes = $testCase.notes
            error = ""
        }
    }
    catch {
        [pscustomobject]@{
            id = $testCase.id
            expectedDecision = $testCase.expectedDecision
            actualDecision = "ERROR"
            correct = $false
            riskScore = ""
            confidence = ""
            reasons = ""
            evidenceSources = ""
            url = $testCase.url
            notes = $testCase.notes
            error = $_.Exception.Message
        }
    }
}

Write-Progress -Activity "Ni Scam Ke? 100-case scan test" -Completed

$results | Export-Csv -NoTypeInformation -LiteralPath $outputPath

$total = @($results).Count
$correct = @($results | Where-Object { $_.correct -eq $true }).Count
$accuracy = if ($total -gt 0) { [math]::Round(($correct / $total) * 100, 2) } else { 0 }

$truePositive = @($results | Where-Object { $_.expectedDecision -eq "BLOCK" -and $_.actualDecision -eq "BLOCK" }).Count
$trueNegative = @($results | Where-Object { $_.expectedDecision -eq "ALLOW" -and $_.actualDecision -eq "ALLOW" }).Count
$falsePositive = @($results | Where-Object { $_.expectedDecision -eq "ALLOW" -and $_.actualDecision -eq "BLOCK" }).Count
$falseNegative = @($results | Where-Object { $_.expectedDecision -eq "BLOCK" -and $_.actualDecision -ne "BLOCK" }).Count

Write-Host "Saved results: $outputPath"
Write-Host "Total: $total"
Write-Host "Correct: $correct"
Write-Host "Accuracy: $accuracy%"
Write-Host "True Positive (scam blocked): $truePositive"
Write-Host "True Negative (safe allowed): $trueNegative"
Write-Host "False Positive (safe blocked): $falsePositive"
Write-Host "False Negative (scam missed): $falseNegative"
