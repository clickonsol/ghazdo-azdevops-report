param(
    [string]$pat = ${env:MAPPED_ADO_PAT},
    [string]$orgUri = ${env:SYSTEM_COLLECTIONURI},
    [string]$project = ${env:SYSTEM_TEAMPROJECT},
    [string]$repository = ${env:BUILD_REPOSITORY_NAME},
    [string]$reportName = "ghazdo-summary-report-${env:BUILD_BUILDNUMBER}.csv",
    [ValidateSet("organization", "project", "repository")]
    [string]$scope = "organization"
)

# Enable verbose output
$VerbosePreference = "Continue"

if ([string]::IsNullOrEmpty($pat)) {
    throw "The `pat` parameter must be set or the `MAPPED_ADO_PAT` environment variable must be set."
}

$orgName = $orgUri -replace "^https://dev.azure.com/|/$"
$headers = @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($pat.Contains(":") ? $pat : ":$pat"))))" }
$isAzDO = $env:TF_BUILD -eq "True"

# Report Configuration
$severities = @("critical", "high", "medium", "low")
$maxAlertsPerRepo = 10000

Write-Verbose "Organization: $orgName"
Write-Verbose "Scope: $scope"

# Build the list of repos to scan
$scans = @()
if ($scope -in @("organization", "project")) {
    $projects = if ($scope -eq "organization") {
        $url = "https://dev.azure.com/$orgName/_apis/projects?api-version=6.0"
        Write-Verbose "Fetching projects from: $url"
        $projectsResponse = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -SkipHttpErrorCheck
        if ($projectsResponse.StatusCode -ne 200) {
            Write-Host "❌ - Error $($projectsResponse.StatusCode) $($projectsResponse.StatusDescription) Failed to retrieve projects for org: $orgName with $url"
            Write-Verbose "Response content: $($projectsResponse.Content)"
            throw "Failed to retrieve projects"
        }
        ($projectsResponse.Content | ConvertFrom-Json).value
    }
    elseif ($scope -eq "project") {
        @(@{ name = $project })
    }

    Write-Verbose "Projects to scan: $($projects | ConvertTo-Json -Compress)"

    foreach ($proj in $projects) {
        $url = "https://dev.azure.com/$orgName/$($proj.name)/_apis/git/repositories?api-version=6.0"
        Write-Verbose "Fetching repositories for project $($proj.name) from: $url"
        $reposResponse = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -SkipHttpErrorCheck
        if ($reposResponse.StatusCode -ne 200) {
            Write-Host "❌ - Error $($reposResponse.StatusCode) $($reposResponse.StatusDescription) Failed to retrieve repositories for org: $orgName and project: $($proj.name) with $url"
            Write-Verbose "Response content: $($reposResponse.Content)"
            continue
        }
        $repos = ($reposResponse.Content | ConvertFrom-Json).value
        foreach ($repo in $repos) {
            $scans += @{
                OrgName     = $orgName
                ProjectName = $proj.name
                RepoName    = $repo.name
            }
        }
    }
}
elseif ($scope -eq "repository") {
    $scans += @{
        OrgName     = $orgName
        ProjectName = $project
        RepoName    = $repository
    }
}

Write-Verbose "Scans to perform: $($scans | ConvertTo-Json -Compress)"

# Loop through repo alert list and compile the final report
[System.Collections.ArrayList]$finalReport = @()

foreach ($scan in $scans) {
    $project = $scan.ProjectName
    $repository = $scan.RepoName
    $repoUrl = "https://dev.azure.com/$orgName/$project/_git/$repository"
    
    Write-Verbose "Processing repository: $repository in project: $project"

    # Get the list of branches
    $branchesUrl = "https://dev.azure.com/$orgName/$project/_apis/git/repositories/$repository/refs?filter=refs/heads/&api-version=6.0"
    Write-Verbose "Fetching branches from: $branchesUrl"
    $branchesResponse = Invoke-WebRequest -Uri $branchesUrl -Headers $headers -Method Get -SkipHttpErrorCheck
    if ($branchesResponse.StatusCode -ne 200) {
        Write-Host "❌ - Error $($branchesResponse.StatusCode) $($branchesResponse.StatusDescription) Failed to retrieve branches for repo: $repository"
        Write-Verbose "Response content: $($branchesResponse.Content)"
        continue
    }
    $branches = ($branchesResponse.Content | ConvertFrom-Json).value

    Write-Verbose "Branches found: $($branches | ConvertTo-Json -Compress)"

    foreach ($branch in $branches) {
        $branchName = $branch.name -replace "^refs/heads/", ""
        $branchUrl = "$repoUrl?version=GB$branchName"

        $alertsUrl = "https://advsec.dev.azure.com/$orgName/$project/_apis/alert/repositories/$repository/alerts?top=$maxAlertsPerRepo&`$filter=ref eq '$branchName'&api-version=7.2-preview.1"
        Write-Verbose "Fetching alerts from: $alertsUrl"
        
        try {
            $alertsResponse = Invoke-WebRequest -Uri $alertsUrl -Headers $headers -Method Get -SkipHttpErrorCheck
            if ($alertsResponse.StatusCode -ne 200) {
                $enablementurl = "https://advsec.dev.azure.com/$orgName/$project/_apis/management/repositories/$repository/enablement"
                Write-Verbose "Checking enablement status from: $enablementurl"
                $repoEnablement = Invoke-WebRequest -Uri $enablementurl -Headers $headers -Method Get -SkipHttpErrorCheck
                $enablement = $repoEnablement.content | ConvertFrom-Json

                if (!$enablement.advSecEnabled) {
                    Write-Verbose "Advanced Security not enabled for repository: $repository"
                    $finalReport += [pscustomobject]@{
                        Project        = $project
                        Repo           = $repository
                        RepoUrl        = $repoUrl
                        Branch         = $branchName
                        BranchUrl      = $branchUrl
                        TotalCritical  = 0
                        TotalHigh      = 0
                        TotalMedium    = 0
                        TotalLow       = 0
                        LastCommitter  = "N/A"
                        LastCommitDate = "N/A"
                        AdvSecEnabled  = $false
                    }
                    continue
                }
            }
            $parsedAlerts = $alertsResponse.Content | ConvertFrom-Json

            $totalCritical = ($parsedAlerts.value | Where-Object { $_.severity -eq "critical" }).Count
            $totalHigh = ($parsedAlerts.value | Where-Object { $_.severity -eq "high" }).Count
            $totalMedium = ($parsedAlerts.value | Where-Object { $_.severity -eq "medium" }).Count
            $totalLow = ($parsedAlerts.value | Where-Object { $_.severity -eq "low" }).Count

            Write-Verbose "Alerts found - Critical: $totalCritical, High: $totalHigh, Medium: $totalMedium, Low: $totalLow"

            # Get the last commit details
            $commitsUrl = "https://dev.azure.com/$orgName/$project/_apis/git/repositories/$repository/commits?searchCriteria.itemVersion.version=$branchName&`$top=1&api-version=6.0"
            Write-Verbose "Fetching last commit from: $commitsUrl"
            $commitsResponse = Invoke-WebRequest -Uri $commitsUrl -Headers $headers -Method Get -SkipHttpErrorCheck
            if ($commitsResponse.StatusCode -ne 200) {
                Write-Host "❌ - Error $($commitsResponse.StatusCode) $($commitsResponse.StatusDescription) Failed to retrieve last commit for repo: $repository, branch: $branchName"
                Write-Verbose "Response content: $($commitsResponse.Content)"
                $lastCommitter = "N/A"
                $lastCommitDate = "N/A"
            } else {
                $lastCommit = ($commitsResponse.Content | ConvertFrom-Json).value | Select-Object -First 1
                $lastCommitter = $lastCommit.author.name
                $lastCommitDate = $lastCommit.author.date
            }

            $finalReport += [pscustomobject]@{
                Project        = $project
                Repo           = $repository
                RepoUrl        = $repoUrl
                Branch         = $branchName
                BranchUrl      = $branchUrl
                TotalCritical  = $totalCritical
                TotalHigh      = $totalHigh
                TotalMedium    = $totalMedium
                TotalLow       = $totalLow
                LastCommitter  = $lastCommitter
                LastCommitDate = $lastCommitDate
                AdvSecEnabled  = $true
            }
        }
        catch {
            Write-Host "⛔ - Unhandled Exception getting alerts from Azure DevOps Advanced Security:", $_.Exception.Message, $_.Exception.Response.StatusCode, $_.Exception.Response.RequestMessage.RequestUri
            Write-Verbose "Full exception details: $_"
            continue
        }
    }
}

Write-Verbose "Final report entries: $($finalReport.Count)"

# Export the final report to CSV
if ($finalReport.Count -gt 0) {
    $reportName = [regex]::Replace($reportName, '[^\w\d.-]', '')
    $reportPath = [System.IO.Path]::Combine($isAzDO ? ${env:BUILD_ARTIFACTSTAGINGDIRECTORY} : $pwd, $reportName)
    $finalReport | Export-Csv -Path "$reportPath" -NoTypeInformation -Force
    if ($isAzdo) {
        Write-Host "##vso[artifact.upload artifactname=GhazdoSecurityReport]$reportPath"
    }
    else {
        Write-Host "📄 - Report generated at $reportPath"
    }
}
else {
    Write-Host "🤷 - No repositories found with alerts in the scope: $scope"
}

if ($isAzdo) {
    Write-Host "##vso[task.complete result=Succeeded;]DONE"
}
exit 0
