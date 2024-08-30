<#
.SYNOPSIS
    This script generates a CSV report of Azure DevOps Advanced Security alerts for a given organization, project, and repository.
.DESCRIPTION
    This script retrieves the list of projects and repositories for a given organization, and then retrieves the list of Advanced Security alerts for each repository.
    It filters the alerts based on severity, alert type, and state and then generates a CSV report of the filtered alerts.
    The script contains an SLA based on number of days since the alert was first seen. For critical it is 7 days, high is 30 days, medium is 90 days, and low is 180 days.
.PARAMETER pat
    The Azure DevOps Personal Access Token (PAT) with Advanced Security=READ, Code=READ (to look up repositories for scope="organization" or scope="project"), and Project=READ (to look up projects in an organization for scope="organization") permissions.
.PARAMETER orgUri
    The URL of the Azure DevOps organization.
.PARAMETER project
    The name of the Azure DevOps project.
.PARAMETER repository
    The name of the Azure DevOps repository.
.PARAMETER reportName
    The name of the csv report.
.PARAMETER scope
    The scope of the report. Valid values are "organization", "project", or "repository".
#>

param(
    [string]$pat = ${env:MAPPED_ADO_PAT},
    [string]$orgUri = ${env:SYSTEM_COLLECTIONURI},
    [string]$project = ${env:SYSTEM_TEAMPROJECT},
    [string]$repository = ${env:BUILD_REPOSITORY_NAME},
    [string]$reportName = "ghazdo-report-${env:BUILD_BUILDNUMBER}.csv",
    [ValidateSet("organization", "project", "repository")]
    [string]$scope = "organization"
)

if ([string]::IsNullOrEmpty($pat)) {
    throw "The `pat` parameter must be set or the `MAPPED_ADO_PAT` environment variable must be set."
}

$orgName = $orgUri -replace "^https://dev.azure.com/|/$"
$headers = @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($pat.Contains(":") ? $pat : ":$pat"))))" }
$isAzDO = $env:TF_BUILD -eq "True"

# Report Configuration
$severities = @("critical", "high", "medium", "low")
$states = @("active", "fixed", "dismissed")
$alertTypes = @("code", "secret", "dependency")
$severityDays = @{
    "critical" = 7
    "high"     = 30
    "medium"   = 90
    "low"      = 180
}
$maxAlertsPerRepo = 10000

# Build the list of repos to scan
$scans = @()
if ($scope -in @("organization", "project")) {
    $projects = if ($scope -eq "organization") {
        $url = "https://dev.azure.com/$orgName/_apis/projects"
        $projectsResponse = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -SkipHttpErrorCheck
        if ($projectsResponse.StatusCode -ne 200) {
            Write-Host "❌ - Error $($projectsResponse.StatusCode) $($projectsResponse.StatusDescription) Failed to retrieve projects for org: $orgName with $url"
            continue
        }
        ($projectsResponse.Content | ConvertFrom-Json).value
    }
    elseif ($scope -eq "project") {
        @(@{ name = $project })
    }

    foreach ($proj in $projects) {
        $url = "https://dev.azure.com/$orgName/$($proj.name)/_apis/git/repositories"
        $reposResponse = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -SkipHttpErrorCheck
        if ($reposResponse.StatusCode -ne 200) {
            Write-Host "❌ - Error $($reposResponse.StatusCode) $($reposResponse.StatusDescription) Failed to retrieve repositories for org: $orgName and project: $($proj.name) with $url"
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

# Loop through repo alert list and compile the final report
[System.Collections.ArrayList]$finalReport = @()

foreach ($scan in $scans) {
    $project = $scan.ProjectName
    $repository = $scan.RepoName
    $repoUrl = "https://dev.azure.com/$orgName/$project/_git/$repository"
    
    # Get the list of branches
    $branchesUrl = "https://dev.azure.com/$orgName/$project/_apis/git/repositories/$repository/refs?filter=refs/heads/&api-version=6.0"
    $branchesResponse = Invoke-WebRequest -Uri $branchesUrl -Headers $headers -Method Get
    $branches = ($branchesResponse.Content | ConvertFrom-Json).value

    foreach ($branch in $branches) {
        $branchName = $branch.name -replace "^refs/heads/", ""
        $branchUrl = "$repoUrl?version=GB$branchName"

        $alertsUrl = "https://advsec.dev.azure.com/$orgName/$project/_apis/alert/repositories/$repository/alerts?top=$maxAlertsPerRepo&$filter=ref eq '$branchName'"
        
        try {
            $alertsResponse = Invoke-WebRequest -Uri $alertsUrl -Headers $headers -Method Get -SkipHttpErrorCheck
            if ($alertsResponse.StatusCode -ne 200) {
                $enablementurl = "https://advsec.dev.azure.com/$orgName/$project/_apis/management/repositories/$repository/enablement"
                $repoEnablement = Invoke-WebRequest -Uri $enablementurl -Headers $headers -Method Get -SkipHttpErrorCheck
                $enablement = $repoEnablement.content | ConvertFrom-Json

                if (!$enablement.advSecEnabled) {
                    $finalReport += [pscustomobject]@{
                        Project        = $project
                        Repo           = "<a href='$repoUrl'>$repository</a>"
                        Branch         = "<a href='$branchUrl'>$branchName</a>"
                        TotalCritical  = 0
                        TotalHigh      = 0
                        TotalMedium    = 0
                        TotalLow       = 0
                        LastCommitter  = "N/A"
                        LastCommitDate = "N/A"
                    }
                    continue
                }
            }
            $parsedAlerts = $alertsResponse.Content | ConvertFrom-Json

            $totalCritical = ($parsedAlerts.value | Where-Object { $_.severity -eq "critical" }).Count
            $totalHigh = ($parsedAlerts.value | Where-Object { $_.severity -eq "high" }).Count
            $totalMedium = ($parsedAlerts.value | Where-Object { $_.severity -eq "medium" }).Count
            $totalLow = ($parsedAlerts.value | Where-Object { $_.severity -eq "low" }).Count

            # Get the last commit details
            $commitsUrl = "https://dev.azure.com/$orgName/$project/_apis/git/repositories/$repository/commits?searchCriteria.itemVersion.version=$branchName&$top=1&api-version=6.0"
            $commitsResponse = Invoke-WebRequest -Uri $commitsUrl -Headers $headers -Method Get
            $lastCommit = ($commitsResponse.Content | ConvertFrom-Json).value | Select-Object -First 1

            $finalReport += [pscustomobject]@{
                Project        = $project
                Repo           = "<a href='$repoUrl'>$repository</a>"
                Branch         = "<a href='$branchUrl'>$branchName</a>"
                TotalCritical  = $totalCritical
                TotalHigh      = $totalHigh
                TotalMedium    = $totalMedium
                TotalLow       = $totalLow
                LastCommitter  = $lastCommit.author.name
                LastCommitDate = $lastCommit.author.date
            }
        }
        catch {
            Write-Host "⛔ - Unhandled Exception getting alerts from Azure DevOps Advanced Security:", $_.Exception.Message, $_.Exception.Response.StatusCode, $_.Exception.Response.RequestMessage.RequestUri
            continue
        }
    }
}

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
