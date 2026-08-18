using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AppLockerAlgorithmEnforcementService
    : IAlgorithmEnforcementService
{
    private static readonly HashSet<string> SupportedExtensions =
        new(
            [
                ".ps1",
                ".bat",
                ".cmd",
                ".vbs",
                ".js"
            ],
            StringComparer.OrdinalIgnoreCase);

    private readonly PowerShellProcessRunner _powerShellRunner;

    public AppLockerAlgorithmEnforcementService(
        PowerShellProcessRunner powerShellRunner)
    {
        _powerShellRunner =
            powerShellRunner;
    }

    public AlgorithmEnforcementLevel GetLevel(
        string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return AlgorithmEnforcementLevel.Unsupported;
        }

        var extension =
            Path.GetExtension(filePath);

        if (!SupportedExtensions.Contains(extension))
        {
            return AlgorithmEnforcementLevel.Unsupported;
        }

        if (string.Equals(
                extension,
                ".ps1",
                StringComparison.OrdinalIgnoreCase))
        {
            return AlgorithmEnforcementLevel.PowerShellConstrained;
        }

        return AlgorithmEnforcementLevel.AppLockerBlocked;
    }

    public async Task<AlgorithmEnforcementResult> AddBlockAsync(
        Guid securityRuleId,
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var fullPath =
            Path.GetFullPath(filePath);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                "Script file was not found.",
                fullPath);
        }

        var level =
            GetLevel(fullPath);

        if (level ==
            AlgorithmEnforcementLevel.Unsupported)
        {
            return new AlgorithmEnforcementResult(
                false,
                level,
                "This script type cannot currently be enforced by AppLocker.");
        }

        var environment =
            new Dictionary<string, string>
            {
                ["SG_TARGET_FILE"] = fullPath,
                ["SG_RULE_ID"] = securityRuleId.ToString("D")
            };

        await _powerShellRunner.RunEncodedAsync(
            BuildPolicyScript(),
            environment,
            cancellationToken);

        var message =
            level switch
            {
                AlgorithmEnforcementLevel.PowerShellConstrained =>
                    "AppLocker rule applied. PowerShell will restrict the blocked script with Constrained Language Mode.",

                AlgorithmEnforcementLevel.AppLockerBlocked =>
                    "AppLocker block rule applied.",

                _ =>
                    "Rule applied."
            };

        return new AlgorithmEnforcementResult(
            true,
            level,
            message);
    }

    private static string BuildPolicyScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module AppLocker -ErrorAction Stop

            $targetFile = $env:SG_TARGET_FILE
            $securityRuleId = $env:SG_RULE_ID
            $ruleName = "SecurityGuard:$securityRuleId"

            if (-not (Test-Path -LiteralPath $targetFile -PathType Leaf)) {
                throw "Target file was not found."
            }

            $service = Get-Service -Name AppIDSvc -ErrorAction Stop

            if ($service.Status -ne 'Running') {
                Start-Service -Name AppIDSvc -ErrorAction Stop
            }

            $currentXmlText = Get-AppLockerPolicy -Local -Xml
            [xml]$currentXml = $currentXmlText

            $currentScriptCollection =
                @(
                    $currentXml.AppLockerPolicy.RuleCollection |
                    Where-Object { $_.Type -eq 'Script' }
                ) |
                Select-Object -First 1

            $hadScriptCollection =
                $null -ne $currentScriptCollection

            $generatedXmlText =
                Get-Item -LiteralPath $targetFile |
                Get-AppLockerFileInformation |
                New-AppLockerPolicy `
                    -RuleType Hash `
                    -User Everyone `
                    -RuleNamePrefix $ruleName `
                    -Xml

            [xml]$generatedXml =
                $generatedXmlText

            $generatedCollection =
                @(
                    $generatedXml.AppLockerPolicy.RuleCollection |
                    Where-Object { $_.Type -eq 'Script' }
                ) |
                Select-Object -First 1

            if ($null -eq $generatedCollection) {
                throw "Unable to create an AppLocker Script rule."
            }

            $generatedRule =
                @(
                    $generatedCollection.FileHashRule
                ) |
                Select-Object -First 1

            if ($null -eq $generatedRule) {
                throw "Unable to create an AppLocker hash rule."
            }

            $generatedRule.Action = 'Deny'
            $generatedRule.Name = $ruleName
            $generatedRule.Description = 'SecurityGuardManaged'

            if (-not $hadScriptCollection) {
                $generatedCollection.EnforcementMode = 'Enabled'

                $baselineRule =
                    $generatedXml.CreateElement(
                        'FilePathRule')

                $baselineRule.SetAttribute(
                    'Id',
                    [Guid]::NewGuid().ToString())

                $baselineRule.SetAttribute(
                    'Name',
                    'SecurityGuard:BaselineAllow')

                $baselineRule.SetAttribute(
                    'Description',
                    'SecurityGuardManagedBaseline')

                $baselineRule.SetAttribute(
                    'UserOrGroupSid',
                    'S-1-1-0')

                $baselineRule.SetAttribute(
                    'Action',
                    'Allow')

                $conditions =
                    $generatedXml.CreateElement(
                        'Conditions')

                $pathCondition =
                    $generatedXml.CreateElement(
                        'FilePathCondition')

                $pathCondition.SetAttribute(
                    'Path',
                    '*')

                $conditions.AppendChild(
                    $pathCondition) |
                    Out-Null

                $baselineRule.AppendChild(
                    $conditions) |
                    Out-Null

                $generatedCollection.PrependChild(
                    $baselineRule) |
                    Out-Null
            }

            $temporaryPolicy =
                Join-Path `
                    ([System.IO.Path]::GetTempPath()) `
                    ("SecurityGuard-" + [Guid]::NewGuid().ToString('N') + '.xml')

            try {
                $generatedXml.Save(
                    $temporaryPolicy)

                Set-AppLockerPolicy `
                    -XmlPolicy $temporaryPolicy `
                    -Merge `
                    -ErrorAction Stop
            }
            finally {
                Remove-Item `
                    -LiteralPath $temporaryPolicy `
                    -Force `
                    -ErrorAction SilentlyContinue
            }

            Write-Output $ruleName
            """;
    }
}