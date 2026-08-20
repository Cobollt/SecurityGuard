using System.Text.Json;
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
                ["SG_TARGET_FILE"] =
                    fullPath,

                ["SG_RULE_ID"] =
                    securityRuleId.ToString("D")
            };

        await _powerShellRunner.RunEncodedAsync(
            BuildAddPolicyScript(),
            environment,
            cancellationToken);

        var message =
            level switch
            {
                AlgorithmEnforcementLevel.PowerShellConstrained =>
                    "AppLocker PowerShell enforcement applied.",

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

    public Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default)
    {
        var environment =
            new Dictionary<string, string>
            {
                ["SG_RULE_ID"] =
                    securityRuleId.ToString("D")
            };

        return _powerShellRunner.RunEncodedAsync(
            BuildRemovePolicyScript(),
            environment,
            cancellationToken);
    }

    public async Task<AlgorithmEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        var output =
            await _powerShellRunner.RunEncodedAsync(
                BuildInspectionScript(),
                cancellationToken: cancellationToken);

        var state =
            JsonSerializer.Deserialize<AppLockerInspectionDto>(
                output,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

        if (state is null)
        {
            throw new InvalidOperationException(
                "Unable to read AppLocker enforcement state.");
        }

        var local =
            state.LocalRuleIds
                .Select(Guid.Parse)
                .ToHashSet();

        var effective =
            state.EffectiveRuleIds
                .Select(Guid.Parse)
                .ToHashSet();

        return new AlgorithmEnforcementSnapshot(
            local,
            effective,
            state.ManagedBaselinePresent,
            state.UnmanagedScriptRulesPresent);
    }

    private static string BuildAddPolicyScript()
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

            [xml]$currentXml =
                Get-AppLockerPolicy -Local -Xml

            $currentCollection =
                @(
                    $currentXml.AppLockerPolicy.RuleCollection |
                    Where-Object {
                        $_.Type -eq 'Script'
                    }
                ) |
                Select-Object -First 1

            if ($null -ne $currentCollection) {
                $existing =
                    @(
                        $currentCollection.ChildNodes |
                        Where-Object {
                            $_.Name -eq $ruleName -and
                            $_.Description -eq 'SecurityGuardManaged'
                        }
                    )

                if ($existing.Count -gt 0) {
                    Write-Output $ruleName
                    return
                }
            }

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
                    Where-Object {
                        $_.Type -eq 'Script'
                    }
                ) |
                Select-Object -First 1

            if ($null -eq $generatedCollection) {
                throw "Unable to create AppLocker Script collection."
            }

            $generatedRule =
                @(
                    $generatedCollection.FileHashRule
                ) |
                Select-Object -First 1

            if ($null -eq $generatedRule) {
                throw "Unable to create AppLocker hash rule."
            }

            $generatedRule.Action = 'Deny'
            $generatedRule.Name = $ruleName
            $generatedRule.Description = 'SecurityGuardManaged'

            if ($null -eq $currentCollection) {
                $generatedCollection.EnforcementMode =
                    'Enabled'

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
                    ("SecurityGuard-" +
                     [Guid]::NewGuid().ToString('N') +
                     '.xml')

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

    private static string BuildRemovePolicyScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module AppLocker -ErrorAction Stop

            $securityRuleId = $env:SG_RULE_ID
            $ruleName = "SecurityGuard:$securityRuleId"

            [xml]$policy =
                Get-AppLockerPolicy -Local -Xml

            $scriptCollection =
                @(
                    $policy.AppLockerPolicy.RuleCollection |
                    Where-Object {
                        $_.Type -eq 'Script'
                    }
                ) |
                Select-Object -First 1

            if ($null -eq $scriptCollection) {
                return
            }

            $rules =
                @(
                    $scriptCollection.ChildNodes
                )

            $targets =
                @(
                    $rules |
                    Where-Object {
                        $_.Name -eq $ruleName -and
                        $_.Description -eq 'SecurityGuardManaged'
                    }
                )

            if ($targets.Count -eq 0) {
                return
            }

            foreach ($target in $targets) {
                $scriptCollection.RemoveChild(
                    $target) |
                    Out-Null
            }

            $remainingManagedRules =
                @(
                    $scriptCollection.ChildNodes |
                    Where-Object {
                        $_.Description -eq 'SecurityGuardManaged'
                    }
                )

            if ($remainingManagedRules.Count -eq 0) {
                $baselines =
                    @(
                        $scriptCollection.ChildNodes |
                        Where-Object {
                            $_.Name -eq 'SecurityGuard:BaselineAllow' -and
                            $_.Description -eq 'SecurityGuardManagedBaseline'
                        }
                    )

                foreach ($baseline in $baselines) {
                    $scriptCollection.RemoveChild(
                        $baseline) |
                        Out-Null
                }
            }

            if ($scriptCollection.ChildNodes.Count -eq 0) {
                $policy.AppLockerPolicy.RemoveChild(
                    $scriptCollection) |
                    Out-Null
            }

            $temporaryPolicy =
                Join-Path `
                    ([System.IO.Path]::GetTempPath()) `
                    ("SecurityGuard-" +
                     [Guid]::NewGuid().ToString('N') +
                     '.xml')

            try {
                $policy.Save(
                    $temporaryPolicy)

                Set-AppLockerPolicy `
                    -XmlPolicy $temporaryPolicy `
                    -ErrorAction Stop
            }
            finally {
                Remove-Item `
                    -LiteralPath $temporaryPolicy `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
            """;
    }

    private static string BuildInspectionScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module AppLocker -ErrorAction Stop

            function Get-ScriptRules {
                param(
                    [xml]$Policy
                )

                $collection =
                    @(
                        $Policy.AppLockerPolicy.RuleCollection |
                        Where-Object {
                            $_.Type -eq 'Script'
                        }
                    ) |
                    Select-Object -First 1

                if ($null -eq $collection) {
                    return @()
                }

                return @(
                    $collection.ChildNodes
                )
            }

            function Get-SecurityGuardIds {
                param(
                    [object[]]$Rules
                )

                $ids = @()

                foreach ($rule in $Rules) {
                    if (
                        $rule.Description -eq 'SecurityGuardManaged' -and
                        $rule.Name -match '^SecurityGuard:(?<id>[0-9a-fA-F-]{36})$'
                    ) {
                        $ids += $Matches['id']
                    }
                }

                return @($ids)
            }

            [xml]$localPolicy =
                Get-AppLockerPolicy -Local -Xml

            [xml]$effectivePolicy =
                Get-AppLockerPolicy -Effective -Xml

            $localRules =
                @(Get-ScriptRules $localPolicy)

            $effectiveRules =
                @(Get-ScriptRules $effectivePolicy)

            $localIds =
                @(Get-SecurityGuardIds $localRules)

            $effectiveIds =
                @(Get-SecurityGuardIds $effectiveRules)

            $managedBaselinePresent =
                @(
                    $localRules |
                    Where-Object {
                        $_.Name -eq 'SecurityGuard:BaselineAllow' -and
                        $_.Description -eq 'SecurityGuardManagedBaseline'
                    }
                ).Count -gt 0

            $unmanagedScriptRulesPresent =
                @(
                    $localRules |
                    Where-Object {
                        $_.Description -ne 'SecurityGuardManaged' -and
                        $_.Description -ne 'SecurityGuardManagedBaseline'
                    }
                ).Count -gt 0

            $result =
                [PSCustomObject]@{
                    LocalRuleIds =
                        @($localIds)

                    EffectiveRuleIds =
                        @($effectiveIds)

                    ManagedBaselinePresent =
                        $managedBaselinePresent

                    UnmanagedScriptRulesPresent =
                        $unmanagedScriptRulesPresent
                }

            $result |
                ConvertTo-Json `
                    -Compress `
                    -Depth 5
            """;
    }

    private sealed record AppLockerInspectionDto(
        string[] LocalRuleIds,
        string[] EffectiveRuleIds,
        bool ManagedBaselinePresent,
        bool UnmanagedScriptRulesPresent);
}