using System.Text.Json;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class WindowsFirewallTransferEnforcementService
    : ITransferEnforcementService
{
    private const string RulePrefix =
        "SecurityGuard.TransferGuard.";

    private const string RuleGroup =
        "SecurityGuard.TransferGuard";

    private readonly TransferPowerShellRunner _runner;

    public WindowsFirewallTransferEnforcementService(
        TransferPowerShellRunner runner)
    {
        _runner =
            runner;
    }

    public async Task<TransferEnforcementResult> AddBlockAsync(
        TransferEnforcementRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        if (!Path.IsPathFullyQualified(
                rule.ProgramPath))
        {
            return new TransferEnforcementResult(
                false,
                $"Program path is not fully qualified: {rule.ProgramPath}");
        }

        if (rule.RemotePort is < 1 or > 65535)
        {
            return new TransferEnforcementResult(
                false,
                $"Invalid remote port: {rule.RemotePort}");
        }

        var environment =
            new Dictionary<string, string>
            {
                ["SG_FW_RULE_ID"] =
                    rule.SecurityRuleId.ToString("D"),

                ["SG_FW_PROGRAM"] =
                    rule.ProgramPath,

                ["SG_FW_REMOTE_ADDRESS"] =
                    rule.RemoteAddress,

                ["SG_FW_REMOTE_PORT"] =
                    rule.RemotePort.ToString(),

                ["SG_FW_PROTOCOL"] =
                    rule.Protocol.ToString()
            };

        await _runner.RunEncodedAsync(
            BuildAddScript(),
            environment,
            cancellationToken);

        return new TransferEnforcementResult(
            true,
            "Windows Firewall outbound block rule applied.");
    }

    public Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default)
    {
        var environment =
            new Dictionary<string, string>
            {
                ["SG_FW_RULE_ID"] =
                    securityRuleId.ToString("D")
            };

        return _runner.RunEncodedAsync(
            BuildRemoveScript(),
            environment,
            cancellationToken);
    }

    public async Task<TransferEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        var output =
            await _runner.RunEncodedAsync(
                BuildInspectScript(),
                cancellationToken:
                    cancellationToken);

        var dto =
            JsonSerializer.Deserialize<InspectionDto>(
                output,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive =
                        true
                });

        if (dto is null)
        {
            throw new InvalidOperationException(
                "Unable to parse Windows Firewall state.");
        }

        return new TransferEnforcementSnapshot(
            ParseIds(
                dto.PersistentRuleIds),
            ParseIds(
                dto.ActiveRuleIds));
    }

    private static IReadOnlySet<Guid> ParseIds(
        IReadOnlyList<string>? values)
    {
        if (values is null)
        {
            return new HashSet<Guid>();
        }

        return values
            .Select(
                value =>
                    Guid.TryParse(
                        value,
                        out var id)
                        ? id
                        : Guid.Empty)
            .Where(
                id =>
                    id != Guid.Empty)
            .ToHashSet();
    }

    private static string BuildAddScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $id =
                $env:SG_FW_RULE_ID

            $name =
                "SecurityGuard.TransferGuard.$id"

            $program =
                $env:SG_FW_PROGRAM

            $address =
                $env:SG_FW_REMOTE_ADDRESS

            $port =
                $env:SG_FW_REMOTE_PORT

            $protocol =
                $env:SG_FW_PROTOCOL

            $existing =
                Get-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -Name $name `
                    -ErrorAction SilentlyContinue

            if ($null -ne $existing) {
                $existing |
                    Remove-NetFirewallRule `
                        -PolicyStore PersistentStore `
                        -ErrorAction Stop
            }

            New-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $name `
                -DisplayName $name `
                -Group "SecurityGuard.TransferGuard" `
                -Description "SecurityGuardManaged:$id" `
                -Direction Outbound `
                -Action Block `
                -Enabled True `
                -Profile Any `
                -Program $program `
                -RemoteAddress $address `
                -RemotePort $port `
                -Protocol $protocol `
                -ErrorAction Stop |
                Out-Null

            Write-Output $name
            """;
    }

    private static string BuildRemoveScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $id =
                $env:SG_FW_RULE_ID

            $name =
                "SecurityGuard.TransferGuard.$id"

            Get-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $name `
                -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -ErrorAction Stop
            """;
    }

    private static string BuildInspectScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $prefix =
                'SecurityGuard.TransferGuard.'

            $group =
                'SecurityGuard.TransferGuard'

            function Get-Ids {
                param(
                    [string]$Store
                )

                $rules =
                    @(
                        Get-NetFirewallRule `
                            -PolicyStore $Store `
                            -ErrorAction Stop |
                        Where-Object {
                            $_.Name.StartsWith(
                                $prefix,
                                [System.StringComparison]::OrdinalIgnoreCase
                            ) -and
                            $_.Group -eq $group
                        }
                    )

                $ids =
                    @()

                foreach ($rule in $rules) {
                    $value =
                        $rule.Name.Substring(
                            $prefix.Length)

                    $parsed =
                        [Guid]::Empty

                    if (
                        [Guid]::TryParse(
                            $value,
                            [ref]$parsed)
                    ) {
                        $ids +=
                            $parsed.ToString('D')
                    }
                }

                return @($ids)
            }

            $result =
                [PSCustomObject]@{
                    PersistentRuleIds =
                        @(Get-Ids 'PersistentStore')

                    ActiveRuleIds =
                        @(Get-Ids 'ActiveStore')
                }

            $result |
                ConvertTo-Json `
                    -Compress `
                    -Depth 5
            """;
    }

    private sealed record InspectionDto(
        string[]? PersistentRuleIds,
        string[]? ActiveRuleIds);
}