using System.Globalization;
using System.Text.Json;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class WindowsFirewallTemporaryEnforcementService
    : ITransferTemporaryEnforcementService
{
    private const string Prefix =
        "SecurityGuard.TransferGuard.Temp.";

    private const string Group =
        "SecurityGuard.TransferGuard.Temporary";

    private readonly TransferPowerShellRunner _runner;

    public WindowsFirewallTemporaryEnforcementService(
        TransferPowerShellRunner runner)
    {
        _runner =
            runner;
    }

    public async Task<TransferTemporaryEnforcementResult> AddOrRefreshAsync(
        TransferTemporaryEnforcementRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        var environment =
            new Dictionary<string, string>
            {
                ["SG_TEMP_RULE_ID"] =
                    rule.Id.ToString("D"),

                ["SG_TEMP_PROGRAM"] =
                    rule.ProgramPath,

                ["SG_TEMP_REMOTE_ADDRESS"] =
                    rule.RemoteAddress,

                ["SG_TEMP_REMOTE_PORT"] =
                    rule.RemotePort.ToString(
                        CultureInfo.InvariantCulture),

                ["SG_TEMP_PROTOCOL"] =
                    rule.Protocol.ToString(),

                ["SG_TEMP_EXPIRES"] =
                    rule.ExpiresAtUtc.ToString(
                        "O",
                        CultureInfo.InvariantCulture)
            };

        var output =
            await _runner.RunEncodedAsync(
                BuildApplyScript(),
                environment,
                cancellationToken);

        var result =
            JsonSerializer.Deserialize<ApplyResultDto>(
                output,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive =
                        true
                });

        if (result is null)
        {
            throw new InvalidOperationException(
                "Unable to parse temporary Windows Firewall result.");
        }

        return new TransferTemporaryEnforcementResult(
            result.Applied,
            result.Message ??
            "Temporary Firewall enforcement completed.",
            result.Applied
                ? rule.ExpiresAtUtc
                : null);
    }

    public Task RemoveAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default)
    {
        return _runner.RunEncodedAsync(
            BuildRemoveScript(),
            new Dictionary<string, string>
            {
                ["SG_TEMP_RULE_ID"] =
                    ruleId.ToString("D")
            },
            cancellationToken);
    }

    public async Task<int> CleanupExpiredAsync(
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        var output =
            await _runner.RunEncodedAsync(
                BuildCleanupScript(),
                new Dictionary<string, string>
                {
                    ["SG_TEMP_NOW"] =
                        nowUtc.ToString(
                            "O",
                            CultureInfo.InvariantCulture)
                },
                cancellationToken);

        return int.TryParse(
            output,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var removed)
                ? removed
                : 0;
    }

    public async Task<int> RemoveAllAsync(
        CancellationToken cancellationToken = default)
    {
        var output =
            await _runner.RunEncodedAsync(
                BuildRemoveAllScript(),
                cancellationToken:
                    cancellationToken);

        return int.TryParse(
            output,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var removed)
                ? removed
                : 0;
    }

    private static string BuildApplyScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $id =
                $env:SG_TEMP_RULE_ID

            $name =
                "SecurityGuard.TransferGuard.Temp.$id"

            $program =
                $env:SG_TEMP_PROGRAM

            $address =
                $env:SG_TEMP_REMOTE_ADDRESS

            $port =
                $env:SG_TEMP_REMOTE_PORT

            $protocol =
                $env:SG_TEMP_PROTOCOL

            $expires =
                $env:SG_TEMP_EXPIRES

            Get-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $name `
                -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -ErrorAction Stop

            New-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $name `
                -DisplayName $name `
                -Group "SecurityGuard.TransferGuard.Temporary" `
                -Description "SecurityGuardTemporary;ExpiresAtUtc=$expires" `
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

            $persistent =
                Get-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -Name $name `
                    -ErrorAction SilentlyContinue

            $active =
                $null

            for (
                $attempt = 0;
                $attempt -lt 5;
                $attempt++
            ) {
                $active =
                    Get-NetFirewallRule `
                        -PolicyStore ActiveStore `
                        -Name $name `
                        -ErrorAction SilentlyContinue

                if ($null -ne $active) {
                    break
                }

                Start-Sleep `
                    -Milliseconds 100
            }

            $applied =
                $null -ne $persistent -and
                $null -ne $active

            if (-not $applied) {
                Get-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -Name $name `
                    -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule `
                        -PolicyStore PersistentStore `
                        -ErrorAction SilentlyContinue
            }

            $result =
                [PSCustomObject]@{
                    Applied =
                        $applied

                    Message =
                        if ($applied) {
                            "Temporary Firewall block is active."
                        }
                        else {
                            "Temporary Firewall block did not appear in ActiveStore."
                        }
                }

            $result |
                ConvertTo-Json `
                    -Compress
            """;
    }

    private static string BuildRemoveScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $name =
                "SecurityGuard.TransferGuard.Temp.$env:SG_TEMP_RULE_ID"

            Get-NetFirewallRule `
                -PolicyStore PersistentStore `
                -Name $name `
                -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -ErrorAction Stop
            """;
    }

    private static string BuildCleanupScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $group =
                'SecurityGuard.TransferGuard.Temporary'

            $now =
                [DateTimeOffset]::Parse(
                    $env:SG_TEMP_NOW,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                )

            $rules =
                @(
                    Get-NetFirewallRule `
                        -PolicyStore PersistentStore `
                        -ErrorAction Stop |
                    Where-Object {
                        $_.Group -eq $group -and
                        $_.Name.StartsWith(
                            'SecurityGuard.TransferGuard.Temp.',
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }
                )

            $removed =
                0

            foreach ($rule in $rules) {
                $expired =
                    $true

                $description =
                    [string]$rule.Description

                if (
                    $description -match
                    'ExpiresAtUtc=([^;]+)'
                ) {
                    try {
                        $expires =
                            [DateTimeOffset]::Parse(
                                $Matches[1],
                                [Globalization.CultureInfo]::InvariantCulture,
                                [Globalization.DateTimeStyles]::RoundtripKind
                            )

                        $expired =
                            $expires -le $now
                    }
                    catch {
                        $expired =
                            $true
                    }
                }

                if ($expired) {
                    $rule |
                        Remove-NetFirewallRule `
                            -PolicyStore PersistentStore `
                            -ErrorAction Stop

                    $removed++
                }
            }

            Write-Output $removed
            """;
    }

    private static string BuildRemoveAllScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            Import-Module NetSecurity -ErrorAction Stop

            $group =
                'SecurityGuard.TransferGuard.Temporary'

            $rules =
                @(
                    Get-NetFirewallRule `
                        -PolicyStore PersistentStore `
                        -ErrorAction Stop |
                    Where-Object {
                        $_.Group -eq $group -and
                        $_.Name.StartsWith(
                            'SecurityGuard.TransferGuard.Temp.',
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }
                )

            foreach ($rule in $rules) {
                $rule |
                    Remove-NetFirewallRule `
                        -PolicyStore PersistentStore `
                        -ErrorAction Stop
            }

            $remaining =
                @(
                    Get-NetFirewallRule `
                        -PolicyStore ActiveStore `
                        -ErrorAction Stop |
                    Where-Object {
                        $_.Group -eq $group -and
                        $_.Name.StartsWith(
                            'SecurityGuard.TransferGuard.Temp.',
                            [StringComparison]::OrdinalIgnoreCase
                        )
                    }
                )

            if ($remaining.Count -gt 0) {
                throw "Temporary SecurityGuard Firewall rules remain in ActiveStore."
            }

            Write-Output $rules.Count
            """;
    }

    private sealed record ApplyResultDto(
        bool Applied,
        string? Message);
}