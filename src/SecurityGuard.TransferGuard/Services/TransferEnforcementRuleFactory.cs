using System.Net;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferEnforcementRuleFactory
{
    private readonly ITransferPathNormalizer _pathNormalizer;

    public TransferEnforcementRuleFactory(
        ITransferPathNormalizer pathNormalizer)
    {
        _pathNormalizer =
            pathNormalizer;
    }

    public bool TryCreate(
        SecurityRule rule,
        out TransferEnforcementRule? result,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        result =
            null;

        error =
            null;

        if (rule.Module !=
                SecurityModuleKind.TransferGuard ||
            rule.Decision !=
                RuleDecision.Block)
        {
            error =
                "Rule is not a TransferGuard block rule.";

            return false;
        }

        if (IsFileTransferRule(
                rule))
        {
            error =
                "File-transfer rules cannot be projected directly to Windows Firewall.";

            return false;
        }

        var processPath =
            GetValue(
                rule,
                RuleScope.ProcessPath);

        processPath =
            _pathNormalizer.Normalize(
                processPath);

        if (string.IsNullOrWhiteSpace(
                processPath) ||
            !Path.IsPathFullyQualified(
                processPath))
        {
            error =
                "ProcessPath is missing or cannot be normalized.";

            return false;
        }

        var remoteAddress =
            GetValue(
                rule,
                RuleScope.RemoteAddress);

        if (string.IsNullOrWhiteSpace(
                remoteAddress) ||
            !IPAddress.TryParse(
                remoteAddress,
                out _))
        {
            error =
                "RemoteAddress is missing or invalid.";

            return false;
        }

        var portValue =
            GetValue(
                rule,
                RuleScope.RemotePort);

        if (!int.TryParse(
                portValue,
                out var remotePort) ||
            remotePort is < 1 or > 65535)
        {
            error =
                "RemotePort is missing or invalid.";

            return false;
        }

        var protocolValue =
            GetValue(
                rule,
                RuleScope.Protocol);

        if (!Enum.TryParse<TransferProtocol>(
                protocolValue,
                true,
                out var protocol))
        {
            error =
                "Protocol is missing or invalid.";

            return false;
        }

        result =
            new TransferEnforcementRule(
                rule.Id,
                processPath,
                remoteAddress,
                remotePort,
                protocol);

        return true;
    }

    private static string? GetValue(
        SecurityRule rule,
        RuleScope scope)
    {
        if (rule.Scope ==
            scope)
        {
            return rule.Value;
        }

        return rule.Conditions?
            .FirstOrDefault(
                condition =>
                    condition.Scope ==
                    scope)
            ?.Value;
    }

    private static bool IsFileTransferRule(
        SecurityRule rule)
    {
        return HasScope(
                rule,
                RuleScope.FileHash) ||
            HasScope(
                rule,
                RuleScope.FilePath) ||
            HasScope(
                rule,
                RuleScope.FileName) ||
            HasScope(
                rule,
                RuleScope.FileExtension) ||
            HasScope(
                rule,
                RuleScope.FileCategory);
    }

    private static bool HasScope(
        SecurityRule rule,
        RuleScope scope)
    {
        if (rule.Scope ==
            scope)
        {
            return true;
        }

        return rule.Conditions?.Any(
                condition =>
                    condition.Scope ==
                    scope) ==
            true;
    }
}