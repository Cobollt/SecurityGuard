using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Services;

public static class TransferRuleClassifier
{
    public static bool IsFileTransferRule(
        SecurityRule rule)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        if (HasValue(
                rule,
                RuleScope.TransferActivityKind,
                TransferActivityKind.FileTransfer.ToString()))
        {
            return true;
        }

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

    public static bool IsNetworkConnectionRule(
        SecurityRule rule)
    {
        ArgumentNullException.ThrowIfNull(
            rule);

        if (HasValue(
                rule,
                RuleScope.TransferActivityKind,
                TransferActivityKind.NetworkConnection.ToString()))
        {
            return true;
        }

        return !IsFileTransferRule(
            rule);
    }

    public static bool HasScope(
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

    private static bool HasValue(
        SecurityRule rule,
        RuleScope scope,
        string value)
    {
        if (rule.Scope ==
                scope &&
            string.Equals(
                rule.Value,
                value,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return rule.Conditions?.Any(
                   condition =>
                       condition.Scope ==
                           scope &&
                       string.Equals(
                           condition.Value,
                           value,
                           StringComparison.OrdinalIgnoreCase)) ==
               true;
    }
}