using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferRuleLifecycleHandler
    : ISecurityRuleLifecycleHandler
{
    private readonly ITransferEnforcementService _enforcementService;

    public TransferRuleLifecycleHandler(
        ITransferEnforcementService enforcementService)
    {
        _enforcementService =
            enforcementService;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.TransferGuard;

    public async Task BeforeDeleteAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default)
    {
        if (rule.Module !=
                SecurityModuleKind.TransferGuard ||
            rule.Decision !=
                RuleDecision.Block)
        {
            return;
        }

        if (IsFileTransferRule(
                rule))
        {
            return;
        }

        await _enforcementService.RemoveBlockAsync(
            rule.Id,
            cancellationToken);
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