using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferRuleLifecycleHandler
    : ISecurityRuleLifecycleHandler
{
    private readonly ITransferEnforcementService _enforcementService;
    private readonly ITransferTemporaryEnforcementService _temporaryEnforcementService;

    public TransferRuleLifecycleHandler(
        ITransferEnforcementService enforcementService,
        ITransferTemporaryEnforcementService temporaryEnforcementService)
    {
        _enforcementService =
            enforcementService;

        _temporaryEnforcementService =
            temporaryEnforcementService;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.TransferGuard;

    public async Task BeforeDeleteAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default)
    {
        if (rule.Module !=
            SecurityModuleKind.TransferGuard)
        {
            return;
        }

        if (rule.Decision !=
            RuleDecision.Block)
        {
            return;
        }

        if (TransferRuleClassifier.IsFileTransferRule(
                rule))
        {
            await _temporaryEnforcementService.RemoveBySourceRuleIdAsync(
                rule.Id,
                cancellationToken);

            return;
        }

        await _enforcementService.RemoveBlockAsync(
            rule.Id,
            cancellationToken);
    }
}