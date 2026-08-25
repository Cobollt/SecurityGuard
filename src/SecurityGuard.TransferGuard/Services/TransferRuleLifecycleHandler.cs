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

        await _enforcementService.RemoveBlockAsync(
            rule.Id,
            cancellationToken);
    }
}