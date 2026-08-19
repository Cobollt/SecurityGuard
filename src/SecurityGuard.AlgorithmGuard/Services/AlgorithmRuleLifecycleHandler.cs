using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmRuleLifecycleHandler
    : ISecurityRuleLifecycleHandler
{
    private readonly IAlgorithmEnforcementService _enforcementService;

    public AlgorithmRuleLifecycleHandler(
        IAlgorithmEnforcementService enforcementService)
    {
        _enforcementService =
            enforcementService;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.AlgorithmGuard;

    public async Task BeforeDeleteAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default)
    {
        if (rule.Module !=
            SecurityModuleKind.AlgorithmGuard)
        {
            return;
        }

        if (rule.Decision !=
            RuleDecision.Block)
        {
            return;
        }

        await _enforcementService.RemoveBlockAsync(
            rule.Id,
            cancellationToken);
    }
}