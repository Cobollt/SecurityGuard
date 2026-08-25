using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IRuleRepository _ruleRepository;
    private readonly ITransferEnforcementService _enforcementService;
    private readonly TransferEnforcementRuleFactory _enforcementRuleFactory;

    public TransferDecisionHandler(
        IRuleRepository ruleRepository,
        ITransferEnforcementService enforcementService,
        TransferEnforcementRuleFactory enforcementRuleFactory)
    {
        _ruleRepository =
            ruleRepository;

        _enforcementService =
            enforcementService;

        _enforcementRuleFactory =
            enforcementRuleFactory;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.TransferGuard;

    public async Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        var ruleDecision =
            decision.Action switch
            {
                SecurityAction.Allow =>
                    RuleDecision.Allow,

                SecurityAction.Block =>
                    RuleDecision.Block,

                _ =>
                    throw new InvalidOperationException(
                        $"Unsupported TransferGuard action: {decision.Action}")
            };

        var rule =
            BuildRule(
                request,
                ruleDecision);

        if (ruleDecision ==
            RuleDecision.Block)
        {
            if (!_enforcementRuleFactory.TryCreate(
                    rule,
                    out var enforcementRule,
                    out var error) ||
                enforcementRule is null)
            {
                throw new InvalidOperationException(
                    error ??
                    "Unable to build Windows Firewall rule.");
            }

            var result =
                await _enforcementService.AddBlockAsync(
                    enforcementRule,
                    cancellationToken);

            if (!result.Applied)
            {
                throw new InvalidOperationException(
                    result.Message);
            }
        }

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
    }

    private static SecurityRule BuildRule(
        SecurityDecisionRequest request,
        RuleDecision decision)
    {
        var context =
            request.RuleContext ??
            throw new InvalidOperationException(
                "TransferGuard rule context is missing.");

        if (string.IsNullOrWhiteSpace(
                context.ProcessPath))
        {
            throw new InvalidOperationException(
                "TransferGuard requires ProcessPath for persistent network rules.");
        }

        var conditions =
            new List<SecurityRuleCondition>();

        AddCondition(
            conditions,
            RuleScope.RemoteAddress,
            context.RemoteAddress);

        AddCondition(
            conditions,
            RuleScope.RemotePort,
            context.RemotePort?.ToString());

        AddCondition(
            conditions,
            RuleScope.Protocol,
            context.Protocol);

        return new SecurityRule(
            Guid.NewGuid(),
            $"{decision}: {request.ProcessName ?? "network connection"}",
            SecurityModuleKind.TransferGuard,
            decision,
            RuleScope.ProcessPath,
            context.ProcessPath,
            true,
            decision ==
            RuleDecision.Block
                ? 200
                : 100,
            DateTimeOffset.UtcNow,
            null,
            conditions);
    }

    private static void AddCondition(
        ICollection<SecurityRuleCondition> conditions,
        RuleScope scope,
        string? value)
    {
        if (string.IsNullOrWhiteSpace(
                value))
        {
            return;
        }

        conditions.Add(
            new SecurityRuleCondition(
                scope,
                value));
    }
}