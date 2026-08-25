using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IRuleRepository _ruleRepository;

    public TransferDecisionHandler(
        IRuleRepository ruleRepository)
    {
        _ruleRepository =
            ruleRepository;
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

        RuleScope primaryScope;
        string primaryValue;

        if (!string.IsNullOrWhiteSpace(
                context.ProcessPath))
        {
            primaryScope =
                RuleScope.ProcessPath;

            primaryValue =
                context.ProcessPath;
        }
        else if (!string.IsNullOrWhiteSpace(
                     context.Process))
        {
            primaryScope =
                RuleScope.Process;

            primaryValue =
                context.Process;
        }
        else if (!string.IsNullOrWhiteSpace(
                     context.RemoteAddress))
        {
            primaryScope =
                RuleScope.RemoteAddress;

            primaryValue =
                context.RemoteAddress;
        }
        else
        {
            throw new InvalidOperationException(
                "Unable to determine TransferGuard rule identity.");
        }

        var conditions =
            new List<SecurityRuleCondition>();

        AddCondition(
            conditions,
            RuleScope.RemoteAddress,
            context.RemoteAddress,
            primaryScope,
            primaryValue);

        AddCondition(
            conditions,
            RuleScope.RemotePort,
            context.RemotePort?.ToString(),
            primaryScope,
            primaryValue);

        AddCondition(
            conditions,
            RuleScope.Protocol,
            context.Protocol,
            primaryScope,
            primaryValue);

        return new SecurityRule(
            Guid.NewGuid(),
            BuildName(
                request,
                decision),
            SecurityModuleKind.TransferGuard,
            decision,
            primaryScope,
            primaryValue,
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
        string? value,
        RuleScope primaryScope,
        string primaryValue)
    {
        if (string.IsNullOrWhiteSpace(
                value))
        {
            return;
        }

        if (scope ==
            primaryScope &&
            string.Equals(
                value,
                primaryValue,
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        conditions.Add(
            new SecurityRuleCondition(
                scope,
                value));
    }

    private static string BuildName(
        SecurityDecisionRequest request,
        RuleDecision decision)
    {
        return
            $"{decision}: {request.ProcessName ?? "network connection"}";
    }
}