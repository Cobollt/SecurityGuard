using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Services;

public sealed class RuleEngine
    : IRuleEngine
{
    private readonly IRuleRepository _repository;

    public RuleEngine(
        IRuleRepository repository)
    {
        _repository =
            repository;
    }

    public async Task<RuleEvaluationResult> EvaluateAsync(
        SecurityModuleKind module,
        RuleMatchContext context,
        CancellationToken cancellationToken = default)
    {
        var now =
            DateTimeOffset.UtcNow;

        var rules =
            await _repository.GetEnabledAsync(
                cancellationToken);

        var matches =
            rules
                .Where(
                    rule =>
                        rule.Module ==
                        module)
                .Where(
                    rule =>
                        rule.ExpiresAtUtc is null ||
                        rule.ExpiresAtUtc > now)
                .Where(
                    rule =>
                        IsActivityCompatible(
                            rule,
                            context))
                .Where(
                    rule =>
                        IsMatch(
                            rule,
                            context))
                .OrderByDescending(
                    rule =>
                        rule.Priority)
                .ThenByDescending(
                    rule =>
                        rule.Decision ==
                        RuleDecision.Block)
                .ToArray();

        if (matches.Length == 0)
        {
            return RuleEvaluationResult.NoMatch();
        }

        var selected =
            matches[0];

        return new RuleEvaluationResult(
            true,
            selected.Decision,
            selected.Id,
            $"Matched rule: {selected.Name}");
    }

    private static bool IsMatch(
        SecurityRule rule,
        RuleMatchContext context)
    {
        if (!IsConditionMatch(
                rule.Scope,
                rule.Value,
                context))
        {
            return false;
        }

        var conditions =
            rule.Conditions ??
            [];

        return conditions.All(
            condition =>
                IsConditionMatch(
                    condition.Scope,
                    condition.Value,
                    context));
    }

    private static bool IsConditionMatch(
        RuleScope scope,
        string value,
        RuleMatchContext context)
    {
        var candidate =
            scope switch
            {
                RuleScope.FileHash =>
                    context.FileHash,

                RuleScope.FilePath =>
                    context.FilePath,

                RuleScope.FileName =>
                    context.FileName,

                RuleScope.FileExtension =>
                    context.FileExtension,

                RuleScope.Publisher =>
                    context.Publisher,

                RuleScope.Process =>
                    context.Process,

                RuleScope.ParentProcess =>
                    context.ParentProcess,

                RuleScope.Interpreter =>
                    context.Interpreter,

                RuleScope.RemoteAddress =>
                    context.RemoteAddress,

                RuleScope.RemotePort =>
                    context.RemotePort?.ToString(),

                RuleScope.Protocol =>
                    context.Protocol,

                RuleScope.DestinationProcess =>
                    context.DestinationProcess,

                RuleScope.CommandLine =>
                    context.CommandLine,

                RuleScope.UserName =>
                    context.UserName,

                RuleScope.ProcessPublisher =>
                    context.ProcessPublisher,

                RuleScope.ParentProcessPath =>
                    context.ParentProcessPath,

                RuleScope.RootProcess =>
                    context.RootProcess,

                RuleScope.RootProcessPath =>
                    context.RootProcessPath,

                RuleScope.ExecutionChain =>
                    context.ExecutionChain,
                
                RuleScope.ProcessPath =>
                    context.ProcessPath,

                RuleScope.FileCategory =>
                    context.FileCategory,

                RuleScope.TransferActivityKind =>
                    context.TransferActivityKind,
                _ =>
                    null
            };

        return candidate is not null &&
               string.Equals(
                   candidate,
                   value,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsActivityCompatible(
        SecurityRule rule,
        RuleMatchContext context)
    {
        if (rule.Module !=
            SecurityModuleKind.TransferGuard)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(
                context.TransferActivityKind))
        {
            return true;
        }

        if (HasScope(
                rule,
                RuleScope.TransferActivityKind))
        {
            return true;
        }

        var fileRule =
            IsFileTransferRule(
                rule);

        if (string.Equals(
                context.TransferActivityKind,
                "FileTransfer",
                StringComparison.OrdinalIgnoreCase))
        {
            return fileRule;
        }

        if (string.Equals(
                context.TransferActivityKind,
                "NetworkConnection",
                StringComparison.OrdinalIgnoreCase))
        {
            return !fileRule;
        }

        return true;
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