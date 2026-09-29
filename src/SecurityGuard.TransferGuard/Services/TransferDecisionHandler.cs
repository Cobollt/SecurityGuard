using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Constants;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IRuleRepository _ruleRepository;
    private readonly ITransferEnforcementService _enforcementService;
    private readonly TransferEnforcementRuleFactory _enforcementRuleFactory;
    private readonly ITransferGuardRuntimeController _runtimeController;
    private readonly ITransferFileEnforcementCoordinator _fileEnforcementCoordinator;
    private readonly ITransferTemporaryEnforcementService _temporaryEnforcementService;

    public TransferDecisionHandler(
        IRuleRepository ruleRepository,
        ITransferEnforcementService enforcementService,
        TransferEnforcementRuleFactory enforcementRuleFactory,
        ITransferGuardRuntimeController runtimeController,
        ITransferFileEnforcementCoordinator fileEnforcementCoordinator,
        ITransferTemporaryEnforcementService temporaryEnforcementService)
    {
        _ruleRepository =
            ruleRepository;

        _enforcementService =
            enforcementService;

        _enforcementRuleFactory =
            enforcementRuleFactory;

        _runtimeController =
            runtimeController;

        _fileEnforcementCoordinator =
            fileEnforcementCoordinator;

        _temporaryEnforcementService =
            temporaryEnforcementService;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.TransferGuard;

    public async Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        if (decision.Action ==
            SecurityAction.AllowApplication)
        {
            await HandleApplicationDecisionAsync(
                request,
                cancellationToken);

            return;
        }

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

        if (request.EventType ==
            SecurityEventType.FileTransfer)
        {
            var fileRule =
                BuildFileRule(
                    request,
                    ruleDecision);

            if (ruleDecision ==
                RuleDecision.Block)
            {
                try
                {
                    await _fileEnforcementCoordinator.ApplyDecisionBlockAsync(
                        fileRule.Id,
                        request,
                        cancellationToken);
                }
                catch (TransferFileEnforcementException exception)
                {
                    await _runtimeController.ReportEnforcementFailureAsync(
                        exception.Message,
                        cancellationToken);

                    throw;
                }
            }

            try
            {
                await _ruleRepository.UpsertAsync(
                    fileRule,
                    cancellationToken);
            }
            catch
            {
                if (ruleDecision ==
                    RuleDecision.Block)
                {
                    try
                    {
                        await _temporaryEnforcementService.RemoveBySourceRuleIdAsync(
                            fileRule.Id,
                            cancellationToken);
                    }
                    catch
                    {
                    }
                }

                throw;
            }

            return;
        }

        if (request.EventType !=
            SecurityEventType.NetworkConnection)
        {
            throw new InvalidOperationException(
                $"Unsupported TransferGuard event type: {request.EventType}");
        }

        await HandleNetworkDecisionAsync(
            request,
            ruleDecision,
            cancellationToken);
    }

    private async Task HandleApplicationDecisionAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var context =
            request.RuleContext ??
            throw new InvalidOperationException(
                "TransferGuard rule context is missing.");

        if (string.IsNullOrWhiteSpace(
                context.ProcessPath))
        {
            throw new InvalidOperationException(
                "TransferGuard requires ProcessPath for application rules.");
        }

        var existingRules =
            await _ruleRepository.GetAllAsync(
                cancellationToken);

        var activities =
            new[]
            {
            Enums.TransferActivityKind.NetworkConnection,
            Enums.TransferActivityKind.FileTransfer
            };

        foreach (var activity in activities)
        {
            var activityValue =
                activity.ToString();

            var existingRule =
                existingRules.FirstOrDefault(
                    rule =>
                        rule.Module ==
                        SecurityModuleKind.TransferGuard &&
                        rule.Decision ==
                        RuleDecision.Allow &&
                        rule.Scope ==
                        RuleScope.ProcessPath &&
                        string.Equals(
                            rule.Value,
                            context.ProcessPath,
                            StringComparison.OrdinalIgnoreCase) &&
                        rule.Conditions is { Count: 1 } &&
                        rule.Conditions[0].Scope ==
                        RuleScope.TransferActivityKind &&
                        string.Equals(
                            rule.Conditions[0].Value,
                            activityValue,
                            StringComparison.OrdinalIgnoreCase));

            if (existingRule is not null)
            {
                if (!existingRule.Enabled ||
                    existingRule.ExpiresAtUtc is not null)
                {
                    await _ruleRepository.UpsertAsync(
                        existingRule with
                        {
                            Enabled = true,
                            ExpiresAtUtc = null
                        },
                        cancellationToken);
                }

                continue;
            }

            var rule =
                BuildApplicationRule(
                    request,
                    context.ProcessPath,
                    activity);

            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);
        }
    }

    private static SecurityRule BuildNetworkRule(
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
            RuleScope.TransferActivityKind,
            Enums.TransferActivityKind
                .NetworkConnection
                .ToString());

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
                ? TransferRulePriorities.NetworkBlock
                : TransferRulePriorities.NetworkAllow,
            DateTimeOffset.UtcNow,
            null,
            conditions);
    }

    private static SecurityRule BuildApplicationRule(
        SecurityDecisionRequest request,
        string processPath,
        Enums.TransferActivityKind activity)
    {
        var processName =
            !string.IsNullOrWhiteSpace(
                request.ProcessName)
                ? request.ProcessName
                : Path.GetFileNameWithoutExtension(
                    processPath);

        var priority =
            activity ==
            Enums.TransferActivityKind.FileTransfer
                ? TransferRulePriorities.FileTransferAllow
                : TransferRulePriorities.NetworkAllow;

        return new SecurityRule(
            Guid.NewGuid(),
            $"Allow application: {processName} ({activity})",
            SecurityModuleKind.TransferGuard,
            RuleDecision.Allow,
            RuleScope.ProcessPath,
            processPath,
            true,
            priority,
            DateTimeOffset.UtcNow,
            null,
            [
                new SecurityRuleCondition(
                RuleScope.TransferActivityKind,
                activity.ToString())
            ]);
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

    private async Task HandleNetworkDecisionAsync(
        SecurityDecisionRequest request,
        RuleDecision ruleDecision,
        CancellationToken cancellationToken)
    {
        var rule =
            BuildNetworkRule(
                request,
                ruleDecision);

        if (ruleDecision ==
            RuleDecision.Allow)
        {
            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return;
        }

        var settings =
            _runtimeController.CurrentSettings;

        if (!settings.Enabled ||
            settings.Mode ==
            Enums.TransferGuardMode.Monitor)
        {
            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return;
        }

        if (!_enforcementRuleFactory.TryCreate(
                rule,
                out var enforcementRule,
                out var error) ||
            enforcementRule is null)
        {
            var message =
                error ??
                "Unable to build Windows Firewall rule.";

            await _runtimeController.ReportEnforcementFailureAsync(
                message,
                cancellationToken);

            if (settings.FailurePolicy ==
                Enums.TransferEnforcementFailurePolicy.FailClosed)
            {
                throw new InvalidOperationException(
                    message);
            }

            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return;
        }

        try
        {
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
        catch (Exception exception)
        {
            await _runtimeController.ReportEnforcementFailureAsync(
                exception.Message,
                cancellationToken);

            if (settings.FailurePolicy ==
                Enums.TransferEnforcementFailurePolicy.FailClosed)
            {
                throw;
            }

            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return;
        }

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
    }

    private static SecurityRule BuildFileRule(
        SecurityDecisionRequest request,
        RuleDecision decision)
    {
        var context =
            request.RuleContext ??
            throw new InvalidOperationException(
                "TransferGuard file rule context is missing.");

        RuleScope primaryScope;
        string primaryValue;

        if (!string.IsNullOrWhiteSpace(
                context.FileHash))
        {
            primaryScope =
                RuleScope.FileHash;

            primaryValue =
                context.FileHash;
        }
        else if (!string.IsNullOrWhiteSpace(
                    context.FilePath))
        {
            primaryScope =
                RuleScope.FilePath;

            primaryValue =
                context.FilePath;
        }
        else
        {
            throw new InvalidOperationException(
                "FileHash and FilePath are missing.");
        }

        var conditions =
            new List<SecurityRuleCondition>();

        AddCondition(
            conditions,
            RuleScope.TransferActivityKind,
            Enums.TransferActivityKind
                .FileTransfer
                .ToString());

        AddCondition(
            conditions,
            RuleScope.FileCategory,
            context.FileCategory);

        if (!string.IsNullOrWhiteSpace(
                context.ProcessPath))
        {
            AddCondition(
                conditions,
                RuleScope.ProcessPath,
                context.ProcessPath);
        }
        else
        {
            AddCondition(
                conditions,
                RuleScope.Process,
                context.Process);
        }

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
            BuildFileRuleName(
                request,
                decision),
            SecurityModuleKind.TransferGuard,
            decision,
            primaryScope,
            primaryValue,
            true,
            decision ==
            RuleDecision.Block
                ? TransferRulePriorities.FileTransferBlock
                : TransferRulePriorities.FileTransferAllow,
            DateTimeOffset.UtcNow,
            null,
            conditions);
    }

    private static string BuildFileRuleName(
        SecurityDecisionRequest request,
        RuleDecision decision)
    {
        var fileName =
            !string.IsNullOrWhiteSpace(
                request.FilePath)
                ? Path.GetFileName(
                    request.FilePath)
                : "file";

        return
            $"{decision} file transfer: {fileName}";
    }
}