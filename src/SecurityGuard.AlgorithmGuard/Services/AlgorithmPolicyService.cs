using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmPolicyService
{
    private readonly AlgorithmObservationService _observationService;
    private readonly AlgorithmRuleContextFactory _contextFactory;
    private readonly IAlgorithmTemporaryDecisionStore _temporaryDecisionStore;
    private readonly IRuleEngine _ruleEngine;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;

    public AlgorithmPolicyService(
        AlgorithmObservationService observationService,
        AlgorithmRuleContextFactory contextFactory,
        IAlgorithmTemporaryDecisionStore temporaryDecisionStore,
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService)
    {
        _observationService =
            observationService;

        _contextFactory =
            contextFactory;

        _temporaryDecisionStore =
            temporaryDecisionStore;

        _ruleEngine =
            ruleEngine;

        _decisionRepository =
            decisionRepository;

        _auditService =
            auditService;
    }

    public async Task HandleAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default)
    {
        var enriched =
            await _observationService.EnrichAsync(
                attempt,
                cancellationToken);

        var identity =
            AlgorithmExecutionIdentity.Create(
                enriched);

        if (_temporaryDecisionStore.TryConsumeAllowOnce(
                identity))
        {
            await WriteAllowedOnceAsync(
                enriched,
                cancellationToken);

            return;
        }

        var context =
            _contextFactory.Create(
                enriched);

        var result =
            await _ruleEngine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                context,
                cancellationToken);

        if (result.Matched)
        {
            await HandleRuleMatchAsync(
                enriched,
                result,
                cancellationToken);

            return;
        }

        await CreateDecisionRequestAsync(
            enriched,
            cancellationToken);
    }

    private Task WriteAllowedOnceAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken)
    {
        return _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            SecuritySeverity.Info,
            "Algorithm allowed once",
            BuildDetails(attempt),
            SecurityAction.AllowOnce,
            cancellationToken: cancellationToken);
    }

    private Task HandleRuleMatchAsync(
        AlgorithmExecutionAttempt attempt,
        RuleEvaluationResult result,
        CancellationToken cancellationToken)
    {
        var action =
            result.Decision switch
            {
                RuleDecision.Allow =>
                    SecurityAction.Allow,

                RuleDecision.Block =>
                    SecurityAction.Block,

                _ =>
                    SecurityAction.None
            };

        var severity =
            result.Decision ==
            RuleDecision.Block
                ? SecuritySeverity.High
                : SecuritySeverity.Info;

        var title =
            result.Decision ==
            RuleDecision.Block
                ? "Algorithm matched block rule"
                : "Algorithm matched allow rule";

        return _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            severity,
            title,
            BuildDetails(attempt),
            action,
            cancellationToken: cancellationToken);
    }

    private async Task CreateDecisionRequestAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken)
    {
        var actions =
            GetAvailableActions(attempt);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Неизвестный запуск алгоритма",
                attempt.CommandLine ??
                attempt.ProcessName,
                attempt.ScriptPath,
                attempt.ProcessName,
                actions,
                DateTimeOffset.UtcNow);

        await _decisionRepository.AddAsync(
            request,
            cancellationToken);

        await _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            SecuritySeverity.Medium,
            "Algorithm requires decision",
            BuildDetails(attempt),
            SecurityAction.None,
            cancellationToken: cancellationToken);
    }

    private static IReadOnlyList<SecurityAction> GetAvailableActions(
        AlgorithmExecutionAttempt attempt)
    {
        if (attempt.InvocationType ==
            AlgorithmInvocationType.ScriptFile &&
            !string.IsNullOrWhiteSpace(
                attempt.ScriptPath))
        {
            return
            [
                SecurityAction.AllowOnce,
                SecurityAction.Allow,
                SecurityAction.Block,
                SecurityAction.Quarantine,
                SecurityAction.Delete
            ];
        }

        return
        [
            SecurityAction.AllowOnce,
            SecurityAction.Allow,
            SecurityAction.Block
        ];
    }

    private static string BuildDetails(
        AlgorithmExecutionAttempt attempt)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"PID: {attempt.ProcessId}",
                $"Parent PID: {attempt.ParentProcessId?.ToString() ?? "Unknown"}",
                $"Process: {attempt.ProcessName}",
                $"Executable: {attempt.ExecutablePath ?? "Unknown"}",
                $"Interpreter: {attempt.Interpreter}",
                $"Invocation: {attempt.InvocationType}",
                $"Script: {attempt.ScriptPath ?? "None"}",
                $"SHA256: {attempt.ScriptSha256 ?? "Unknown"}",
                $"CommandLine: {attempt.CommandLine ?? "Unknown"}"
            });
    }
}