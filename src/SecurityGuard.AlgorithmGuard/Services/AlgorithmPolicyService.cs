using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.AlgorithmGuard.Configuration;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmPolicyService
{
    private readonly AlgorithmObservationService _observationService;
    private readonly AlgorithmRuleContextFactory _contextFactory;
    private readonly IAlgorithmTemporaryDecisionStore _temporaryDecisionStore;
    private readonly IRuleEngine _ruleEngine;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;
    private readonly AlgorithmGuardOptions _options;

    public AlgorithmPolicyService(
        AlgorithmObservationService observationService,
        AlgorithmRuleContextFactory contextFactory,
        IAlgorithmTemporaryDecisionStore temporaryDecisionStore,
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        AlgorithmGuardOptions options)
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

        _options =
            options;
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
                context,
                identity,
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
            correlationId: attempt.CorrelationId,
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
            correlationId: attempt.CorrelationId,
            cancellationToken: cancellationToken);
    }

    private async Task CreateDecisionRequestAsync(
        AlgorithmExecutionAttempt attempt,
        RuleMatchContext context,
        string identity,
        CancellationToken cancellationToken)
    {
        var now =
            DateTimeOffset.UtcNow;

        await _decisionRepository.RemoveOlderThanAsync(
            now - _options.PendingDecisionLifetime,
            cancellationToken);

        var actions =
            GetAvailableActions(
                attempt);

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
                now,
                context,
                identity);

        var added =
            await _decisionRepository.TryAddAsync(
                request,
                cancellationToken);

        if (!added)
        {
            return;
        }

        await _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.AlgorithmExecution,
            SecuritySeverity.Medium,
            "Algorithm requires decision",
            BuildDetails(attempt),
            SecurityAction.None,
            correlationId: attempt.CorrelationId,
            cancellationToken: cancellationToken);
    }
    private static string BuildExecutionChain(
        AlgorithmExecutionAttempt attempt)
    {
        var ancestry =
            attempt.ExecutionChain ??
            [];

        return string.Join(
            " > ",
            ancestry
                .Reverse()
                .Select(
                    item =>
                        item.ProcessName)
                .Append(
                    attempt.ProcessName));
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
                $"User: {attempt.UserName ?? "Unknown"}",
                $"Process: {attempt.ProcessName}",
                $"Executable: {attempt.ExecutablePath ?? "Unknown"}",
                $"Process publisher: {attempt.ProcessPublisher ?? "Unknown"}",
                $"Process signature: {attempt.ProcessSignatureStatus ?? "Unknown"}",
                $"Parent PID: {attempt.ParentProcessId?.ToString() ?? "Unknown"}",
                $"Parent process: {attempt.ParentProcessName ?? "Unknown"}",
                $"Parent executable: {attempt.ParentExecutablePath ?? "Unknown"}",
                $"Execution chain: {BuildExecutionChain(attempt)}",
                $"Interpreter: {attempt.Interpreter}",
                $"Invocation: {attempt.InvocationType}",
                $"Script: {attempt.ScriptPath ?? "None"}",
                $"SHA256: {attempt.ScriptSha256 ?? "Unknown"}",
                $"Script publisher: {attempt.ScriptPublisher ?? "Unknown"}",
                $"Script signature: {attempt.ScriptSignatureStatus ?? "Unknown"}",
                $"CommandLine: {attempt.CommandLine ?? "Unknown"}"
            });
    }
}