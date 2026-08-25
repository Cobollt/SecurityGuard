using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferPolicyService
{
    private readonly TransferRuleContextFactory _contextFactory;
    private readonly IRuleEngine _ruleEngine;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;
    private readonly TransferGuardOptions _options;

    public TransferPolicyService(
        TransferRuleContextFactory contextFactory,
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        TransferGuardOptions options)
    {
        _contextFactory =
            contextFactory;

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
        NetworkConnectionObservation observation,
        CancellationToken cancellationToken = default)
    {
        var context =
            _contextFactory.Create(
                observation);

        var result =
            await _ruleEngine.EvaluateAsync(
                SecurityModuleKind.TransferGuard,
                context,
                cancellationToken);

        if (result.Matched)
        {
            await HandleMatchAsync(
                observation,
                result,
                cancellationToken);

            return;
        }

        await CreateDecisionRequestAsync(
            observation,
            context,
            cancellationToken);
    }

    private Task HandleMatchAsync(
        NetworkConnectionObservation observation,
        RuleEvaluationResult result,
        CancellationToken cancellationToken)
    {
        var blocked =
            result.Decision ==
            RuleDecision.Block;

        return _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            blocked
                ? SecuritySeverity.High
                : SecuritySeverity.Info,
            blocked
                ? "Outbound connection matched block rule"
                : "Outbound connection matched allow rule",
            BuildDetails(
                observation),
            blocked
                ? SecurityAction.Block
                : SecurityAction.Allow,
            cancellationToken:
                cancellationToken);
    }

    private async Task CreateDecisionRequestAsync(
        NetworkConnectionObservation observation,
        RuleMatchContext context,
        CancellationToken cancellationToken)
    {
        var now =
            DateTimeOffset.UtcNow;

        await _decisionRepository.RemoveOlderThanAsync(
            now -
            _options.PendingDecisionLifetime,
            cancellationToken);

        var identity =
            TransferConnectionIdentity.Create(
                observation);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.TransferGuard,
                SecurityEventType.NetworkConnection,
                "Неизвестное исходящее соединение",
                BuildDescription(
                    observation),
                null,
                observation.Process?.ProcessName,
                [
                    SecurityAction.Allow,
                    SecurityAction.Block
                ],
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
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            SecuritySeverity.Medium,
            "Outbound connection requires decision",
            BuildDetails(
                observation),
            SecurityAction.None,
            cancellationToken:
                cancellationToken);
    }

    private static string BuildDescription(
        NetworkConnectionObservation observation)
    {
        return
            $"{observation.Process?.ProcessName ?? "Unknown"} → " +
            $"{observation.RemoteAddress}:{observation.RemotePort} " +
            $"({observation.Protocol})";
    }

    private static string BuildDetails(
        NetworkConnectionObservation observation)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Protocol: {observation.Protocol}",
                $"PID: {observation.Process?.ProcessId.ToString() ?? "Unknown"}",
                $"Process: {observation.Process?.ProcessName ?? "Unknown"}",
                $"Executable: {observation.Process?.ExecutablePath ?? "Unknown"}",
                $"WFP application: {observation.ApplicationPath ?? "Unknown"}",
                $"Local: {observation.LocalAddress}:{observation.LocalPort}",
                $"Remote: {observation.RemoteAddress}:{observation.RemotePort}"
            });
    }
}