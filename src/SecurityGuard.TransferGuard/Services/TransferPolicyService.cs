using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferPolicyService
{
    private readonly TransferRuleContextFactory _contextFactory;
    private readonly IRuleEngine _ruleEngine;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;
    private readonly TransferGuardOptions _options;
    private readonly IWindowsSystemProcessTrustService _systemProcessTrustService;
    private readonly ITransferGuardRuntimeState _runtimeState;

    public TransferPolicyService(
        TransferRuleContextFactory contextFactory,
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        TransferGuardOptions options,
        IWindowsSystemProcessTrustService systemProcessTrustService,
        ITransferGuardRuntimeState runtimeState)
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

        _systemProcessTrustService =
            systemProcessTrustService;

        _runtimeState =
            runtimeState;
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

        if (_runtimeState
                .CurrentSettings
                .TrustWindowsSystemProcesses &&
            await TryHandleTrustedWindowsProcessAsync(
                observation,
                cancellationToken))
        {
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

    private async Task<bool> TryHandleTrustedWindowsProcessAsync(
        NetworkConnectionObservation observation,
        CancellationToken cancellationToken)
    {
        var process =
            observation.Process;

        if (process is null)
        {
            return false;
        }

        var executablePath =
            !string.IsNullOrWhiteSpace(
                process.ExecutablePath)
                ? process.ExecutablePath
                : observation.ApplicationPath;

        var trustResult =
            await _systemProcessTrustService.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    process.ProcessId,
                    process.ProcessName,
                    executablePath,
                    process.Publisher),
                cancellationToken);

        if (!trustResult.IsTrusted)
        {
            return false;
        }

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            SecuritySeverity.Info,
            "Trusted Windows process outbound connection",
            BuildTrustedProcessDetails(
                observation,
                trustResult),
            SecurityAction.Allow,
            cancellationToken:
                cancellationToken);

        return true;
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
                    SecurityAction.AllowApplication,
                    SecurityAction.Block,
                    SecurityAction.BlockApplication
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

    private static string BuildTrustedProcessDetails(
        NetworkConnectionObservation observation,
        WindowsSystemProcessTrustResult trustResult)
    {
        return string.Join(
            Environment.NewLine,
            BuildDetails(
                observation),
            $"Trust: {trustResult.Reason}");
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
                $"Publisher: {observation.Process?.Publisher ?? "Unknown"}",
                $"WFP application: {observation.ApplicationPath ?? "Unknown"}",
                $"Local: {observation.LocalAddress}:{observation.LocalPort}",
                $"Remote: {observation.RemoteAddress}:{observation.RemotePort}"
            });
    }
}