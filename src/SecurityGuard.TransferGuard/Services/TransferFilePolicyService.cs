using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferFilePolicyService
{
    private readonly TransferFileRuleContextFactory _contextFactory;
    private readonly IRuleEngine _ruleEngine;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;
    private readonly TransferGuardOptions _options;
    private readonly ITransferFileEnforcementCoordinator _enforcementCoordinator;

    public TransferFilePolicyService(
        TransferFileRuleContextFactory contextFactory,
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
        FileTransferCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            candidate);

        if (candidate.Confidence ==
            TransferCorrelationConfidence.Low)
        {
            return;
        }

        var context =
            _contextFactory.Create(
                candidate);

        var result =
            await _ruleEngine.EvaluateAsync(
                SecurityModuleKind.TransferGuard,
                context,
                cancellationToken);

        if (result.Matched)
        {
            await HandleMatchAsync(
                candidate,
                result,
                cancellationToken);

            return;
        }

        await CreateDecisionRequestAsync(
            candidate,
            context,
            cancellationToken);
    }

    private async Task HandleMatchAsync(
        FileTransferCandidate candidate,
        RuleEvaluationResult result,
        CancellationToken cancellationToken)
    {
        var blocked =
            result.Decision ==
            RuleDecision.Block;

        TransferFileEnforcementResult? enforcement =
            null;

        if (blocked)
        {
            if (result.MatchedRuleId is null)
            {
                throw new TransferFileEnforcementException(
                    "RuleEngine returned a matched FileTransfer block without a rule ID.");
            }

            enforcement =
                await _enforcementCoordinator.ApplyCandidateBlockAsync(
                    result.MatchedRuleId.Value,
                    candidate,
                    cancellationToken);
        }

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.FileTransfer,
            blocked
                ? SecuritySeverity.High
                : SecuritySeverity.Info,
            blocked
                ? "File transfer candidate matched block policy"
                : "File transfer candidate matched allow policy",
            BuildDetails(
                candidate,
                BuildPolicyResult(
                    blocked,
                    enforcement)),
            blocked
                ? SecurityAction.Block
                : SecurityAction.Allow,
            cancellationToken:
                cancellationToken);
    }

    private async Task CreateDecisionRequestAsync(
        FileTransferCandidate candidate,
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
            TransferFileDecisionIdentity.Create(
                candidate);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.TransferGuard,
                SecurityEventType.FileTransfer,
                "Возможная передача файла",
                BuildDescription(
                    candidate),
                candidate.FilePath,
                candidate.Connection.Process?.ProcessName,
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
            SecurityEventType.FileTransfer,
            candidate.Confidence ==
            TransferCorrelationConfidence.High
                ? SecuritySeverity.High
                : SecuritySeverity.Medium,
            "File transfer candidate requires decision",
            BuildDetails(
                candidate,
                "No matching file-transfer rule exists."),
            SecurityAction.None,
            cancellationToken:
                cancellationToken);
    }

    private static string BuildDescription(
        FileTransferCandidate candidate)
    {
        return
            $"{Path.GetFileName(candidate.FilePath)} → " +
            $"{candidate.Connection.RemoteAddress}:" +
            $"{candidate.Connection.RemotePort} " +
            $"({candidate.Connection.Protocol}, {candidate.Confidence})";
    }

    private static string BuildDetails(
        FileTransferCandidate candidate,
        string policy)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                policy,
                "Correlation only: file content transmission is not cryptographically proven.",
                $"Confidence: {candidate.Confidence}",
                $"Category: {candidate.Classification.Category}",
                $"PID: {candidate.ProcessId}",
                $"Process: {candidate.Connection.Process?.ProcessName ?? "Unknown"}",
                $"Executable: {candidate.Connection.Process?.ExecutablePath ?? "Unknown"}",
                $"File: {candidate.FilePath}",
                $"SHA256: {candidate.Sha256 ?? "Not calculated"}",
                $"Observed read bytes: {candidate.ObservedReadBytes}",
                $"Observed sent bytes: {candidate.ObservedSentBytes}",
                $"Volume similarity: {candidate.VolumeSimilarity:P1}",
                $"Remote: {candidate.Connection.RemoteAddress}:{candidate.Connection.RemotePort}",
                $"Protocol: {candidate.Connection.Protocol}"
            });
    }

    public TransferFilePolicyService(
        TransferFileRuleContextFactory contextFactory,
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        ITransferFileEnforcementCoordinator enforcementCoordinator,
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

        _enforcementCoordinator =
            enforcementCoordinator;

        _options =
            options;
    }

    private static string BuildPolicyResult(
        bool blocked,
        TransferFileEnforcementResult? enforcement)
    {
        if (!blocked)
        {
            return "Allow policy matched.";
        }

        if (enforcement is null)
        {
            return "Block policy matched.";
        }

        if (enforcement.Applied)
        {
            return
                $"Temporary Firewall enforcement active until " +
                $"{enforcement.ExpiresAtUtc:O}.";
        }

        if (enforcement.Skipped)
        {
            return
                $"Block policy matched. Temporary enforcement skipped: " +
                enforcement.Message;
        }

        return
            $"Block policy matched. Temporary enforcement failed: " +
            enforcement.Message;
    }
}