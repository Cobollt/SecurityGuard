using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardDecisionExecutor
    : IArchiveGuardDecisionExecutor
{
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IArchiveGuardFileActionService _fileActions;
    private readonly IArchiveGuardAuditSink _audit;

    public ArchiveGuardDecisionExecutor(
        IDecisionRequestRepository decisionRepository,
        IArchiveGuardFileActionService fileActions,
        IArchiveGuardAuditSink audit)
    {
        _decisionRepository =
            decisionRepository;

        _fileActions =
            fileActions;

        _audit =
            audit;
    }

    public async Task<ArchiveGuardDecisionExecutionResult> ExecuteAsync(
        Guid decisionRequestId,
        SecurityAction action,
        CancellationToken cancellationToken = default)
    {
        var request =
            await _decisionRepository.GetByIdAsync(
                decisionRequestId,
                cancellationToken);

        if (request is null)
        {
            return new ArchiveGuardDecisionExecutionResult(
                false,
                action,
                "Decision request was not found.");
        }

        if (request.Module !=
            SecurityModuleKind.ArchiveGuard)
        {
            return new ArchiveGuardDecisionExecutionResult(
                false,
                action,
                "Decision request does not belong to ArchiveGuard.");
        }

        if (!request.AvailableActions.Contains(
                action))
        {
            return new ArchiveGuardDecisionExecutionResult(
                false,
                action,
                "Requested action is not available.");
        }

        if (string.IsNullOrWhiteSpace(
                request.FilePath))
        {
            return new ArchiveGuardDecisionExecutionResult(
                false,
                action,
                "Decision request does not contain a file path.");
        }

        try
        {
            var message =
                await ExecuteFileActionAsync(
                    request.FilePath,
                    request,
                    action,
                    cancellationToken);

            await _decisionRepository.RemoveAsync(
                request.Id,
                cancellationToken);

            await _audit.WriteAsync(
                SecurityEventType.ArchiveScan,
                GetSeverity(
                    action),
                "ArchiveGuard decision executed",
                $"DecisionRequestId={request.Id}; Action={action}; File={request.FilePath}",
                cancellationToken);

            return new ArchiveGuardDecisionExecutionResult(
                true,
                action,
                message);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            await _audit.WriteAsync(
                SecurityEventType.ArchiveScan,
                SecuritySeverity.High,
                "ArchiveGuard decision failed",
                $"DecisionRequestId={request.Id}; Action={action}; Error={exception.Message}",
                cancellationToken);

            return new ArchiveGuardDecisionExecutionResult(
                false,
                action,
                exception.Message);
        }
    }

    private async Task<string> ExecuteFileActionAsync(
        string filePath,
        SecurityGuard.Core.Models.SecurityDecisionRequest request,
        SecurityAction action,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case SecurityAction.AllowOnce:
                await _fileActions.KeepAsync(
                    filePath,
                    cancellationToken);

                return "File was kept.";

            case SecurityAction.Quarantine:
                await _fileActions.QuarantineAsync(
                    filePath,
                    BuildQuarantineReason(
                        request),
                    cancellationToken);

                return "File was moved to quarantine.";

            case SecurityAction.Delete:
                await _fileActions.DeleteAsync(
                    filePath,
                    cancellationToken);

                return "File was deleted.";

            default:
                throw new InvalidOperationException(
                    $"Unsupported ArchiveGuard action: {action}.");
        }
    }

    private static string BuildQuarantineReason(
        SecurityGuard.Core.Models.SecurityDecisionRequest request)
    {
        return
            $"ArchiveGuard decision {request.Id}: {request.Title}";
    }

    private static SecuritySeverity GetSeverity(
        SecurityAction action)
    {
        return action switch
        {
            SecurityAction.Delete =>
                SecuritySeverity.High,

            SecurityAction.Quarantine =>
                SecuritySeverity.High,

            _ =>
                SecuritySeverity.Info
        };
    }
}