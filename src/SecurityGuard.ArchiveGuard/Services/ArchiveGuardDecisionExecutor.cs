using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardDecisionExecutor
    : IArchiveGuardDecisionExecutor
{
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IArchiveGuardFileActionService _fileActions;
    private readonly IArchiveGuardExceptionService _exceptionService;
    private readonly IArchiveGuardAuditSink _audit;

    public ArchiveGuardDecisionExecutor(
        IDecisionRequestRepository decisionRepository,
        IArchiveGuardFileActionService fileActions,
        IArchiveGuardExceptionService exceptionService,
        IArchiveGuardAuditSink audit)
    {
        _decisionRepository =
            decisionRepository;

        _fileActions =
            fileActions;

        _exceptionService =
            exceptionService;

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
                await ExecuteActionAsync(
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

    private async Task<string> ExecuteActionAsync(
        SecurityDecisionRequest request,
        SecurityAction action,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case SecurityAction.AllowOnce:
                await _fileActions.KeepAsync(
                    request.FilePath!,
                    cancellationToken);

                return "File was kept.";

            case SecurityAction.Allow:
                await AddExceptionAsync(
                    request,
                    cancellationToken);

                await _fileActions.KeepAsync(
                    request.FilePath!,
                    cancellationToken);

                return "File was kept and a SHA-256 exception was added.";

            case SecurityAction.Quarantine:
                await _fileActions.QuarantineAsync(
                    request.FilePath!,
                    BuildQuarantineReason(
                        request),
                    cancellationToken);

                return "File was moved to quarantine.";

            case SecurityAction.Delete:
                await _fileActions.DeleteAsync(
                    request.FilePath!,
                    cancellationToken);

                return "File was deleted.";

            default:
                throw new InvalidOperationException(
                    $"Unsupported ArchiveGuard action: {action}.");
        }
    }

    private async Task AddExceptionAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var sha256 =
            request.RuleContext?.FileHash;

        if (string.IsNullOrWhiteSpace(
                sha256))
        {
            throw new InvalidOperationException(
                "A SHA-256 exception cannot be created because the decision request does not contain a file hash.");
        }

        await _exceptionService.AddSha256ExceptionAsync(
            sha256,
            Path.GetFileName(
                request.FilePath!),
            cancellationToken);
    }

    private static string BuildQuarantineReason(
        SecurityDecisionRequest request)
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

            SecurityAction.Allow =>
                SecuritySeverity.Medium,

            _ =>
                SecuritySeverity.Info
        };
    }
}