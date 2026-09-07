using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardDecisionExecutor
{
    Task<ArchiveGuardDecisionExecutionResult> ExecuteAsync(
        Guid decisionRequestId,
        SecurityAction action,
        CancellationToken cancellationToken = default);
}