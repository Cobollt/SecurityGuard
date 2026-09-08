using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Ipc.ArchiveGuard;

namespace SecurityGuard.UI.Services;

public interface IArchiveGuardUiGateway
{
    Task<ArchiveGuardScanIpcDto> ScanAsync(
        string filePath,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ArchiveGuardRecentScanIpcDto>> GetRecentAsync(
        int limit = 50,
        CancellationToken cancellationToken = default);

    Task SubmitDecisionAsync(
        Guid decisionRequestId,
        SecurityAction action,
        CancellationToken cancellationToken = default);
}