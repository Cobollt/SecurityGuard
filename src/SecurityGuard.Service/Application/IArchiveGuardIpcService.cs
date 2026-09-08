using SecurityGuard.Core.Ipc.ArchiveGuard;

namespace SecurityGuard.Service.Application;

public interface IArchiveGuardIpcService
{
    Task<ArchiveGuardScanIpcDto> ScanAsync(
        ArchiveGuardScanIpcRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ArchiveGuardRecentScanIpcDto>> GetRecentAsync(
        ArchiveGuardRecentScansIpcRequest request,
        CancellationToken cancellationToken = default);
}