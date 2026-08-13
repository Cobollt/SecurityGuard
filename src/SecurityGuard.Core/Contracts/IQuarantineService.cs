using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IQuarantineService
{
    Task<QuarantineRecord> QuarantineAsync(
        string filePath,
        SecurityModuleKind sourceModule,
        string reason,
        CancellationToken cancellationToken = default);

    Task<string> RestoreAsync(
        Guid quarantineId,
        string? destinationPath = null,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        Guid quarantineId,
        CancellationToken cancellationToken = default);
}