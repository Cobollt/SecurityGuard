using SecurityGuard.Core.Lists;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityListImportHistoryRepository
{
    Task<SecurityListImportRecord?> GetByPackageSha256Async(
        string packageSha256,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SecurityListImportRecord>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default);
}