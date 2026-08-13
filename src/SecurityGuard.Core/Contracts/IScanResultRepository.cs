using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IScanResultRepository
{
    Task AddAsync(
        ScanResult result,
        CancellationToken cancellationToken = default);

    Task<ScanResult?> GetLatestByHashAsync(
        string sha256,
        CancellationToken cancellationToken = default);
}