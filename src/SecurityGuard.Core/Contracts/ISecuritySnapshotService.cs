using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecuritySnapshotService
{
    Task<SecuritySnapshot> GetAsync(
        CancellationToken cancellationToken = default);
}