using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IProtectedObjectRepository
{
    Task<ProtectedObject?> FindByHashAsync(
        string sha256,
        CancellationToken cancellationToken = default);

    Task<ProtectedObject?> FindByPathAsync(
        string path,
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ProtectedObject protectedObject,
        CancellationToken cancellationToken = default);
}