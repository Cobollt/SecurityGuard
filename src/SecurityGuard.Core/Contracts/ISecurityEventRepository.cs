using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityEventRepository
{
    Task AddAsync(
        SecurityEvent securityEvent,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SecurityEvent>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default);
}