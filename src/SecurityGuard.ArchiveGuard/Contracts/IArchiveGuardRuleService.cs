using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardRuleService
{
    Task<bool> IsAllowedAsync(
        ArchiveGuardScanResult result,
        CancellationToken cancellationToken = default);
}