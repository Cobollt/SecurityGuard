using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface IFilteringPlatformAuditPolicyService
{
    Task<FilteringPlatformAuditState> GetAsync(
        CancellationToken cancellationToken = default);

    Task<FilteringPlatformAuditState> EnsureSuccessEnabledAsync(
        CancellationToken cancellationToken = default);
}