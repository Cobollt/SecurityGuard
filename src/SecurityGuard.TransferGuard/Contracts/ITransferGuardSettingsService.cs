using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferGuardSettingsService
{
    Task<TransferGuardSettings> GetAsync(
        CancellationToken cancellationToken = default);

    Task SaveAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default);
}