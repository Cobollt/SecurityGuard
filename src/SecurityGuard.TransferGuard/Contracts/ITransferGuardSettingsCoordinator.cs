using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferGuardSettingsCoordinator
{
    Task<TransferGuardSettings> GetAsync(
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default);
}