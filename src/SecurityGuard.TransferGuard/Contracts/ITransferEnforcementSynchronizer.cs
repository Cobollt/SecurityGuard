using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferEnforcementSynchronizer
{
    Task<TransferEnforcementSyncResult> SynchronizeAsync(
        CancellationToken cancellationToken = default);
}