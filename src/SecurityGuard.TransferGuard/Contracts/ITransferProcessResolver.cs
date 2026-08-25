using SecurityGuard.Core.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferProcessResolver
{
    Task<ProcessInfo?> GetAsync(
        int processId,
        CancellationToken cancellationToken = default);
}