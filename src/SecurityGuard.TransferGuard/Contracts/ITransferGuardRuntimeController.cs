using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferGuardRuntimeController
{
    TransferGuardSettings CurrentSettings { get; }

    Task ApplyAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default);

    Task ReportEnforcementFailureAsync(
        string message,
        CancellationToken cancellationToken = default);
}