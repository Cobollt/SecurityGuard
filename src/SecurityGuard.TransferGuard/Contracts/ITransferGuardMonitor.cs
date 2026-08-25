namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferGuardMonitor
{
    Task RunAsync(
        CancellationToken cancellationToken = default);
}