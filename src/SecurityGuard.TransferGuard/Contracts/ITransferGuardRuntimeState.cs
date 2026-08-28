using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferGuardRuntimeState
{
    TransferGuardSettings CurrentSettings { get; }
}