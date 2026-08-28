using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardRuntimeState
    : ITransferGuardRuntimeState
{
    private TransferGuardSettings _currentSettings =
        TransferGuardSettings.Default;

    public TransferGuardSettings CurrentSettings =>
        Volatile.Read(
            ref _currentSettings);

    public void Update(
        TransferGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        Volatile.Write(
            ref _currentSettings,
            settings);
    }
}