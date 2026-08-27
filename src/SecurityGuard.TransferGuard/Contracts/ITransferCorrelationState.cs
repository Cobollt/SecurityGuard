using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferCorrelationState
{
    void RecordFileRead(
        FileReadActivity activity);

    void RecordConnection(
        NetworkConnectionObservation observation);

    void RecordNetworkSend(
        NetworkSendActivity activity);

    IReadOnlyList<RecentFileRead> GetRecentFiles(
        int processId,
        DateTimeOffset referenceTime);

    IReadOnlyList<NetworkConnectionObservation> GetRecentConnections(
        int processId,
        DateTimeOffset referenceTime);

    IReadOnlyList<RecentNetworkSend> GetRecentNetworkSends(
        int processId,
        DateTimeOffset referenceTime);
}