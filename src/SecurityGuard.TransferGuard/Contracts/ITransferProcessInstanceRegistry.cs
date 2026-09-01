using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferProcessInstanceRegistry
{
    void Prime();

    TransferProcessInstanceId? Resolve(
        int processId);

    TransferProcessInstanceId RegisterStart(
        int processId,
        DateTimeOffset detectedAtUtc);

    TransferProcessInstanceId? RegisterStop(
        int processId);

    IReadOnlyList<TransferProcessInstanceId> PruneStale();
}