using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferTelemetryHealthTracker
{
    void RecordKernelDrop();

    void RecordWfpDrop();

    void RecordKernelSourceFailure();

    void RecordWfpSubscriptionFailure();

    void RecordWfpParseFailure();

    void RecordCorrelationFailure();

    TransferTelemetryHealthSnapshot GetSnapshot();
}