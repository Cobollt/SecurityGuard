using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record FileTransferCandidate(
    Guid Id,
    DateTimeOffset DetectedAtUtc,
    int ProcessId,
    string FilePath,
    string? Sha256,
    long ObservedReadBytes,
    long? FileSize,
    TimeSpan TimeDifference,
    TransferCorrelationConfidence Confidence,
    NetworkConnectionObservation Connection);