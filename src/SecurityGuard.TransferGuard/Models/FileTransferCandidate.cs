using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record FileTransferCandidate(
    Guid Id,
    DateTimeOffset DetectedAtUtc,
    int ProcessId,
    string FilePath,
    string? Sha256,
    long ObservedReadBytes,
    long ObservedSentBytes,
    long? FileSize,
    TimeSpan TimeDifference,
    double VolumeSimilarity,
    TransferCorrelationConfidence Confidence,
    NetworkConnectionObservation Connection);