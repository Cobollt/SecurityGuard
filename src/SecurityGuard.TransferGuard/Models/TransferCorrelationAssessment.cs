using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferCorrelationAssessment(
    TransferCorrelationConfidence Confidence,
    double VolumeSimilarity);