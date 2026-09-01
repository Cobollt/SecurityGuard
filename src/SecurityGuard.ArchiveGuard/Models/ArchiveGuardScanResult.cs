using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveGuardScanResult(
    Guid Id,
    string FilePath,
    string? Sha256,
    long? FileSize,
    ScanVerdict Verdict,
    IReadOnlyList<ArchiveScanFinding> Findings,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    DetectedFileType FileType = DetectedFileType.Unknown);