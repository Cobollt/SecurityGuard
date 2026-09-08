using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Ipc.ArchiveGuard;

public sealed record ArchiveGuardScanIpcRequest(
    string FilePath);

public sealed record ArchiveGuardRecentScansIpcRequest(
    int Limit = 50);

public sealed record ArchiveGuardFindingIpcDto(
    string Kind,
    ScanVerdict Verdict,
    SecuritySeverity Severity,
    string Title,
    string Details,
    string? EntryPath);

public sealed record ArchiveGuardScanIpcDto(
    Guid ScanId,
    string FilePath,
    string? Sha256,
    long? FileSize,
    ScanVerdict Verdict,
    string FileType,
    IReadOnlyList<ArchiveGuardFindingIpcDto> Findings,
    Guid? DecisionRequestId,
    IReadOnlyList<SecurityAction> AvailableActions,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc);

public sealed record ArchiveGuardRecentScanIpcDto(
    Guid Id,
    string FilePath,
    string? Sha256,
    long? FileSize,
    ScanVerdict Verdict,
    string Summary,
    DateTimeOffset CompletedAtUtc);