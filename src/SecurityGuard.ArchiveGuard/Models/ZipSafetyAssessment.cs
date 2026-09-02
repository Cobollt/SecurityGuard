namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ZipSafetyAssessment(
    bool IsValidStructure,
    int EntryCount,
    long TotalCompressedBytes,
    long TotalExpandedBytes,
    IReadOnlyList<ZipEntrySafetyInfo> Entries,
    IReadOnlyList<ArchiveScanFinding> Findings,
    bool EntriesTruncated,
    bool FindingsTruncated);