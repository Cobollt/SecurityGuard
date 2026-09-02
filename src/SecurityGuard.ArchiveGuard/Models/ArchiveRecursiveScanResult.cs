using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveRecursiveScanResult(
    ScanVerdict Verdict,
    IReadOnlyList<ArchiveScanFinding> Findings,
    long ExpandedBytesRead,
    int EntriesInspected,
    int ArchivesInspected,
    bool BudgetExhausted);