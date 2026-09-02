using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveScanFinding(
    ArchiveFindingKind Kind,
    ScanVerdict Verdict,
    SecuritySeverity Severity,
    string Title,
    string Details,
    string? EntryPath = null);