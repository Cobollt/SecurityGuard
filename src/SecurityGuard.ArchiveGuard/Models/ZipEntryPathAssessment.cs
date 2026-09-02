namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ZipEntryPathAssessment(
    string NormalizedPath,
    bool IsAbsolute,
    bool HasTraversal,
    bool HasAlternateDataStream);