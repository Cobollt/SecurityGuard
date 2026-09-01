namespace SecurityGuard.ArchiveGuard.Enums;

public enum ArchiveFindingKind
{
    KnownMaliciousHash = 0,
    DoubleExtension = 1,
    ExecutableContentMismatch = 2,
    AnalyzerFailure = 3,
    FileAccessFailure = 4,
    FileReadFailure = 5
}