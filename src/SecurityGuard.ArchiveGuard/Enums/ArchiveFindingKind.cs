namespace SecurityGuard.ArchiveGuard.Enums;

public enum ArchiveFindingKind
{
    KnownMaliciousHash = 0,
    DoubleExtension = 1,
    ExecutableContentMismatch = 2,
    AnalyzerFailure = 3,
    FileAccessFailure = 4,
    FileTypeMismatch = 5,
    ZipEntryCountExceeded = 6,
    ZipExpandedSizeExceeded = 7,
    ZipEntrySizeExceeded = 8,
    ZipCompressionRatioExceeded = 9,
    ZipPathTraversal = 10,
    ZipAbsolutePath = 11,
    ZipDuplicatePath = 12,
    ZipEncryptedEntry = 13,
    ZipInvalidStructure = 14,
    ZipAlternateDataStreamPath = 15
}