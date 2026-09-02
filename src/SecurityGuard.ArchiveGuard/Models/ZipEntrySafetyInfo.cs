namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ZipEntrySafetyInfo(
    string FullName,
    string NormalizedPath,
    long CompressedLength,
    long ExpandedLength,
    double CompressionRatio,
    bool IsDirectory,
    bool IsEncrypted,
    bool IsNestedContainerCandidate);