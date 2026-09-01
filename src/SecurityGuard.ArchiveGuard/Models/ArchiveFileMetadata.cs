using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveFileMetadata(
    string FilePath,
    string FileName,
    string Extension,
    long Length,
    DateTimeOffset LastWriteAtUtc,
    string Sha256,
    byte[] Header,
    DetectedFileType FileType);