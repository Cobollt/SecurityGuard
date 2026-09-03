namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveFormatEntry(
    string FullName,
    long? ExpandedLength,
    long? CompressedLength,
    bool IsDirectory,
    bool IsEncrypted,
    bool IsLink,
    string? LinkTarget,
    DateTimeOffset? LastWriteAtUtc,
    Func<CancellationToken, ValueTask<Stream>> OpenAsync);