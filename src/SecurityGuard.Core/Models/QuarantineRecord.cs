namespace SecurityGuard.Core.Models;

public sealed record QuarantineRecord(
    Guid Id,
    string OriginalPath,
    string StoredPath,
    string OriginalFileName,
    string Sha256,
    long SizeBytes,
    string SourceModule,
    string Reason,
    DateTimeOffset QuarantinedAtUtc);