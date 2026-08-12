using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record ProtectedObject(
    Guid Id,
    string Path,
    string FileName,
    string Extension,
    string Sha256,
    long SizeBytes,
    ObjectTrustStatus TrustStatus,
    DateTimeOffset FirstSeenAtUtc,
    DateTimeOffset LastSeenAtUtc);