namespace SecurityGuard.ArchiveGuard.Models;

public sealed record AuthenticodePublisherInfo(
    string? Name,
    string Subject,
    string Issuer,
    string Thumbprint,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc);