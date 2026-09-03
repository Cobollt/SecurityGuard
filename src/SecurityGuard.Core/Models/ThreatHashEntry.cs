namespace SecurityGuard.Core.Models;

public sealed record ThreatHashEntry(
    string Sha256,
    string Source,
    string? Description,
    bool Enabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);