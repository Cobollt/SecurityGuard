using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record ScanResult(
    Guid Id,
    SecurityModuleKind Module,
    string FilePath,
    string? Sha256,
    long? FileSize,
    ScanVerdict Verdict,
    string Summary,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc);