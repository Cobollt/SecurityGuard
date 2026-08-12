using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record ScanResult(
    Guid Id,
    string FilePath,
    string Sha256,
    ScanVerdict Verdict,
    int RiskScore,
    IReadOnlyList<string> Findings,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc);