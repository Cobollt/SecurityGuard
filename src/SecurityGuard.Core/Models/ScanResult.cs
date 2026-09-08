using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record ScanResult
{
    public Guid Id { get; init; }

    public SecurityModuleKind Module { get; init; }

    public string FilePath { get; init; }

    public string? Sha256 { get; init; }

    public long? FileSize { get; init; }

    public ScanVerdict Verdict { get; init; }

    public string Summary { get; init; }

    public int RiskScore { get; init; }

    public IReadOnlyList<string> Findings { get; init; }

    public DateTimeOffset StartedAtUtc { get; init; }

    public DateTimeOffset CompletedAtUtc { get; init; }

    public ScanResult(
        Guid id,
        SecurityModuleKind module,
        string filePath,
        string? sha256,
        long? fileSize,
        ScanVerdict verdict,
        string summary,
        DateTimeOffset startedAtUtc,
        DateTimeOffset completedAtUtc)
        : this(
            id,
            module,
            filePath,
            sha256,
            fileSize,
            verdict,
            summary,
            0,
            [],
            startedAtUtc,
            completedAtUtc)
    {
    }

    public ScanResult(
        Guid id,
        SecurityModuleKind module,
        string filePath,
        string? sha256,
        long? fileSize,
        ScanVerdict verdict,
        string summary,
        int riskScore,
        IReadOnlyList<string> findings,
        DateTimeOffset startedAtUtc,
        DateTimeOffset completedAtUtc)
    {
        Id =
            id;

        Module =
            module;

        FilePath =
            filePath;

        Sha256 =
            sha256;

        FileSize =
            fileSize;

        Verdict =
            verdict;

        Summary =
            summary;

        RiskScore =
            riskScore;

        Findings =
            findings;

        StartedAtUtc =
            startedAtUtc;

        CompletedAtUtc =
            completedAtUtc;
    }

    public ScanResult(
        Guid id,
        string filePath,
        string sha256,
        ScanVerdict verdict,
        int riskScore,
        IReadOnlyList<string> findings,
        DateTimeOffset startedAtUtc,
        DateTimeOffset completedAtUtc)
        : this(
            id,
            SecurityModuleKind.Core,
            filePath,
            sha256,
            null,
            verdict,
            string.Join(
                Environment.NewLine,
                findings),
            riskScore,
            findings,
            startedAtUtc,
            completedAtUtc)
    {
    }
}