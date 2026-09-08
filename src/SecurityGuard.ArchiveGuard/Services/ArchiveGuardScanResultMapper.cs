using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardScanResultMapper
{
    public ScanResult Map(
        ArchiveGuardScanResult source)
    {
        ArgumentNullException.ThrowIfNull(
            source);

        return new ScanResult(
            source.Id,
            SecurityModuleKind.ArchiveGuard,
            source.FilePath,
            source.Sha256,
            source.FileSize,
            source.Verdict,
            BuildSummary(
                source),
            source.StartedAtUtc,
            source.CompletedAtUtc);
    }

    private static string BuildSummary(
        ArchiveGuardScanResult source)
    {
        var findings =
            source.Findings
                .Take(10)
                .Select(
                    finding =>
                        string.IsNullOrWhiteSpace(
                            finding.EntryPath)
                            ? $"{finding.Kind}: {finding.Title}"
                            : $"{finding.EntryPath}: {finding.Kind}: {finding.Title}")
                .ToArray();

        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Type={source.FileType}",
                $"Verdict={source.Verdict}",
                $"Findings={source.Findings.Count}",
                findings.Length == 0
                    ? "No findings."
                    : string.Join(
                        Environment.NewLine,
                        findings)
            });
    }
}