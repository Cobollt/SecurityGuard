using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardDecisionRequestFactory
{
    public SecurityDecisionRequest Create(
        ArchiveGuardScanResult result)
    {
        ArgumentNullException.ThrowIfNull(
            result);

        var filePath =
            Path.GetFullPath(
                result.FilePath);

        var ruleContext =
            new RuleMatchContext(
                FileHash:
                    result.Sha256,
                FilePath:
                    filePath,
                FileName:
                    Path.GetFileName(
                        filePath),
                FileExtension:
                    Path.GetExtension(
                        filePath));

        return new SecurityDecisionRequest(
            Guid.NewGuid(),
            SecurityModuleKind.ArchiveGuard,
            SecurityEventType.ArchiveScan,
            GetTitle(
                result.Verdict),
            BuildDescription(
                result),
            filePath,
            null,
            GetAvailableActions(
                result.Verdict),
            DateTimeOffset.UtcNow,
            ruleContext,
            ArchiveGuardDecisionIdentity.Create(
                result));
    }

    private static IReadOnlyList<SecurityAction> GetAvailableActions(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Clean =>
                [],

            _ =>
            [
                SecurityAction.AllowOnce,
                SecurityAction.Quarantine,
                SecurityAction.Delete
            ]
        };
    }

    private static string GetTitle(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Malicious =>
                "Обнаружен вредоносный файл",

            ScanVerdict.Suspicious =>
                "Обнаружен подозрительный файл",

            ScanVerdict.Unknown =>
                "Файл проверен не полностью",

            ScanVerdict.Error =>
                "Ошибка проверки файла",

            _ =>
                "Проверка файла завершена"
        };
    }

    private static string BuildDescription(
        ArchiveGuardScanResult result)
    {
        var findings =
            result.Findings
                .Take(5)
                .Select(
                    finding =>
                        $"{finding.Kind}: {finding.Title}")
                .ToArray();

        var details =
            findings.Length == 0
                ? "Признаки не зарегистрированы."
                : string.Join(
                    Environment.NewLine,
                    findings);

        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Verdict: {result.Verdict}",
                $"File: {result.FilePath}",
                $"SHA256: {result.Sha256 ?? "Unavailable"}",
                $"Size: {result.FileSize?.ToString() ?? "Unknown"}",
                $"Type: {result.FileType}",
                details
            });
    }
}