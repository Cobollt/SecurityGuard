using System.Text;
using System.Text.RegularExpressions;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class ScriptStaticAnalyzer
    : IArchiveFileAnalyzer
{
    private static readonly HashSet<string> ScriptExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".ps1",
            ".psm1",
            ".psd1",
            ".bat",
            ".cmd",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".py"
        };

    private readonly ArchiveGuardOptions _options;

    public ScriptStaticAnalyzer(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!ScriptExtensions.Contains(
                metadata.Extension))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        var text =
            DecodeText(
                metadata.Header);

        if (string.IsNullOrWhiteSpace(
                text))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        var findings =
            new List<ArchiveScanFinding>();

        var encoded =
            Matches(
                text,
                @"\bpowershell(?:\.exe)?\b[^\r\n]{0,300}\s-(?:enc|encodedcommand)\b") ||
            Matches(
                text,
                @"\bfrombase64string\s*\(");

        var download =
            Matches(
                text,
                @"\b(?:invoke-webrequest|downloadstring|downloadfile|start-bitstransfer|urlopen|requests\.get)\b") ||
            Matches(
                text,
                @"\b(?:msxml2\.xmlhttp|winhttp\.winhttprequest)\b");

        var dynamicExecution =
            Matches(
                text,
                @"\b(?:invoke-expression|iex)\b") ||
            Matches(
                text,
                @"\b(?:eval|exec)\s*\(");

        var childProcess =
            Matches(
                text,
                @"\bstart-process\b") ||
            Matches(
                text,
                @"\bsubprocess\.(?:popen|run|call)\b") ||
            Matches(
                text,
                @"\bos\.system\s*\(") ||
            Matches(
                text,
                @"\bwscript\.shell\b");

        var largeEncodedBlob =
            Matches(
                text,
                @"[A-Za-z0-9+/]{200,}={0,2}");

        if (encoded)
        {
            AddFinding(
                findings,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ScriptEncodedCommand,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.High,
                    "Script contains encoded command execution",
                    $"File={metadata.FileName}"));
        }

        if (download &&
            (dynamicExecution ||
             childProcess))
        {
            AddFinding(
                findings,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ScriptDownloadExecute,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.High,
                    "Script combines download and execution behavior",
                    $"File={metadata.FileName}"));
        }

        if (largeEncodedBlob &&
            (encoded ||
             dynamicExecution))
        {
            AddFinding(
                findings,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ScriptObfuscation,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.High,
                    "Script contains likely encoded or obfuscated payload data",
                    $"File={metadata.FileName}"));
        }

        if (dynamicExecution &&
            encoded)
        {
            AddFinding(
                findings,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ScriptDynamicExecution,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.High,
                    "Script combines encoded data with dynamic execution",
                    $"File={metadata.FileName}"));
        }

        if (metadata.Length >
            metadata.Header.LongLength)
        {
            AddFinding(
                findings,
                new ArchiveScanFinding(
                    ArchiveFindingKind.ScriptAnalysisTruncated,
                    ScanVerdict.Unknown,
                    SecuritySeverity.Low,
                    "Script static analysis inspected only the bounded prefix",
                    $"AnalyzedBytes={metadata.Header.LongLength}; FileBytes={metadata.Length}"));
        }

        return Task.FromResult<
            IReadOnlyList<ArchiveScanFinding>>(
                findings);
    }

    private void AddFinding(
        ICollection<ArchiveScanFinding> findings,
        ArchiveScanFinding finding)
    {
        if (findings.Count >=
            _options.MaxScriptFindingsPerFile)
        {
            return;
        }

        findings.Add(
            finding);
    }

    private static bool Matches(
        string text,
        string pattern)
    {
        try
        {
            return Regex.IsMatch(
                text,
                pattern,
                RegexOptions.IgnoreCase |
                RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(
                    100));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static string DecodeText(
        byte[] data)
    {
        if (data.Length == 0)
        {
            return string.Empty;
        }

        if (data.Length >= 3 &&
            data[0] ==
                0xEF &&
            data[1] ==
                0xBB &&
            data[2] ==
                0xBF)
        {
            return Encoding.UTF8.GetString(
                data,
                3,
                data.Length -
                3);
        }

        if (data.Length >= 2 &&
            data[0] ==
                0xFF &&
            data[1] ==
                0xFE)
        {
            return Encoding.Unicode.GetString(
                data,
                2,
                data.Length -
                2);
        }

        if (data.Length >= 2 &&
            data[0] ==
                0xFE &&
            data[1] ==
                0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(
                data,
                2,
                data.Length -
                2);
        }

        return Encoding.UTF8.GetString(
            data);
    }
}