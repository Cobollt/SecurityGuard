using SecurityGuard.ArchiveGuard.Analyzers;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardScannerTests
{
    [Fact]
    public async Task Normal_text_file_is_clean()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "document.txt");

            await File.WriteAllTextAsync(
                file,
                "SecurityGuard test file");

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Clean,
                result.Verdict);

            Assert.NotNull(
                result.Sha256);

            Assert.Empty(
                result.Findings);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private static ArchiveGuardScanner CreateScanner(
        IKnownThreatHashStore? hashStore = null)
    {
        var options =
            new ArchiveGuardOptions();

        var metadata =
            new ArchiveFileMetadataService(
                new TestFileHashService(),
                options);

        return new ArchiveGuardScanner(
            metadata,
            [
                new KnownThreatHashAnalyzer(
                    hashStore ??
                    new EmptyKnownThreatHashStore()),

                new DoubleExtensionAnalyzer(),

                new ExecutableContentMismatchAnalyzer()
            ]);
    }

    private static string CreateTemporaryDirectory()
    {
        var path =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.ArchiveGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(
            path);

        return path;
    }

    private sealed class TestFileHashService
        : IFileHashService
    {
        public async Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            await using var stream =
                File.OpenRead(
                    filePath);

            var hash =
                await System.Security.Cryptography.SHA256.HashDataAsync(
                    stream,
                    cancellationToken);

            return Convert.ToHexString(
                hash);
        }
    }

    [Fact]
    public async Task Double_extension_is_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "invoice.pdf.exe");

            await File.WriteAllTextAsync(
                file,
                "test");

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Suspicious,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.DoubleExtension);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Pe_content_with_pdf_extension_is_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "document.pdf");

            await File.WriteAllBytesAsync(
                file,
                [
                    0x4D,
                    0x5A,
                    0x90,
                    0x00,
                    0x03,
                    0x00
                ]);

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Suspicious,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ExecutableContentMismatch);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private sealed class MaliciousHashStore
        : IKnownThreatHashStore
    {
        private readonly string _hash;

        public MaliciousHashStore(
            string hash)
        {
            _hash =
                hash;
        }

        public Task<bool> IsMaliciousAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                string.Equals(
                    _hash,
                    sha256,
                    StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public async Task Known_malicious_hash_is_malicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "sample.bin");

            await File.WriteAllTextAsync(
                file,
                "known malicious test sample");

            string hash;

            await using (
                var stream =
                    File.OpenRead(
                        file))
            {
                hash =
                    Convert.ToHexString(
                        await System.Security.Cryptography.SHA256.HashDataAsync(
                            stream));
            }

            var scanner =
                CreateScanner(
                    new MaliciousHashStore(
                        hash));

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Malicious,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.KnownMaliciousHash);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Missing_file_returns_error()
    {
        var scanner =
            CreateScanner();

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    Path.Combine(
                        Path.GetTempPath(),
                        Guid.NewGuid().ToString("N"),
                        "missing.bin")));

        Assert.Equal(
            ScanVerdict.Error,
            result.Verdict);

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.FileAccessFailure);
    }

    private sealed class FailingAnalyzer
        : IArchiveFileAnalyzer
    {
        public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException(
                "Test analyzer failure");
        }
    }

    [Fact]
    public async Task Analyzer_failure_returns_error_verdict()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "document.txt");

            await File.WriteAllTextAsync(
                file,
                "test");

            var options =
                new ArchiveGuardOptions();

            var scanner =
                new ArchiveGuardScanner(
                    new ArchiveFileMetadataService(
                        new TestFileHashService(),
                        options),
                    [
                        new FailingAnalyzer()
                    ]);

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Error,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.AnalyzerFailure);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}