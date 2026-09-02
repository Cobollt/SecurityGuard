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
                new FileTypeDetector(),
                options);

        return new ArchiveGuardScanner(
            metadata,
            [
                new KnownThreatHashAnalyzer(
                    hashStore ??
                    new EmptyKnownThreatHashStore()),

                new DoubleExtensionAnalyzer(),

                new FileTypeMismatchAnalyzer(
                    new FileTypeCompatibilityService())
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

    private static byte[] CreatePeFile()
    {
        var data =
            new byte[512];

        data[0] =
            0x4D;

        data[1] =
            0x5A;

        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
            data.AsSpan(
                0x3C,
                4),
            0x80);

        data[0x80] =
            0x50;

        data[0x81] =
            0x45;

        data[0x82] =
            0x00;

        data[0x83] =
            0x00;

        return data;
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
                CreatePeFile());

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                DetectedFileType.Pe,
                result.FileType);

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

    [Fact]
    public async Task Zip_content_with_pdf_extension_is_suspicious()
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
                    0x50,
                    0x4B,
                    0x03,
                    0x04,
                    0x14,
                    0x00,
                    0x00,
                    0x00
                ]);

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                DetectedFileType.Zip,
                result.FileType);

            Assert.Equal(
                ScanVerdict.Suspicious,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.FileTypeMismatch);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Zip_container_with_docx_extension_is_not_mismatch()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "document.docx");

            await File.WriteAllBytesAsync(
                file,
                [
                    0x50,
                    0x4B,
                    0x03,
                    0x04,
                    0x14,
                    0x00,
                    0x00,
                    0x00
                ]);

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                DetectedFileType.Zip,
                result.FileType);

            Assert.DoesNotContain(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.FileTypeMismatch);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Real_pdf_is_detected()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "document.pdf");

            await File.WriteAllTextAsync(
                file,
                "%PDF-1.7\n%%EOF");

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                DetectedFileType.Pdf,
                result.FileType);

            Assert.Equal(
                ScanVerdict.Clean,
                result.Verdict);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Unknown_binary_file_is_not_automatically_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "data.bin");

            await File.WriteAllBytesAsync(
                file,
                [
                    0x10,
                    0x20,
                    0x30,
                    0x40
                ]);

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                DetectedFileType.Unknown,
                result.FileType);

            Assert.Equal(
                ScanVerdict.Clean,
                result.Verdict);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private static ArchiveGuardScanner CreateScanner(
        IKnownThreatHashStore? hashStore = null,
        ArchiveGuardOptions? options = null)
    {
        options ??=
            new ArchiveGuardOptions();

        var detector =
            new FileTypeDetector();

        var pathInspector =
            new ZipEntryPathInspector();

        var metadata =
            new ArchiveFileMetadataService(
                new TestFileHashService(),
                detector,
                options);

        IArchiveFileAnalyzer[] analyzers =
        [
            new KnownThreatHashAnalyzer(
                hashStore ??
                new EmptyKnownThreatHashStore()),

            new DoubleExtensionAnalyzer(),

            new FileTypeMismatchAnalyzer(
                new FileTypeCompatibilityService())
        ];

        var zipSafety =
            new ZipSafetyAnalyzer(
                options,
                pathInspector);

        var recursive =
            new ArchiveRecursiveScanner(
                options,
                zipSafety,
                pathInspector,
                detector,
                analyzers,
                new ArchiveTemporarySpoolService(
                    options));

        return new ArchiveGuardScanner(
            metadata,
            analyzers,
            recursive);
    }

    [Fact]
    public async Task Normal_zip_is_clean()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "archive.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "documents/readme.txt");

                await using var stream =
                    entry.Open();

                await using var writer =
                    new StreamWriter(
                        stream);

                await writer.WriteAsync(
                    "SecurityGuard");
            }

            var scanner =
                CreateScanner();

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Clean,
                result.Verdict);

            Assert.Equal(
                DetectedFileType.Zip,
                result.FileType);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Zip_path_traversal_is_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "archive.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "../outside.txt");

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    "test"u8.ToArray());
            }

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
                    ArchiveFindingKind.ZipPathTraversal);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}