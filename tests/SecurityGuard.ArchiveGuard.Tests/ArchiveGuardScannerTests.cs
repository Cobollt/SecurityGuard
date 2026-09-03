using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Enums;
using Xunit;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardScannerTests
{
    [Fact]
    public async Task Clean_file_returns_clean_result()
    {
        var metadata =
            CreateMetadata();

        var metadataService =
            new FakeMetadataService(
                metadata);

        var scanner =
            new ArchiveGuardScanner(
                metadataService,
                []);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.NotEqual(
            Guid.Empty,
            result.Id);

        Assert.Equal(
            metadata.FilePath,
            result.FilePath);

        Assert.Equal(
            metadata.Sha256,
            result.Sha256);

        Assert.Equal(
            metadata.Length,
            result.FileSize);

        Assert.Equal(
            metadata.FileType,
            result.FileType);

        Assert.Equal(
            ScanVerdict.Clean,
            result.Verdict);

        Assert.Empty(
            result.Findings);

        Assert.True(
            result.CompletedAtUtc >=
            result.StartedAtUtc);
    }

    [Fact]
    public async Task Suspicious_finding_returns_suspicious_result()
    {
        var metadata =
            CreateMetadata();

        var finding =
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Double extension",
                "File has a suspicious double extension.");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new FakeAnalyzer(
                        finding)
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Suspicious,
            result.Verdict);

        var storedFinding =
            Assert.Single(
                result.Findings);

        Assert.Equal(
            ArchiveFindingKind.DoubleExtension,
            storedFinding.Kind);

        Assert.Equal(
            ScanVerdict.Suspicious,
            storedFinding.Verdict);

        Assert.Equal(
            SecuritySeverity.High,
            storedFinding.Severity);
    }

    [Fact]
    public async Task Malicious_finding_has_priority_over_suspicious()
    {
        var metadata =
            CreateMetadata();

        var suspicious =
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Double extension",
                "Suspicious file name.");

        var malicious =
            new ArchiveScanFinding(
                ArchiveFindingKind.KnownMaliciousHash,
                ScanVerdict.Malicious,
                SecuritySeverity.Critical,
                "Known malicious hash",
                "File hash matches a blocked hash.");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new FakeAnalyzer(
                        suspicious),

                    new FakeAnalyzer(
                        malicious)
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Malicious,
            result.Verdict);

        Assert.Equal(
            2,
            result.Findings.Count);

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Verdict ==
                ScanVerdict.Suspicious);

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Verdict ==
                ScanVerdict.Malicious);
    }

    [Fact]
    public async Task Error_finding_has_priority_over_suspicious()
    {
        var metadata =
            CreateMetadata();

        var suspicious =
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Double extension",
                "Suspicious file name.");

        var error =
            new ArchiveScanFinding(
                ArchiveFindingKind.AnalyzerFailure,
                ScanVerdict.Error,
                SecuritySeverity.High,
                "Analyzer failure",
                "Analyzer failed.");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new FakeAnalyzer(
                        suspicious),

                    new FakeAnalyzer(
                        error)
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Error,
            result.Verdict);

        Assert.Equal(
            2,
            result.Findings.Count);
    }

    [Fact]
    public async Task Suspicious_has_priority_over_unknown()
    {
        var metadata =
            CreateMetadata();

        var unknown =
            new ArchiveScanFinding(
                ArchiveFindingKind.AnalyzerFailure,
                ScanVerdict.Unknown,
                SecuritySeverity.Medium,
                "Incomplete analysis",
                "The content could not be fully classified.");

        var suspicious =
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Double extension",
                "Suspicious file name.");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new FakeAnalyzer(
                        unknown),

                    new FakeAnalyzer(
                        suspicious)
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Suspicious,
            result.Verdict);

        Assert.Equal(
            2,
            result.Findings.Count);
    }

    [Fact]
    public async Task Analyzer_failure_is_converted_to_error_finding()
    {
        var metadata =
            CreateMetadata();

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new ThrowingAnalyzer(
                        new InvalidOperationException(
                            "Analyzer failure"))
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Error,
            result.Verdict);

        var finding =
            Assert.Single(
                result.Findings);

        Assert.Equal(
            ArchiveFindingKind.AnalyzerFailure,
            finding.Kind);

        Assert.Equal(
            ScanVerdict.Error,
            finding.Verdict);

        Assert.Equal(
            SecuritySeverity.High,
            finding.Severity);

        Assert.Contains(
            "Analyzer failure",
            finding.Details,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Analyzer_failure_does_not_stop_other_analyzers()
    {
        var metadata =
            CreateMetadata();

        var suspicious =
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Double extension",
                "Suspicious file name.");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    new ThrowingAnalyzer(
                        new InvalidOperationException(
                            "Failed analyzer")),

                    new FakeAnalyzer(
                        suspicious)
                ]);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            ScanVerdict.Error,
            result.Verdict);

        Assert.Equal(
            2,
            result.Findings.Count);

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.AnalyzerFailure);

        Assert.Contains(
            result.Findings,
            finding =>
                finding.Kind ==
                ArchiveFindingKind.DoubleExtension);
    }

    [Fact]
    public async Task Metadata_failure_returns_error_result()
    {
        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    new IOException(
                        "Unable to read file")),
                []);

        var filePath =
            Path.Combine(
                Path.GetTempPath(),
                "missing.zip");

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    filePath));

        Assert.NotEqual(
            Guid.Empty,
            result.Id);

        Assert.Equal(
            filePath,
            result.FilePath);

        Assert.Null(
            result.Sha256);

        Assert.Null(
            result.FileSize);

        Assert.Equal(
            DetectedFileType.Unknown,
            result.FileType);

        Assert.Equal(
            ScanVerdict.Error,
            result.Verdict);

        var finding =
            Assert.Single(
                result.Findings);

        Assert.Equal(
            ArchiveFindingKind.FileAccessFailure,
            finding.Kind);

        Assert.Equal(
            ScanVerdict.Error,
            finding.Verdict);

        Assert.Contains(
            "Unable to read file",
            finding.Details,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Metadata_is_loaded_for_requested_file()
    {
        var metadata =
            CreateMetadata();

        var metadataService =
            new FakeMetadataService(
                metadata);

        var scanner =
            new ArchiveGuardScanner(
                metadataService,
                []);

        await scanner.ScanAsync(
            new ArchiveScanRequest(
                metadata.FilePath));

        Assert.Equal(
            1,
            metadataService.CallCount);

        Assert.Equal(
            metadata.FilePath,
            metadataService.LastFilePath);
    }

    [Fact]
    public async Task Every_analyzer_receives_same_metadata()
    {
        var metadata =
            CreateMetadata();

        var first =
            new RecordingAnalyzer();

        var second =
            new RecordingAnalyzer();

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    first,
                    second
                ]);

        await scanner.ScanAsync(
            new ArchiveScanRequest(
                metadata.FilePath));

        Assert.Same(
            metadata,
            first.Metadata);

        Assert.Same(
            metadata,
            second.Metadata);

        Assert.Equal(
            1,
            first.CallCount);

        Assert.Equal(
            1,
            second.CallCount);
    }

    [Fact]
    public async Task Metadata_cancellation_is_propagated()
    {
        using var cancellation =
            new CancellationTokenSource();

        cancellation.Cancel();

        var scanner =
            new ArchiveGuardScanner(
                new CancellationMetadataService(),
                []);

        await Assert.ThrowsAnyAsync<
            OperationCanceledException>(
                () =>
                    scanner.ScanAsync(
                        new ArchiveScanRequest(
                            "cancelled.zip"),
                        cancellation.Token));
    }

    [Fact]
    public async Task Analyzer_cancellation_is_propagated()
    {
        var metadata =
            CreateMetadata();

        using var cancellation =
            new CancellationTokenSource();

        var analyzer =
            new CancellingAnalyzer(
                cancellation);

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                [
                    analyzer
                ]);

        await Assert.ThrowsAnyAsync<
            OperationCanceledException>(
                () =>
                    scanner.ScanAsync(
                        new ArchiveScanRequest(
                            metadata.FilePath),
                        cancellation.Token));
    }

    [Fact]
    public async Task Scan_result_preserves_detected_archive_type()
    {
        var metadata =
            CreateMetadata(
                DetectedFileType.SevenZip,
                ".7z");

        var scanner =
            new ArchiveGuardScanner(
                new FakeMetadataService(
                    metadata),
                []);

        var result =
            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    metadata.FilePath));

        Assert.Equal(
            DetectedFileType.SevenZip,
            result.FileType);

        Assert.Equal(
            metadata.Sha256,
            result.Sha256);

        Assert.Equal(
            metadata.Length,
            result.FileSize);
    }

    private static ArchiveFileMetadata CreateMetadata(
        DetectedFileType fileType =
            DetectedFileType.Zip,
        string extension =
            ".zip")
    {
        var filePath =
            Path.Combine(
                Path.GetTempPath(),
                $"archive-{Guid.NewGuid():N}{extension}");

        return new ArchiveFileMetadata(
            filePath,
            Path.GetFileName(
                filePath),
            extension,
            4096,
            DateTimeOffset.UtcNow,
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            [
                0x50,
                0x4B,
                0x03,
                0x04
            ],
            fileType);
    }

    private sealed class FakeMetadataService
        : IArchiveFileMetadataService
    {
        private readonly ArchiveFileMetadata? _metadata;
        private readonly Exception? _exception;

        public FakeMetadataService(
            ArchiveFileMetadata metadata)
        {
            _metadata =
                metadata;
        }

        public FakeMetadataService(
            Exception exception)
        {
            _exception =
                exception;
        }

        public int CallCount { get; private set; }

        public string? LastFilePath { get; private set; }

        public Task<ArchiveFileMetadata> LoadAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CallCount++;

            LastFilePath =
                filePath;

            if (_exception is not null)
            {
                return Task.FromException<
                    ArchiveFileMetadata>(
                        _exception);
            }

            return Task.FromResult(
                _metadata!);
        }
    }

    private sealed class CancellationMetadataService
        : IArchiveFileMetadataService
    {
        public Task<ArchiveFileMetadata> LoadAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            throw new OperationCanceledException(
                cancellationToken);
        }
    }

    private sealed class FakeAnalyzer
        : IArchiveFileAnalyzer
    {
        private readonly IReadOnlyList<ArchiveScanFinding> _findings;

        public FakeAnalyzer(
            params ArchiveScanFinding[] findings)
        {
            _findings =
                findings;
        }

        public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                _findings);
        }
    }

    private sealed class RecordingAnalyzer
        : IArchiveFileAnalyzer
    {
        public ArchiveFileMetadata? Metadata { get; private set; }

        public int CallCount { get; private set; }

        public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            Metadata =
                metadata;

            CallCount++;

            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                    []);
        }
    }

    private sealed class ThrowingAnalyzer
        : IArchiveFileAnalyzer
    {
        private readonly Exception _exception;

        public ThrowingAnalyzer(
            Exception exception)
        {
            _exception =
                exception;
        }

        public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromException<
                IReadOnlyList<ArchiveScanFinding>>(
                    _exception);
        }
    }

    private sealed class CancellingAnalyzer
        : IArchiveFileAnalyzer
    {
        private readonly CancellationTokenSource _cancellation;

        public CancellingAnalyzer(
            CancellationTokenSource cancellation)
        {
            _cancellation =
                cancellation;
        }

        public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            _cancellation.Cancel();

            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                    []);
        }
    }

    private static byte[] CreateTarBytes(
        string entryName,
        byte[] content)
    {
        using var memory =
            new MemoryStream();

        using (
            var writer =
                new System.Formats.Tar.TarWriter(
                    memory,
                    leaveOpen:
                        true))
        {
            var entry =
                new System.Formats.Tar.PaxTarEntry(
                    System.Formats.Tar.TarEntryType.RegularFile,
                    entryName)
                {
                    DataStream =
                        new MemoryStream(
                            content)
                };

            writer.WriteEntry(
                entry);
        }

        return memory.ToArray();
    }

    [Fact]
    public async Task Tar_gzip_is_scanned_recursively()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var tar =
                CreateTarBytes(
                    "invoice.pdf.exe",
                    "test"u8.ToArray());

            var file =
                Path.Combine(
                    root,
                    "archive.tar.gz");

            await using (
                var output =
                    File.Create(
                        file))
            {
                await using var gzip =
                    new System.IO.Compression.GZipStream(
                        output,
                        System.IO.Compression.CompressionLevel.SmallestSize);

                await gzip.WriteAsync(
                    tar);
            }

            var result =
                await CreateScanner()
                    .ScanAsync(
                        new ArchiveScanRequest(
                            file));

            Assert.Equal(
                DetectedFileType.Gzip,
                result.FileType);

            Assert.Equal(
                ScanVerdict.Suspicious,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                        ArchiveFindingKind.DoubleExtension &&
                    finding.EntryPath is not null);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Suspicious_file_inside_7z_is_detected()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "archive.7z");

            await using (
                var output =
                    File.Create(
                        file))
            {
                using var writer =
                    SharpCompress.Writers.WriterFactory.OpenWriter(
                        output,
                        SharpCompress.Common.ArchiveType.SevenZip,
                        new SharpCompress.Writers.SevenZip.SevenZipWriterOptions(
                            SharpCompress.Common.CompressionType.LZMA2));

                using var content =
                    new MemoryStream(
                        "test"u8.ToArray());

                writer.Write(
                    "invoice.pdf.exe",
                    content,
                    DateTime.UtcNow);
            }

            var result =
                await CreateScanner()
                    .ScanAsync(
                        new ArchiveScanRequest(
                            file));

            Assert.Equal(
                DetectedFileType.SevenZip,
                result.FileType);

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
    public void Rar_handler_supports_rar()
    {
        var handler =
            new RarArchiveFormatHandler();

        Assert.Equal(
            DetectedFileType.Rar,
            handler.FileType);

        Assert.False(
            handler.RequiresSeekableInput);
    }
}    