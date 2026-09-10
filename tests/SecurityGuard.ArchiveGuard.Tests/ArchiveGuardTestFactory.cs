using System.Security.Cryptography;
using SecurityGuard.ArchiveGuard.Analyzers;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Formats;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

internal static class ArchiveGuardTestFactory
{
    public static ArchiveGuardScanner CreateUnitScanner(
        IArchiveFileMetadataService metadataService,
        IEnumerable<IArchiveFileAnalyzer> analyzers)
    {
        return new ArchiveGuardScanner(
            metadataService,
            analyzers,
            [],
            new NullArchiveRecursiveScanner(),
            new AlwaysConsistentService(),
            new NullScanCache());
    }

    public static ArchiveGuardScanner CreateScanner(
        IKnownThreatHashStore? threatHashStore = null,
        ArchiveGuardOptions? options = null)
    {
        options ??=
            new ArchiveGuardOptions();

        var fileTypeDetector =
            new FileTypeDetector();

        var analyzers =
            new IArchiveFileAnalyzer[]
            {
                new KnownThreatHashAnalyzer(
                    threatHashStore ??
                    new EmptyThreatHashStore()),

                new DoubleExtensionAnalyzer(),

                new FileTypeMismatchAnalyzer(
                    new FileTypeCompatibilityService()),

                new ScriptStaticAnalyzer(
                    options)
            };

        var peStaticAnalyzer =
            new PeStaticAnalyzer(
                options);

        var seekableAnalyzers =
            new IArchiveSeekableContentAnalyzer[]
            {
                new PeSeekableContentAnalyzer(
                    peStaticAnalyzer)
            };

        var handlers =
            new IArchiveFormatHandler[]
            {
                new ZipArchiveFormatHandler(),
                new TarArchiveFormatHandler(),
                new GzipArchiveFormatHandler(),
                new SevenZipArchiveFormatHandler(),
                new RarArchiveFormatHandler()
            };

        var spoolService =
            new ArchiveTemporarySpoolService(
                options);

        var recursiveScanner =
            new ArchiveRecursiveScanner(
                options,
                handlers,
                new ZipEntryPathInspector(),
                fileTypeDetector,
                analyzers,
                seekableAnalyzers,
                spoolService);

        var metadataService =
            new ArchiveFileMetadataService(
                new TestFileHashService(),
                fileTypeDetector,
                options);
        
        var consistencyService =
            new ArchiveGuardFileConsistencyService(
                new TestFileHashService());

        var cache =
            new ArchiveGuardScanCache(
                options);

        return new ArchiveGuardScanner(
            metadataService,
            analyzers,
            seekableAnalyzers,
            recursiveScanner,
            consistencyService,
            cache);
    }

    public static string CreateTemporaryDirectory()
    {
        var directory =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard",
                "ArchiveGuardTests",
                Guid.NewGuid().ToString(
                    "N"));

        Directory.CreateDirectory(
            directory);

        return directory;
    }

    private sealed class TestFileHashService
        : IFileHashService
    {
        public async Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            await using var stream =
                new FileStream(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    64 * 1024,
                    FileOptions.Asynchronous |
                    FileOptions.SequentialScan);

            var hash =
                await SHA256.HashDataAsync(
                    stream,
                    cancellationToken);

            return Convert.ToHexString(
                hash);
        }
    }

    private sealed class EmptyThreatHashStore
        : IKnownThreatHashStore
    {
        public Task<bool> IsMaliciousAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                false);
        }
    }

    private sealed class NullArchiveRecursiveScanner
        : IArchiveRecursiveScanner
    {
        public bool Supports(
            DetectedFileType fileType)
        {
            return false;
        }

        public Task<ArchiveRecursiveScanResult> ScanAsync(
            string filePath,
            DetectedFileType fileType,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                new ArchiveRecursiveScanResult(
                    ScanVerdict.Clean,
                    [],
                    0,
                    0,
                    0,
                    false));
        }
    }
}

internal sealed class MaliciousHashStore
    : IKnownThreatHashStore
{
    private readonly HashSet<string> _hashes;

    public MaliciousHashStore(
        params string[] hashes)
    {
        _hashes =
            new HashSet<string>(
                hashes,
                StringComparer.OrdinalIgnoreCase);
    }

    public Task<bool> IsMaliciousAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(
            _hashes.Contains(
                sha256));
    }

    private sealed class AlwaysConsistentService
        : IArchiveGuardFileConsistencyService
    {
        public Task<bool> IsConsistentAsync(
            ArchiveFileMetadata metadata,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                true);
        }
    }

    private sealed class NullScanCache
        : IArchiveGuardScanCache
    {
        public bool TryGet(
            ArchiveFileMetadata metadata,
            out ArchiveGuardScanResult result)
        {
            result =
                null!;

            return false;
        }

        public void Store(
            ArchiveFileMetadata metadata,
            ArchiveGuardScanResult result)
        {
        }

        public void Clear()
        {
        }
    }
}