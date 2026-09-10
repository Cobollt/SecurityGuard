using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardScanCacheTests
{
    [Fact]
    public void Same_hash_and_file_name_hits_cache()
    {
        var cache =
            new ArchiveGuardScanCache(
                new ArchiveGuardOptions());

        var metadata =
            CreateMetadata(
                "test.zip");

        var result =
            CreateResult(
                metadata);

        cache.Store(
            metadata,
            result);

        Assert.True(
            cache.TryGet(
                metadata,
                out var cached));

        Assert.Equal(
            result.Verdict,
            cached.Verdict);
    }

    [Fact]
    public void Same_hash_with_different_file_name_does_not_hit_cache()
    {
        var cache =
            new ArchiveGuardScanCache(
                new ArchiveGuardOptions());

        var first =
            CreateMetadata(
                "test.exe");

        var second =
            first with
            {
                FileName =
                    "test.pdf.exe",

                FilePath =
                    @"C:\Temp\test.pdf.exe",

                Extension =
                    ".exe"
            };

        cache.Store(
            first,
            CreateResult(
                first));

        Assert.False(
            cache.TryGet(
                second,
                out _));
    }

    private static ArchiveFileMetadata CreateMetadata(
        string fileName)
    {
        return new ArchiveFileMetadata(
            Path.Combine(
                @"C:\Temp",
                fileName),
            fileName,
            Path.GetExtension(
                fileName),
            100,
            DateTimeOffset.UtcNow,
            new string(
                'A',
                64),
            [],
            DetectedFileType.Unknown);
    }

    private static ArchiveGuardScanResult CreateResult(
        ArchiveFileMetadata metadata)
    {
        return new ArchiveGuardScanResult(
            Guid.NewGuid(),
            metadata.FilePath,
            metadata.Sha256,
            metadata.Length,
            ScanVerdict.Clean,
            [],
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            metadata.FileType);
    }
}