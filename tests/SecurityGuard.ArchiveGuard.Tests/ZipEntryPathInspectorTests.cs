using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ZipEntryPathInspectorTests
{
    private readonly ZipEntryPathInspector _inspector =
        new();

    [Fact]
    public void Parent_traversal_is_detected()
    {
        var result =
            _inspector.Inspect(
                @"folder\..\..\secret.txt");

        Assert.True(
            result.HasTraversal);
    }

    [Fact]
    public void Windows_absolute_path_is_detected()
    {
        var result =
            _inspector.Inspect(
                @"C:\Windows\evil.exe");

        Assert.True(
            result.IsAbsolute);
    }

    [Fact]
    public void Unix_absolute_path_is_detected()
    {
        var result =
            _inspector.Inspect(
                "/etc/passwd");

        Assert.True(
            result.IsAbsolute);
    }

    [Fact]
    public void Alternate_data_stream_is_detected()
    {
        var result =
            _inspector.Inspect(
                @"documents\report.txt:payload.exe");

        Assert.True(
            result.HasAlternateDataStream);
    }

    [Fact]
    public void Normal_path_is_safe()
    {
        var result =
            _inspector.Inspect(
                @"documents\2026\report.pdf");

        Assert.False(
            result.IsAbsolute);

        Assert.False(
            result.HasTraversal);

        Assert.False(
            result.HasAlternateDataStream);
    }

    [Fact]
    public async Task Duplicate_zip_paths_are_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "duplicate.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                archive.CreateEntry(
                    "Data/report.txt");

                archive.CreateEntry(
                    "data/REPORT.TXT");
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
                    ArchiveFindingKind.ZipDuplicatePath);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Oversized_zip_entry_is_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "large.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "large.bin");

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    new byte[1024]);
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxZipEntryBytes =
                                128
                        });

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
                    ArchiveFindingKind.ZipEntrySizeExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Total_expanded_zip_size_is_limited()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "expanded.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                for (var index = 0;
                    index < 5;
                    index++)
                {
                    var entry =
                        archive.CreateEntry(
                            $"file-{index}.bin");

                    await using var stream =
                        entry.Open();

                    await stream.WriteAsync(
                        new byte[100]);
                }
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxZipExpandedBytes =
                                300
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ZipExpandedSizeExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Extreme_compression_ratio_is_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "compressed.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "zeros.bin",
                        System.IO.Compression.CompressionLevel.SmallestSize);

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    new byte[
                        1024 * 1024]);
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxZipCompressionRatio =
                                10
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ZipCompressionRatioExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Too_many_zip_entries_are_suspicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "entries.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                for (var index = 0;
                    index < 10;
                    index++)
                {
                    archive.CreateEntry(
                        $"file-{index}.txt");
                }
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxZipEntryCount =
                                5
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ZipEntryCountExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Invalid_zip_structure_returns_error()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "broken.zip");

            await File.WriteAllBytesAsync(
                file,
                [
                    0x50,
                    0x4B,
                    0x03,
                    0x04,
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
                ScanVerdict.Error,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ZipInvalidStructure);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Suspicious_file_inside_zip_is_detected()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "documents/invoice.pdf.exe");

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

            var finding =
                Assert.Single(
                    result.Findings,
                    item =>
                        item.Kind ==
                        ArchiveFindingKind.DoubleExtension);

            Assert.Contains(
                "outer.zip!/documents/invoice.pdf.exe",
                finding.EntryPath);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Disguised_pe_inside_zip_is_detected()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "documents/report.pdf");

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    CreatePeFile());
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
                        ArchiveFindingKind.ExecutableContentMismatch &&
                    finding.EntryPath is not null &&
                    finding.EntryPath.EndsWith(
                        "report.pdf",
                        StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Known_malicious_file_inside_zip_makes_archive_malicious()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var payload =
                "SecurityGuard nested malicious test"u8
                    .ToArray();

            var hash =
                Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        payload));

            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "payload.bin");

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    payload);
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
                        ArchiveFindingKind.KnownMaliciousHash &&
                    finding.EntryPath is not null);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private static byte[] CreateZipBytes(
        string entryName,
        byte[] content)
    {
        using var memory =
            new MemoryStream();

        using (
            var archive =
                new System.IO.Compression.ZipArchive(
                    memory,
                    System.IO.Compression.ZipArchiveMode.Create,
                    leaveOpen:
                        true))
        {
            var entry =
                archive.CreateEntry(
                    entryName);

            using var stream =
                entry.Open();

            stream.Write(
                content);
        }

        return memory.ToArray();
    }

    [Fact]
    public async Task Nested_zip_is_scanned_recursively()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var inner =
                CreateZipBytes(
                    "invoice.pdf.exe",
                    "test"u8.ToArray());

            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            await File.WriteAllBytesAsync(
                file,
                CreateZipBytes(
                    "inner.zip",
                    inner));

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
                        ArchiveFindingKind.DoubleExtension &&
                    finding.EntryPath is not null &&
                    finding.EntryPath.Contains(
                        "inner.zip!/",
                        StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Nested_archive_depth_is_limited()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var levelTwo =
                CreateZipBytes(
                    "payload.txt",
                    "test"u8.ToArray());

            var levelOne =
                CreateZipBytes(
                    "level2.zip",
                    levelTwo);

            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            await File.WriteAllBytesAsync(
                file,
                CreateZipBytes(
                    "level1.zip",
                    levelOne));

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxArchiveDepth =
                                1
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Unknown,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ArchiveDepthExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Recursive_expanded_byte_budget_is_enforced()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry =
                    archive.CreateEntry(
                        "large.bin");

                await using var stream =
                    entry.Open();

                await stream.WriteAsync(
                    new byte[4096]);
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxRecursiveExpandedBytes =
                                128
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Unknown,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.ArchiveReadBudgetExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Recursive_entry_count_is_limited()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            using (
                var archive =
                    System.IO.Compression.ZipFile.Open(
                        file,
                        System.IO.Compression.ZipArchiveMode.Create))
            {
                for (var index = 0;
                    index < 10;
                    index++)
                {
                    var entry =
                        archive.CreateEntry(
                            $"file-{index}.txt");

                    await using var stream =
                        entry.Open();

                    await stream.WriteAsync(
                        "x"u8.ToArray());
                }
            }

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxRecursiveEntryCount =
                                3
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Equal(
                ScanVerdict.Unknown,
                result.Verdict);

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.RecursiveEntryCountExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Large_nested_zip_is_not_recursed()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var inner =
                CreateZipBytes(
                    "large.bin",
                    new byte[4096]);

            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            await File.WriteAllBytesAsync(
                file,
                CreateZipBytes(
                    "inner.zip",
                    inner));

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            MaxNestedArchiveBytes =
                                32
                        });

            var result =
                await scanner.ScanAsync(
                    new ArchiveScanRequest(
                        file));

            Assert.Contains(
                result.Findings,
                finding =>
                    finding.Kind ==
                    ArchiveFindingKind.NestedArchiveSizeExceeded);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Nested_zip_spool_is_deleted_after_scan()
    {
        var root =
            CreateTemporaryDirectory();

        try
        {
            var spool =
                Path.Combine(
                    root,
                    "spool");

            var inner =
                CreateZipBytes(
                    "file.txt",
                    "test"u8.ToArray());

            var file =
                Path.Combine(
                    root,
                    "outer.zip");

            await File.WriteAllBytesAsync(
                file,
                CreateZipBytes(
                    "inner.zip",
                    inner));

            var scanner =
                CreateScanner(
                    options:
                        new ArchiveGuardOptions
                        {
                            SpoolDirectory =
                                spool
                        });

            await scanner.ScanAsync(
                new ArchiveScanRequest(
                    file));

            var remaining =
                Directory.Exists(
                    spool)
                    ? Directory.GetFiles(
                        spool)
                    : [];

            Assert.Empty(
                remaining);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}