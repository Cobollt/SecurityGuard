using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardScanResultMapperTests
{
    [Fact]
    public void Archive_result_maps_to_core_scan_result()
    {
        var now =
            DateTimeOffset.UtcNow;

        var source =
            new ArchiveGuardScanResult(
                Guid.NewGuid(),
                @"C:\Test\archive.zip",
                new string(
                    'A',
                    64),
                500,
                ScanVerdict.Suspicious,
                [],
                now,
                now,
                DetectedFileType.Zip);

        var mapper =
            new ArchiveGuardScanResultMapper();

        var result =
            mapper.Map(
                source);

        Assert.Equal(
            source.Id,
            result.Id);

        Assert.Equal(
            SecurityModuleKind.ArchiveGuard,
            result.Module);

        Assert.Equal(
            source.Sha256,
            result.Sha256);

        Assert.Equal(
            source.Verdict,
            result.Verdict);
    }
}