using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardFileReadinessServiceTests
{
    [Fact]
    public async Task Stable_file_becomes_ready()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.ArchiveReadiness",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(
            root);

        try
        {
            var file =
                Path.Combine(
                    root,
                    "test.bin");

            await File.WriteAllTextAsync(
                file,
                "SecurityGuard");

            var settings =
                ArchiveGuardAutoScanSettings.Default with
                {
                    StabilityCheckCount =
                        2,

                    StabilityCheckIntervalMilliseconds =
                        10,

                    ReadyTimeoutSeconds =
                        2
                };

            var service =
                new ArchiveGuardFileReadinessService();

            Assert.True(
                await service.WaitUntilStableAsync(
                    file,
                    settings));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Missing_file_is_not_ready()
    {
        var service =
            new ArchiveGuardFileReadinessService();

        var result =
            await service.WaitUntilStableAsync(
                Path.Combine(
                    Path.GetTempPath(),
                    Guid.NewGuid().ToString("N")),
                ArchiveGuardAutoScanSettings.Default);

        Assert.False(
            result);
    }
}