using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardSpoolCleanupServiceTests
{
    [Fact]
    public async Task Old_spool_file_is_deleted()
    {
        var root =
            ArchiveGuardTestFactory.CreateTemporaryDirectory();

        try
        {
            var spool =
                Path.Combine(
                    root,
                    "spool");

            Directory.CreateDirectory(
                spool);

            var file =
                Path.Combine(
                    spool,
                    "old.tmp");

            await File.WriteAllTextAsync(
                file,
                "test");

            File.SetLastWriteTimeUtc(
                file,
                DateTime.UtcNow.AddHours(
                    -2));

            var service =
                new ArchiveGuardSpoolCleanupService(
                    new ArchiveGuardOptions
                    {
                        SpoolDirectory =
                            spool
                    });

            var deleted =
                await service.CleanupAsync(
                    DateTimeOffset.UtcNow.AddHours(
                        -1));

            Assert.Equal(
                1,
                deleted);

            Assert.False(
                File.Exists(
                    file));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Recent_spool_file_is_preserved()
    {
        var root =
            ArchiveGuardTestFactory.CreateTemporaryDirectory();

        try
        {
            var spool =
                Path.Combine(
                    root,
                    "spool");

            Directory.CreateDirectory(
                spool);

            var file =
                Path.Combine(
                    spool,
                    "recent.tmp");

            await File.WriteAllTextAsync(
                file,
                "test");

            var service =
                new ArchiveGuardSpoolCleanupService(
                    new ArchiveGuardOptions
                    {
                        SpoolDirectory =
                            spool
                    });

            var deleted =
                await service.CleanupAsync(
                    DateTimeOffset.UtcNow.AddMinutes(
                        -30));

            Assert.Equal(
                0,
                deleted);

            Assert.True(
                File.Exists(
                    file));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}