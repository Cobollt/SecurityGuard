using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Tests;

public sealed class WindowsArchiveGuardWatchDirectoryProviderTests
{
    [Fact]
    public void Additional_directory_is_returned()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.Provider",
                Guid.NewGuid().ToString("N"));

        var securityGuardRoot =
            Path.Combine(
                root,
                "SecurityGuard");

        var incoming =
            Path.Combine(
                root,
                "Incoming");

        Directory.CreateDirectory(
            securityGuardRoot);

        Directory.CreateDirectory(
            incoming);

        try
        {
            var provider =
                new WindowsArchiveGuardWatchDirectoryProvider(
                    new SecurityGuardPaths(
                        securityGuardRoot));

            var settings =
                ArchiveGuardAutoScanSettings.Default with
                {
                    ScanUserDownloads =
                        false,

                    AdditionalDirectories =
                    [
                        incoming
                    ]
                };

            var result =
                provider.GetDirectories(
                    settings);

            Assert.Contains(
                Path.GetFullPath(
                    incoming),
                result);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public void SecurityGuard_internal_directory_is_not_watched()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.Provider",
                Guid.NewGuid().ToString("N"));

        var securityGuardRoot =
            Path.Combine(
                root,
                "SecurityGuard");

        var quarantine =
            Path.Combine(
                securityGuardRoot,
                "Quarantine");

        Directory.CreateDirectory(
            quarantine);

        try
        {
            var provider =
                new WindowsArchiveGuardWatchDirectoryProvider(
                    new SecurityGuardPaths(
                        securityGuardRoot));

            var settings =
                ArchiveGuardAutoScanSettings.Default with
                {
                    ScanUserDownloads =
                        false,

                    AdditionalDirectories =
                    [
                        quarantine
                    ]
                };

            var result =
                provider.GetDirectories(
                    settings);

            Assert.Empty(
                result);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}