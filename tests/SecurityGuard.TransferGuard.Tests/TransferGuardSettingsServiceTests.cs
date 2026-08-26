using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferGuardSettingsServiceTests
{
    [Fact]
    public async Task Defaults_are_returned_when_settings_are_missing()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.TransferGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(
            root);

        try
        {
            var factory =
                new SqliteConnectionFactory(
                    new StorageOptions(
                        Path.Combine(
                            root,
                            "test.db")));

            await new DatabaseInitializer(
                factory).InitializeAsync();

            var service =
                new TransferGuardSettingsService(
                    new SqliteSettingsRepository(
                        factory));

            var settings =
                await service.GetAsync();

            Assert.True(
                settings.Enabled);

            Assert.Equal(
                TransferGuardMode.Monitor,
                settings.Mode);

            Assert.Equal(
                TransferEnforcementFailurePolicy.FailOpen,
                settings.FailurePolicy);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task Settings_are_saved_and_restored()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.TransferGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(
            root);

        try
        {
            var factory =
                new SqliteConnectionFactory(
                    new StorageOptions(
                        Path.Combine(
                            root,
                            "test.db")));

            await new DatabaseInitializer(
                factory).InitializeAsync();

            var service =
                new TransferGuardSettingsService(
                    new SqliteSettingsRepository(
                        factory));

            var expected =
                new TransferGuardSettings(
                    false,
                    TransferGuardMode.Enforce,
                    TransferEnforcementFailurePolicy.FailClosed);

            await service.SaveAsync(
                expected);

            var restored =
                await service.GetAsync();

            Assert.Equal(
                expected,
                restored);
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }
}