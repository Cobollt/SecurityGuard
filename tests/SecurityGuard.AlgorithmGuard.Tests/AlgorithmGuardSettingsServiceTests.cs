using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmGuardSettingsServiceTests
{
    [Fact]
    public async Task Defaults_are_returned_when_settings_are_missing()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.AlgorithmGuard.Tests",
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
                new AlgorithmGuardSettingsService(
                    new SqliteSettingsRepository(
                        factory));

            var settings =
                await service.GetAsync();

            Assert.True(
                settings.Enabled);

            Assert.Equal(
                AlgorithmGuardMode.Monitor,
                settings.Mode);

            Assert.Equal(
                EnforcementFailurePolicy.FailOpen,
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
                "SecurityGuard.AlgorithmGuard.Tests",
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
                new AlgorithmGuardSettingsService(
                    new SqliteSettingsRepository(
                        factory));

            var expected =
                new AlgorithmGuardSettings(
                    false,
                    AlgorithmGuardMode.Enforce,
                    EnforcementFailurePolicy.FailClosed);

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