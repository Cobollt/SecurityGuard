using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardAutoScanSettingsServiceTests
{
    [Fact]
    public async Task Missing_settings_return_defaults()
    {
        var service =
            new ArchiveGuardAutoScanSettingsService(
                new FakeSettingsRepository());

        var result =
            await service.GetAsync();

        Assert.True(
            result.Enabled);

        Assert.True(
            result.ScanUserDownloads);

        Assert.Empty(
            result.AdditionalDirectories);
    }

    [Fact]
    public async Task Settings_can_be_saved_and_loaded()
    {
        var repository =
            new FakeSettingsRepository();

        var service =
            new ArchiveGuardAutoScanSettingsService(
                repository);

        await service.SaveAsync(
            ArchiveGuardAutoScanSettings.Default with
            {
                Enabled =
                    false,

                AdditionalDirectories =
                [
                    @"C:\Data",
                    @"D:\Incoming"
                ]
            });

        var result =
            await service.GetAsync();

        Assert.False(
            result.Enabled);

        Assert.Equal(
            2,
            result.AdditionalDirectories.Length);
    }

    private sealed class FakeSettingsRepository
        : ISettingsRepository
    {
        private readonly Dictionary<string, string> _values =
            new();

        public Task<string?> GetAsync(
            string key,
            CancellationToken cancellationToken = default)
        {
            _values.TryGetValue(
                key,
                out var value);

            return Task.FromResult(
                value);
        }

        public Task SetAsync(
            string key,
            string value,
            CancellationToken cancellationToken = default)
        {
            _values[key] =
                value;

            return Task.CompletedTask;
        }
    }
}