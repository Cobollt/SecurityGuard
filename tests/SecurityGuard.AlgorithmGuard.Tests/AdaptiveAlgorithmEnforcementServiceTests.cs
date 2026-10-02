using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AdaptiveAlgorithmEnforcementServiceTests
{
    [Fact]
    public async Task Uses_process_fallback_when_applocker_management_is_unavailable()
    {
        var health =
            new FakeAppLockerHealthService(
                CreateManagementUnavailableHealth());

        var processFallback =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                new FakeProcessTerminationService());

        var appLocker =
            new AppLockerAlgorithmEnforcementService(
                new PowerShellProcessRunner(),
                health);

        var service =
            new AdaptiveAlgorithmEnforcementService(
                appLocker,
                processFallback,
                health);

        var path =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.cmd");

        await File.WriteAllTextAsync(
            path,
            "@echo off");

        try
        {
            var ruleId =
                Guid.NewGuid();

            var result =
                await service.AddBlockAsync(
                    ruleId,
                    path,
                    FakeFileHashService.Hash);

            Assert.True(
                result.Applied);

            Assert.True(
                await service.UsesProcessFallbackAsync());

            var snapshot =
                await service.InspectAsync();

            Assert.Contains(
                ruleId,
                snapshot.LocalManagedRuleIds);

            Assert.Contains(
                ruleId,
                snapshot.EffectiveManagedRuleIds);
        }
        finally
        {
            File.Delete(
                path);
        }
    }

    [Fact]
    public async Task Process_fallback_remains_selected_when_applocker_becomes_available()
    {
        var health =
            new FakeAppLockerHealthService(
                CreateManagementUnavailableHealth());

        var service =
            CreateService(
                health);

        Assert.True(
            await service.UsesProcessFallbackAsync());

        health.SetSnapshot(
            CreateHealthyHealth());

        Assert.True(
            await service.UsesProcessFallbackAsync());

        Assert.Equal(
            1,
            health.EnsureReadyCalls);
    }

    [Fact]
    public async Task AppLocker_remains_selected_when_health_becomes_unavailable()
    {
        var health =
            new FakeAppLockerHealthService(
                CreateHealthyHealth());

        var service =
            CreateService(
                health);

        Assert.False(
            await service.UsesProcessFallbackAsync());

        health.SetSnapshot(
            CreateManagementUnavailableHealth());

        Assert.False(
            await service.UsesProcessFallbackAsync());

        Assert.Equal(
            1,
            health.EnsureReadyCalls);
    }

    private static AdaptiveAlgorithmEnforcementService CreateService(
        IAppLockerHealthService health)
    {
        var processFallback =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                new FakeProcessTerminationService());

        var appLocker =
            new AppLockerAlgorithmEnforcementService(
                new PowerShellProcessRunner(),
                health);

        return new AdaptiveAlgorithmEnforcementService(
            appLocker,
            processFallback,
            health);
    }

    private static AppLockerHealthSnapshot CreateManagementUnavailableHealth()
    {
        return new AppLockerHealthSnapshot(
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            "AppLocker management cmdlets are unavailable.");
    }

    private static AppLockerHealthSnapshot CreateHealthyHealth()
    {
        return new AppLockerHealthSnapshot(
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            null);
    }

    private sealed class FakeAppLockerHealthService
        : IAppLockerHealthService
    {
        private AppLockerHealthSnapshot _snapshot;

        public FakeAppLockerHealthService(
            AppLockerHealthSnapshot snapshot)
        {
            _snapshot =
                snapshot;
        }

        public int EnsureReadyCalls { get; private set; }

        public void SetSnapshot(
            AppLockerHealthSnapshot snapshot)
        {
            _snapshot =
                snapshot;
        }

        public Task<AppLockerHealthSnapshot> GetHealthAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _snapshot);
        }

        public Task<AppLockerHealthSnapshot> EnsureReadyAsync(
            CancellationToken cancellationToken = default)
        {
            EnsureReadyCalls++;

            return Task.FromResult(
                _snapshot);
        }
    }

    private sealed class FakeFileHashService
        : IFileHashService
    {
        public const string Hash =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        public Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Hash);
        }
    }

    private sealed class FakeProcessTerminationService
        : IProcessTerminationService
    {
        public Task<ProcessTerminationResult> TerminateAsync(
            int processId,
            string? expectedProcessName,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new ProcessTerminationResult(
                    true,
                    "Terminated"));
        }
    }
}