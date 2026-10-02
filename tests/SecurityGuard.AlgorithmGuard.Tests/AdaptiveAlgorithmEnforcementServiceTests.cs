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
            new FakeAppLockerHealthService();

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
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

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

    private sealed class FakeAppLockerHealthService
        : IAppLockerHealthService
    {
        private static readonly AppLockerHealthSnapshot Snapshot =
            new(
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                "AppLocker management cmdlets are unavailable.");

        public Task<AppLockerHealthSnapshot> GetHealthAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Snapshot);
        }

        public Task<AppLockerHealthSnapshot> EnsureReadyAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Snapshot);
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