using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class ProcessExecutionEnforcementServiceTests
{
    [Fact]
    public async Task Added_rule_appears_in_snapshot_and_can_be_removed()
    {
        var service =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                new FakeProcessTerminationService());

        var path =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.ps1");

        await File.WriteAllTextAsync(
            path,
            "Write-Output test");

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
                service.ContainsHash(
                    FakeFileHashService.Hash));

            var snapshot =
                await service.InspectAsync();

            Assert.Contains(
                ruleId,
                snapshot.LocalManagedRuleIds);

            Assert.Contains(
                ruleId,
                snapshot.EffectiveManagedRuleIds);

            await service.RemoveBlockAsync(
                ruleId);

            snapshot =
                await service.InspectAsync();

            Assert.DoesNotContain(
                ruleId,
                snapshot.LocalManagedRuleIds);

            Assert.False(
                service.ContainsHash(
                    FakeFileHashService.Hash));
        }
        finally
        {
            File.Delete(
                path);
        }
    }

    [Fact]
    public async Task Unsupported_file_is_not_registered()
    {
        var service =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                new FakeProcessTerminationService());

        var path =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.txt");

        await File.WriteAllTextAsync(
            path,
            "test");

        try
        {
            var result =
                await service.AddBlockAsync(
                    Guid.NewGuid(),
                    path,
                    FakeFileHashService.Hash);

            Assert.False(
                result.Applied);
        }
        finally
        {
            File.Delete(
                path);
        }
    }

    [Fact]
    public async Task Mismatched_hash_is_not_registered()
    {
        var service =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                new FakeProcessTerminationService());

        var path =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.ps1");

        await File.WriteAllTextAsync(
            path,
            "Write-Output test");

        try
        {
            const string persistedHash =
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

            var result =
                await service.AddBlockAsync(
                    Guid.NewGuid(),
                    path,
                    persistedHash);

            Assert.False(
                result.Applied);

            Assert.False(
                service.ContainsHash(
                    persistedHash));

            Assert.False(
                service.ContainsHash(
                    FakeFileHashService.Hash));
        }
        finally
        {
            File.Delete(
                path);
        }
    }

    private sealed class FakeFileHashService
        : IFileHashService
    {
        public const string Hash =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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

    [Fact]
    public async Task Matching_hash_terminates_process()
    {
        var termination =
            new TrackingProcessTerminationService();

        var service =
            new ProcessExecutionEnforcementService(
                new FakeFileHashService(),
                termination);

        var path =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.ps1");

        await File.WriteAllTextAsync(
            path,
            "Write-Output test");

        try
        {
            await service.AddBlockAsync(
                Guid.NewGuid(),
                path,
                FakeFileHashService.Hash);

            var attempt =
                new AlgorithmExecutionAttempt(
                    Guid.NewGuid(),
                    12345,
                    null,
                    "powershell.exe",
                    null,
                    null,
                    Enums.InterpreterKind.PowerShell,
                    Enums.AlgorithmInvocationType.ScriptFile,
                    path,
                    FakeFileHashService.Hash,
                    DateTimeOffset.UtcNow);

            var result =
                await service.EnforceAsync(
                    attempt);

            Assert.True(
                result.Required);

            Assert.True(
                result.Terminated);

            Assert.Equal(
                12345,
                termination.ProcessId);

            Assert.Equal(
                "powershell.exe",
                termination.ProcessName);
        }
        finally
        {
            File.Delete(
                path);
        }
    }

    private sealed class TrackingProcessTerminationService
        : IProcessTerminationService
    {
        public int? ProcessId { get; private set; }

        public string? ProcessName { get; private set; }

        public Task<ProcessTerminationResult> TerminateAsync(
            int processId,
            string? expectedProcessName,
            CancellationToken cancellationToken = default)
        {
            ProcessId =
                processId;

            ProcessName =
                expectedProcessName;

            return Task.FromResult(
                new ProcessTerminationResult(
                    true,
                    "Terminated"));
        }
    }
}