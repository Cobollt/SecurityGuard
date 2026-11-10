using System.Collections.Concurrent;
using System.Reflection;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Service.Hosting;

namespace SecurityGuard.Service.Tests;

public sealed class ArchiveGuardQueueOverflowTests
{
    [Fact]
    public async Task Full_queue_releases_deduplication_and_recovers_dropped_file()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SecurityGuardQueueTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var target = Path.Combine(directory, "dropped.zip");
        await File.WriteAllTextAsync(target, "test content");
        var workflow = new Workflow();
        using var service = new ArchiveGuardAutoScanHostedService(
            null!, null!, new CandidatePolicy(), new Readiness(), workflow, null!, new Audit());
        using var cancellation = new CancellationTokenSource();
        try
        {
            // Fill the real production queue before starting consumption.
            for (var index = 0; index < 2048; index++)
                Invoke(service, "QueueFile", Path.Combine(directory, $"queued-{index}.zip"));
            Invoke(service, "QueueFile", target);
            var pending = Field<ConcurrentDictionary<string, byte>>(service, "_queuedPaths");
            Assert.False(pending.ContainsKey(target));
            Invoke(service, "QueueRecovery", directory, "Watcher overflow");
            Assert.Empty(Field<ConcurrentDictionary<string, byte>>(service, "_queuedRecoveryDirectories"));

            SetField(service, "_watchedDirectories", new[] { directory });
            SetField(service, "_settings", ArchiveGuardAutoScanSettings.Default with { QuietPeriodMilliseconds = 0 });
            var recovery = (Task)Invoke(service, "RecoverOverflowAsync", cancellation.Token)!;
            try
            {
                Assert.Equal(target, await workflow.Scanned.Task.WaitAsync(TimeSpan.FromSeconds(15)));
            }
            finally
            {
                await cancellation.CancelAsync();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => recovery);
            }
            Assert.False(pending.ContainsKey(target));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    private static object? Invoke(object instance, string name, params object[] args)
        => instance.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(instance, args);
    private static T Field<T>(object instance, string name)
        => (T)instance.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(instance)!;
    private static void SetField(object instance, string name, object value)
        => instance.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(instance, value);

    private sealed class CandidatePolicy : IArchiveGuardFileCandidatePolicy
    {
        public bool ShouldScan(string filePath) => true;
    }
    private sealed class Readiness : IArchiveGuardFileReadinessService
    {
        public Task<bool> WaitUntilStableAsync(string filePath, ArchiveGuardAutoScanSettings settings,
            CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
    private sealed class Workflow : IArchiveGuardWorkflowService
    {
        public TaskCompletionSource<string> Scanned { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<ArchiveGuardWorkflowResult> ScanAsync(string filePath, CancellationToken cancellationToken = default)
        {
            Scanned.TrySetResult(filePath);
            return Task.FromResult(new ArchiveGuardWorkflowResult(
                new ArchiveGuardScanResult(Guid.NewGuid(), filePath, null, null, ScanVerdict.Clean,
                    [], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow), null));
        }
    }
    private sealed class Audit : IAuditService
    {
        public Task WriteAsync(SecurityModuleKind module, SecurityEventType type, SecuritySeverity severity,
            string title, string details, SecurityAction action = SecurityAction.None,
            Guid? correlationId = null, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
