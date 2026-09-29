using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Core.Services;
using SecurityGuard.Service.Application;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.Service.Tests;

public sealed class SecuritySnapshotServiceTests
{
    [Fact]
    public async Task Snapshot_contains_modules_and_events()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var decisionRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var registry =
            new ModuleRegistry();

        registry.Set(
            SecurityModuleKind.Core,
            ModuleOperationalState.Active,
            "Ready");

        await eventRepository.AddAsync(
            SecurityEvent.Create(
                SecurityModuleKind.Core,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "Test event",
                "Test"));

        var service =
            new SecuritySnapshotService(
                registry,
                eventRepository,
                decisionRepository,
                quarantineRepository);

        var snapshot =
            await service.GetAsync();

        Assert.Equal(
            4,
            snapshot.Modules.Count);

        Assert.Single(
            snapshot.RecentEvents);

        Assert.Empty(
            snapshot.PendingRequests);

        Assert.Equal(
            0,
            snapshot.QuarantineCount);
    }

    [Fact]
    public async Task Snapshot_waits_for_events_before_reading_pending_requests()
    {
        var eventRepository =
            new BlockingEventRepository();

        var decisionRepository =
            new TrackingDecisionRequestRepository();

        var quarantineRepository =
            new FakeQuarantineRepository();

        var registry =
            new ModuleRegistry();

        var service =
            new SecuritySnapshotService(
                registry,
                eventRepository,
                decisionRepository,
                quarantineRepository);

        var snapshotTask =
            service.GetAsync();

        Assert.True(
            eventRepository.WasCalled);

        Assert.False(
            decisionRepository.WasCalled);

        eventRepository.Release();

        var snapshot =
            await snapshotTask;

        Assert.True(
            decisionRepository.WasCalled);

        Assert.Empty(
            snapshot.RecentEvents);

        Assert.Empty(
            snapshot.PendingRequests);

        Assert.Equal(
            0,
            snapshot.QuarantineCount);
    }

    private sealed class BlockingEventRepository
    : ISecurityEventRepository
    {
        private readonly TaskCompletionSource<bool> _release =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);

        public bool WasCalled { get; private set; }

        public Task AddAsync(
            SecurityEvent securityEvent,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public async Task<IReadOnlyList<SecurityEvent>> GetRecentAsync(
            int limit,
            CancellationToken cancellationToken = default)
        {
            WasCalled =
                true;

            await _release.Task.WaitAsync(
                cancellationToken);

            return Array.Empty<SecurityEvent>();
        }

        public void Release()
        {
            _release.TrySetResult(
                true);
        }
    }

    private sealed class TrackingDecisionRequestRepository
    : IDecisionRequestRepository
    {
        public bool WasCalled { get; private set; }

        public Task AddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<bool> TryAddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                true);
        }

        public Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
            CancellationToken cancellationToken = default)
        {
            WasCalled =
                true;

            return Task.FromResult<
                IReadOnlyList<SecurityDecisionRequest>>(
                Array.Empty<SecurityDecisionRequest>());
        }

        public Task<SecurityDecisionRequest?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                SecurityDecisionRequest?>(
                null);
        }

        public Task<SecurityDecisionRequest?> GetByIdentityAsync(
            string identity,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                SecurityDecisionRequest?>(
                null);
        }

        public Task<int> RemoveOlderThanAsync(
            DateTimeOffset cutoffUtc,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }

        public Task RemoveAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FakeQuarantineRepository
    : IQuarantineRepository
    {
        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                IReadOnlyList<QuarantineRecord>>(
                Array.Empty<QuarantineRecord>());
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                QuarantineRecord?>(
                null);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}