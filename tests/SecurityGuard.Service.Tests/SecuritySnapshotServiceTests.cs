using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Core.Services;
using SecurityGuard.Service.Application;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

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
}