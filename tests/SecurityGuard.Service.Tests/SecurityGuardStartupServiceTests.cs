using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Services;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Infrastructure.FileSystem;
using SecurityGuard.Service.Hosting;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityGuardStartupServiceTests
{
    [Fact]
    public async Task Start_initializes_core()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var directoryBootstrapper =
            new DirectoryBootstrapper(
                environment.Paths,
                new NoOpFileAccessProtectionService());

        var databaseInitializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var auditService =
            new AuditService(
                eventRepository);

        var moduleRegistry =
            new ModuleRegistry();

        var service =
            new SecurityGuardStartupService(
                directoryBootstrapper,
                databaseInitializer,
                moduleRegistry,
                auditService);

        await service.StartAsync(
            CancellationToken.None);

        var status =
            moduleRegistry.Get(
                SecurityModuleKind.Core);

        Assert.Equal(
            ModuleOperationalState.Active,
            status.State);

        Assert.True(
            File.Exists(
                environment.Paths.DatabasePath));

        Assert.True(
            Directory.Exists(
                environment.Paths.QuarantineDirectory));

        var events =
            await eventRepository.GetRecentAsync(10);

        Assert.Contains(
            events,
            securityEvent =>
                securityEvent.Title ==
                "SecurityGuard started");
    }

    [Fact]
    public async Task Stop_disables_core()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var directoryBootstrapper =
            new DirectoryBootstrapper(
                environment.Paths,
                new NoOpFileAccessProtectionService());

        var databaseInitializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var moduleRegistry =
            new ModuleRegistry();

        var service =
            new SecurityGuardStartupService(
                directoryBootstrapper,
                databaseInitializer,
                moduleRegistry,
                new AuditService(eventRepository));

        await service.StartAsync(
            CancellationToken.None);

        await service.StopAsync(
            CancellationToken.None);

        var status =
            moduleRegistry.Get(
                SecurityModuleKind.Core);

        Assert.Equal(
            ModuleOperationalState.Disabled,
            status.State);

        var events =
            await eventRepository.GetRecentAsync(10);

        Assert.Contains(
            events,
            securityEvent =>
                securityEvent.Title ==
                "SecurityGuard stopped");
    }
}