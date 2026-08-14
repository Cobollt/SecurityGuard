using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Infrastructure.FileSystem;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Service.Hosting;

public sealed class SecurityGuardStartupService
    : IHostedService
{
    private readonly DirectoryBootstrapper _directoryBootstrapper;
    private readonly DatabaseInitializer _databaseInitializer;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public SecurityGuardStartupService(
        DirectoryBootstrapper directoryBootstrapper,
        DatabaseInitializer databaseInitializer,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _directoryBootstrapper = directoryBootstrapper;
        _databaseInitializer = databaseInitializer;
        _moduleRegistry = moduleRegistry;
        _auditService = auditService;
    }

    public async Task StartAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            _moduleRegistry.Set(
                SecurityModuleKind.Core,
                ModuleOperationalState.Starting,
                "SecurityGuard core is starting");

            _directoryBootstrapper.Initialize();

            await _databaseInitializer.InitializeAsync(
                cancellationToken);

            _moduleRegistry.Set(
                SecurityModuleKind.Core,
                ModuleOperationalState.Active,
                "SecurityGuard core is active");

            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "SecurityGuard started",
                "SecurityGuard service initialization completed",
                cancellationToken: cancellationToken);
        }
        catch
        {
            _moduleRegistry.Set(
                SecurityModuleKind.Core,
                ModuleOperationalState.Faulted,
                "SecurityGuard core initialization failed");

            throw;
        }
    }

    public async Task StopAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "SecurityGuard stopped",
                "SecurityGuard service is shutting down",
                cancellationToken: cancellationToken);
        }
        finally
        {
            _moduleRegistry.Set(
                SecurityModuleKind.Core,
                ModuleOperationalState.Disabled,
                "SecurityGuard core is stopped");
        }
    }
}