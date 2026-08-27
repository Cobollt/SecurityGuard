using Microsoft.Extensions.DependencyInjection;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Services;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Infrastructure.FileSystem;
using SecurityGuard.Infrastructure.Hashing;
using SecurityGuard.Infrastructure.Quarantine;
using SecurityGuard.Service.Hosting;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;
using SecurityGuard.Service.Application;
using SecurityGuard.Service.Ipc;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Monitoring;
using SecurityGuard.AlgorithmGuard.Parsing;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Monitoring;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.Service.DependencyInjection;

public static class ServiceRegistration
{
    public static IServiceCollection AddSecurityGuard(
        this IServiceCollection services)
    {
        var paths =
            SecurityGuardPaths.CreateDefault();

        var storageOptions =
            new StorageOptions(
                paths.DatabasePath);

        services.AddSingleton(paths);
        services.AddSingleton(storageOptions);

        services.AddSingleton<SqliteConnectionFactory>();
        services.AddSingleton<DatabaseInitializer>();

        services.AddSingleton<IRuleRepository, SqliteRuleRepository>();
        services.AddSingleton<ISecurityEventRepository, SqliteSecurityEventRepository>();
        services.AddSingleton<IQuarantineRepository, SqliteQuarantineRepository>();
        services.AddSingleton<IProtectedObjectRepository, SqliteProtectedObjectRepository>();
        services.AddSingleton<IDecisionRequestRepository, SqliteDecisionRequestRepository>();
        services.AddSingleton<IScanResultRepository, SqliteScanResultRepository>();
        services.AddSingleton<ISettingsRepository, SqliteSettingsRepository>();

        services.AddSingleton<IModuleRegistry, ModuleRegistry>();
        services.AddSingleton<IRuleEngine, RuleEngine>();

        services.AddSingleton<IFileHashService, Sha256FileHashService>();
        services.AddSingleton<IAuditService, AuditService>();

        services.AddSingleton<SecurityGuardPipeFactory>();

        services.AddSingleton<PipeClientContextFactory>();

        services.AddSingleton<PipeAuthorizationService>();

        services.AddSingleton(
            new AlgorithmGuardOptions());

        services.AddSingleton<
            AlgorithmDecisionMaintenanceService>();

        services.AddSingleton<
            IFileAccessProtectionService,
            WindowsFileAccessProtectionService>();

        services.AddSingleton<DirectoryBootstrapper>();

        services.AddSingleton<
            ITransferKernelTelemetrySource,
            EtwTransferKernelTelemetrySource>();

        services.AddSingleton<
            TransferCorrelationConfidenceCalculator>();

        services.AddSingleton<
            ITransferCorrelationState,
            TransferCorrelationState>();

        services.AddSingleton<
            TransferCorrelationService>();

        services.AddSingleton<
            IQuarantineService,
            QuarantineManager>();

        services.AddSingleton<
            ISecuritySnapshotService,
            SecuritySnapshotService>();

        services.AddSingleton<
            ISecurityDecisionService,
            SecurityDecisionService>();

        services.AddSingleton<PipeRequestHandler>();

        services.AddSingleton<InterpreterCatalog>();

        services.AddSingleton<WindowsCommandLineParser>();

        services.AddSingleton<
            IProcessStartMonitor,
            WmiProcessStartMonitor>();

        services.AddSingleton<
            IProcessAncestryProvider,
            WmiProcessAncestryProvider>();

        services.AddSingleton<
            IProcessMetadataProvider,
            WmiProcessMetadataProvider>();

        services.AddSingleton<
            IAlgorithmExecutionAnalyzer,
            AlgorithmExecutionAnalyzer>();

        services.AddSingleton<AlgorithmRuleContextFactory>();

        services.AddSingleton<
            IAlgorithmTemporaryDecisionStore,
            AlgorithmTemporaryDecisionStore>();

        services.AddSingleton<
            IInternalProcessRegistry,
            InternalProcessRegistry>();

        services.AddSingleton<PowerShellProcessRunner>();

        services.AddSingleton<
            IAuthenticodeSignatureService,
            PowerShellAuthenticodeSignatureService>();

        services.AddSingleton<
            IAlgorithmEnforcementService,
            AppLockerAlgorithmEnforcementService>();

        services.AddSingleton<
            ISecurityRuleLifecycleHandler,
            AlgorithmRuleLifecycleHandler>();

        services.AddSingleton<
            IRuleManagementService,
            RuleManagementService>();

        services.AddSingleton<AlgorithmPolicyService>();

        services.AddSingleton<
            ISecurityDecisionHandler,
            AlgorithmDecisionHandler>();

        services.AddSingleton<
            IAlgorithmGuardMonitor,
            AlgorithmGuardMonitor>();

        services.AddSingleton<
            IAlgorithmGuardSettingsService,
            AlgorithmGuardSettingsService>();

        services.AddSingleton<
            IAlgorithmEnforcementSynchronizer,
            AlgorithmEnforcementSynchronizer>();

        services.AddSingleton<
            IAlgorithmGuardSettingsCoordinator,
            AlgorithmGuardSettingsCoordinator>();

        services.AddSingleton<
            ITransferGuardSettingsService,
            TransferGuardSettingsService>();

        services.AddSingleton<
            ITransferGuardSettingsCoordinator,
            TransferGuardSettingsCoordinator>();

        services.AddSingleton(
            new TransferGuardOptions());

        services.AddSingleton<FilteringPlatformEventParser>();

        services.AddSingleton<
            IFilteringPlatformAuditPolicyService,
            WindowsFilteringPlatformAuditPolicyService>();

        services.AddSingleton<
            ITransferPathNormalizer,
            WindowsTransferPathNormalizer>();

        services.AddSingleton<
            TransferPowerShellRunner>();

        services.AddSingleton<
            ITransferEnforcementService,
            WindowsFirewallTransferEnforcementService>();

        services.AddSingleton<
            TransferEnforcementRuleFactory>();

        services.AddSingleton<
            ITransferEnforcementSynchronizer,
            TransferEnforcementSynchronizer>();

        services.AddSingleton<
            ISecurityRuleLifecycleHandler,
            TransferRuleLifecycleHandler>();

        services.AddSingleton<
            IOutboundConnectionEventSource,
            WindowsOutboundConnectionEventSource>();

        services.AddSingleton<
            ITransferProcessResolver,
            WindowsTransferProcessResolver>();

        services.AddSingleton<TransferObservationService>();

        services.AddSingleton<TransferRuleContextFactory>();

        services.AddSingleton<TransferPolicyService>();

        services.AddSingleton<
            ISecurityDecisionHandler,
            TransferDecisionHandler>();

        services.AddSingleton<
            ITransferGuardMonitor,
            TransferGuardMonitor>();

        services.AddHostedService<SecurityGuardPipeServer>();
        services.AddHostedService<SecurityGuardStartupService>();
        services.AddHostedService<SecurityGuardWorker>();

        services.AddSingleton<AlgorithmGuardHostedService>();

        services.AddSingleton<
            TransferGuardHostedService>();

        services.AddSingleton<
            ITransferGuardRuntimeController>(
                provider =>
                    provider.GetRequiredService<
                        TransferGuardHostedService>());

        services.AddHostedService(
            provider =>
            
                provider.GetRequiredService<
                    TransferGuardHostedService>());

        services.AddSingleton<
            IAlgorithmGuardRuntimeController>(
                provider =>
                    provider.GetRequiredService<
                        AlgorithmGuardHostedService>());

        services.AddHostedService(
            provider =>
                provider.GetRequiredService<
                    AlgorithmGuardHostedService>());
                    
        services.AddHostedService<SecurityGuardWorker>();
        services.AddHostedService<
            AlgorithmDecisionMaintenanceHostedService>();

        return services;
    }
}