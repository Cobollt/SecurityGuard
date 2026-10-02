using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmPolicyServiceTests
{
    [Fact]
    public async Task Runtime_termination_failure_fail_open_degrades_module()
    {
        var moduleRegistry =
            new FakeModuleRegistry();

        var audit =
            new FakeAuditService();

        var settings =
            new FakeSettingsService(
                new AlgorithmGuardSettings(
                    true,
                    AlgorithmGuardMode.Enforce,
                    EnforcementFailurePolicy.FailOpen));

        var service =
            CreateService(
                settings,
                moduleRegistry,
                audit);

        await service.HandleAsync(
            CreateAttempt());

        Assert.Equal(
            ModuleOperationalState.Degraded,
            moduleRegistry.LastState);

        Assert.Contains(
            audit.Entries,
            entry =>
                entry.Severity ==
                    SecuritySeverity.Critical &&
                entry.Title ==
                    "Blocked algorithm process termination failed");
    }

    [Fact]
    public async Task Runtime_termination_failure_fail_closed_throws()
    {
        var moduleRegistry =
            new FakeModuleRegistry();

        var audit =
            new FakeAuditService();

        var settings =
            new FakeSettingsService(
                new AlgorithmGuardSettings(
                    true,
                    AlgorithmGuardMode.Enforce,
                    EnforcementFailurePolicy.FailClosed));

        var service =
            CreateService(
                settings,
                moduleRegistry,
                audit);

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () =>
                    service.HandleAsync(
                        CreateAttempt()));

        Assert.Contains(
            "Algorithm runtime enforcement failed",
            exception.Message);

        Assert.Contains(
            audit.Entries,
            entry =>
                entry.Severity ==
                    SecuritySeverity.Critical &&
                entry.Title ==
                    "Blocked algorithm process termination failed");
    }

    private static AlgorithmPolicyService CreateService(
        IAlgorithmGuardSettingsService settingsService,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        return new AlgorithmPolicyService(
            new AlgorithmObservationService(
                new FakeFileHashService(),
                new FakeProtectedObjectRepository(),
                new FakeSignatureService()),
            new AlgorithmRuleContextFactory(),
            new FakeTemporaryDecisionStore(),
            new FakeRuleEngine(),
            new FakeRuntimeEnforcer(),
            settingsService,
            moduleRegistry,
            new FakeDecisionRequestRepository(),
            auditService,
            new AlgorithmGuardOptions());
    }

    private static AlgorithmExecutionAttempt CreateAttempt()
    {
        return new AlgorithmExecutionAttempt(
            Guid.NewGuid(),
            4242,
            null,
            "powershell.exe",
            null,
            null,
            default,
            default,
            null,
            null,
            DateTimeOffset.UtcNow);
    }

    private sealed class FakeRuntimeEnforcer
        : IAlgorithmRuntimeEnforcer
    {
        public Task<AlgorithmRuntimeEnforcementResult> EnforceAsync(
            AlgorithmExecutionAttempt attempt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new AlgorithmRuntimeEnforcementResult(
                    true,
                    false,
                    "Termination failed"));
        }
    }

    private sealed class FakeRuleEngine
        : IRuleEngine
    {
        public Task<RuleEvaluationResult> EvaluateAsync(
            SecurityModuleKind module,
            RuleMatchContext context,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new RuleEvaluationResult(
                    true,
                    RuleDecision.Block,
                    Guid.NewGuid(),
                    "Matched test block rule"));
        }
    }

    private sealed class FakeSettingsService
        : IAlgorithmGuardSettingsService
    {
        private AlgorithmGuardSettings _settings;

        public FakeSettingsService(
            AlgorithmGuardSettings settings)
        {
            _settings =
                settings;
        }

        public Task<AlgorithmGuardSettings> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _settings);
        }

        public Task SaveAsync(
            AlgorithmGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            _settings =
                settings;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeModuleRegistry
        : IModuleRegistry
    {
        public ModuleOperationalState? LastState { get; private set; }

        public string? LastMessage { get; private set; }

        public IReadOnlyList<ModuleStatus> GetAll()
        {
            return Array.Empty<ModuleStatus>();
        }

        public ModuleStatus Get(
            SecurityModuleKind module)
        {
            throw new NotSupportedException();
        }

        public void Set(
            SecurityModuleKind module,
            ModuleOperationalState state,
            string message)
        {
            LastState =
                state;

            LastMessage =
                message;
        }
    }

    private sealed class FakeAuditService
        : IAuditService
    {
        public List<AuditEntry> Entries { get; } =
            [];

        public Task WriteAsync(
            SecurityModuleKind module,
            SecurityEventType type,
            SecuritySeverity severity,
            string title,
            string details,
            SecurityAction action = SecurityAction.None,
            Guid? correlationId = null,
            CancellationToken cancellationToken = default)
        {
            Entries.Add(
                new AuditEntry(
                    severity,
                    title));

            return Task.CompletedTask;
        }
    }

    private sealed record AuditEntry(
        SecuritySeverity Severity,
        string Title);

    private sealed class FakeTemporaryDecisionStore
        : IAlgorithmTemporaryDecisionStore
    {
        public void AllowOnce(
            string identity,
            DateTimeOffset expiresAtUtc)
        {
        }

        public bool TryConsumeAllowOnce(
            string identity)
        {
            return false;
        }
    }

    private sealed class FakeDecisionRequestRepository
        : IDecisionRequestRepository
    {
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

    private sealed class FakeFileHashService
        : IFileHashService
    {
        public Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                string.Empty);
        }
    }

    private sealed class FakeProtectedObjectRepository
        : IProtectedObjectRepository
    {
        public Task<ProtectedObject?> FindByHashAsync(
            string sha256,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                ProtectedObject?>(
                null);
        }

        public Task<ProtectedObject?> FindByPathAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                ProtectedObject?>(
                null);
        }

        public Task UpsertAsync(
            ProtectedObject protectedObject,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSignatureService
        : IAuthenticodeSignatureService
    {
        public Task<AuthenticodeSignatureInfo> GetAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new AuthenticodeSignatureInfo(
                    filePath,
                    false,
                    false,
                    "Unsigned",
                    null,
                    null));
        }
    }
}