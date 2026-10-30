using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferFilePolicyServiceTests
{
    [Fact]
    public async Task Trusted_werfault_does_not_create_pending_request()
    {
        var rules =
            new FakeRuleEngine(
                RuleEvaluationResult.NoMatch());

        var decisions =
            new FakeDecisionRequestRepository();

        var audit =
            new FakeAuditService();

        var trust =
            new FakeWindowsSystemProcessTrustService(
                true);

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust);

        await service.HandleAsync(
            CreateCandidate(
                "WerFault.exe",
                @"C:\Windows\System32\WerFault.exe"));

        Assert.Empty(
            decisions.Requests);

        Assert.Equal(
            1,
            trust.CallCount);

        Assert.Single(
            audit.Entries);

        Assert.Equal(
            SecurityAction.Allow,
            audit.Entries[0].Action);

        Assert.Equal(
            "Trusted Windows process file transfer candidate",
            audit.Entries[0].Title);
    }

    [Fact]
    public async Task Disabled_windows_trust_creates_pending_request()
    {
        var rules =
            new FakeRuleEngine(
                RuleEvaluationResult.NoMatch());

        var decisions =
            new FakeDecisionRequestRepository();

        var audit =
            new FakeAuditService();

        var trust =
            new FakeWindowsSystemProcessTrustService(
                true);

        var runtimeState =
            new FakeTransferGuardRuntimeState
            {
                CurrentSettings =
                    new TransferGuardSettings(
                        true,
                        TransferGuardMode.Monitor,
                        TransferEnforcementFailurePolicy.FailOpen,
                        false)
            };

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust,
                runtimeState);

        await service.HandleAsync(
            CreateCandidate(
                "WerFault.exe",
                @"C:\Windows\System32\WerFault.exe"));

        Assert.Single(
            decisions.Requests);

        Assert.Equal(
            0,
            trust.CallCount);
    }

    [Fact]
    public async Task Explicit_block_rule_has_priority_over_windows_trust()
    {
        var rules =
            new FakeRuleEngine(
                new RuleEvaluationResult(
                    true,
                    RuleDecision.Block,
                    Guid.NewGuid(),
                    "Explicit block"));

        var decisions =
            new FakeDecisionRequestRepository();

        var audit =
            new FakeAuditService();

        var trust =
            new FakeWindowsSystemProcessTrustService(
                true);

        var enforcement =
            new FakeFileEnforcementCoordinator();

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust,
                enforcementCoordinator:
                    enforcement);

        await service.HandleAsync(
            CreateCandidate(
                "WerFault.exe",
                @"C:\Windows\System32\WerFault.exe"));

        Assert.Empty(
            decisions.Requests);

        Assert.Equal(
            0,
            trust.CallCount);

        Assert.True(
            enforcement.CandidateCalled);

        Assert.Single(
            audit.Entries);

        Assert.Equal(
            SecurityAction.Block,
            audit.Entries[0].Action);
    }

    private static TransferFilePolicyService CreateService(
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        IWindowsSystemProcessTrustService trustService,
        FakeTransferGuardRuntimeState? runtimeState = null,
        ITransferFileEnforcementCoordinator? enforcementCoordinator = null)
    {
        return new TransferFilePolicyService(
            new TransferFileRuleContextFactory(),
            ruleEngine,
            decisionRepository,
            auditService,
            enforcementCoordinator ??
            new FakeFileEnforcementCoordinator(),
            trustService,
            runtimeState ??
            new FakeTransferGuardRuntimeState(),
            new TransferGuardOptions());
    }

    private static FileTransferCandidate CreateCandidate(
        string processName,
        string executablePath)
    {
        return new FileTransferCandidate(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            100,
            @"C:\Users\Ivan\Documents\report.pdf",
            "ABC123",
            1024 * 1024,
            1100 * 1024,
            1024 * 1024,
            TimeSpan.FromMilliseconds(400),
            0.93,
            TransferCorrelationConfidence.High,
            new TransferFileClassification(
                TransferFileCategory.Document,
                TransferFilePriority.High,
                "Document"),
            new NetworkConnectionObservation(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.20",
                51000,
                "1.1.1.1",
                443,
                new ProcessInfo(
                    100,
                    null,
                    processName,
                    executablePath,
                    null,
                    null,
                    null),
                executablePath));
    }

    private sealed class FakeRuleEngine
        : IRuleEngine
    {
        private readonly RuleEvaluationResult _result;

        public FakeRuleEngine(
            RuleEvaluationResult result)
        {
            _result =
                result;
        }

        public Task<RuleEvaluationResult> EvaluateAsync(
            SecurityModuleKind module,
            RuleMatchContext context,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _result);
        }
    }

    private sealed class FakeWindowsSystemProcessTrustService
        : IWindowsSystemProcessTrustService
    {
        private readonly bool _trusted;

        public int CallCount { get; private set; }

        public FakeWindowsSystemProcessTrustService(
            bool trusted)
        {
            _trusted =
                trusted;
        }

        public Task<WindowsSystemProcessTrustResult> EvaluateAsync(
            WindowsSystemProcessTrustRequest request,
            CancellationToken cancellationToken = default)
        {
            CallCount++;

            return Task.FromResult(
                new WindowsSystemProcessTrustResult(
                    _trusted,
                    _trusted
                        ? "Trusted"
                        : "Not trusted"));
        }
    }

    private sealed class FakeDecisionRequestRepository
        : IDecisionRequestRepository
    {
        public List<SecurityDecisionRequest> Requests { get; } =
            [];

        public Task AddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(
                request);

            return Task.CompletedTask;
        }

        public Task<bool> TryAddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(
                request);

            return Task.FromResult(
                true);
        }

        public Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                IReadOnlyList<SecurityDecisionRequest>>(
                Requests);
        }

        public Task<SecurityDecisionRequest?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Requests.FirstOrDefault(
                    request =>
                        request.Id == id));
        }

        public Task<SecurityDecisionRequest?> GetByIdentityAsync(
            string identity,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Requests.FirstOrDefault(
                    request =>
                        request.Identity == identity));
        }

        public Task<int> RemoveOlderThanAsync(
            DateTimeOffset cutoffUtc,
            CancellationToken cancellationToken = default)
        {
            var removed =
                Requests.RemoveAll(
                    request =>
                        request.CreatedAtUtc <
                        cutoffUtc);

            return Task.FromResult(
                removed);
        }

        public Task RemoveAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            Requests.RemoveAll(
                request =>
                    request.Id == id);

            return Task.CompletedTask;
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
                    module,
                    type,
                    severity,
                    title,
                    details,
                    action));

            return Task.CompletedTask;
        }
    }

    private sealed class FakeFileEnforcementCoordinator
        : ITransferFileEnforcementCoordinator
    {
        public bool CandidateCalled { get; private set; }

        public Task<TransferFileEnforcementResult> ApplyCandidateBlockAsync(
            Guid sourceSecurityRuleId,
            FileTransferCandidate candidate,
            CancellationToken cancellationToken = default)
        {
            CandidateCalled =
                true;

            return Task.FromResult(
                new TransferFileEnforcementResult(
                    true,
                    false,
                    "Applied",
                    DateTimeOffset.UtcNow +
                    TimeSpan.FromMinutes(2)));
        }

        public Task<TransferFileEnforcementResult> ApplyDecisionBlockAsync(
            Guid sourceSecurityRuleId,
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferFileEnforcementResult(
                    true,
                    false,
                    "Applied",
                    DateTimeOffset.UtcNow +
                    TimeSpan.FromMinutes(2)));
        }
    }

    private sealed class FakeTransferGuardRuntimeState
        : ITransferGuardRuntimeState
    {
        public TransferGuardSettings CurrentSettings { get; set; } =
            TransferGuardSettings.Default;
    }

    private sealed record AuditEntry(
        SecurityModuleKind Module,
        SecurityEventType Type,
        SecuritySeverity Severity,
        string Title,
        string Details,
        SecurityAction Action);
}