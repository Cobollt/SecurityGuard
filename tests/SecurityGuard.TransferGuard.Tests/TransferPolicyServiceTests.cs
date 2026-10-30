using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferPolicyServiceTests
{
    [Fact]
    public async Task Trusted_windows_process_does_not_create_pending_request()
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
            CreateObservation(
                "svchost.exe",
                @"C:\Windows\System32\svchost.exe"));

        Assert.Empty(
            decisions.Requests);

        Assert.Single(
            audit.Entries);

        Assert.Equal(
            SecurityAction.Allow,
            audit.Entries[0].Action);

        Assert.Equal(
            "Trusted Windows process outbound connection",
            audit.Entries[0].Title);
    }

    [Fact]
    public async Task Cmd_process_still_creates_pending_request()
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
                request =>
                    !string.Equals(
                        request.ProcessName,
                        "cmd.exe",
                        StringComparison.OrdinalIgnoreCase));

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust);

        await service.HandleAsync(
            CreateObservation(
                "cmd.exe",
                @"C:\Windows\System32\cmd.exe"));

        Assert.Single(
            decisions.Requests);

        Assert.Equal(
            "cmd.exe",
            decisions.Requests[0].ProcessName);

        Assert.Equal(
            "Неизвестное исходящее соединение",
            decisions.Requests[0].Title);
    }

    [Fact]
    public async Task Third_party_process_creates_pending_request()
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
                false);

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust);

        await service.HandleAsync(
            CreateObservation(
                "client.exe",
                @"C:\Apps\client.exe"));

        Assert.Single(
            decisions.Requests);

        Assert.Equal(
            "client.exe",
            decisions.Requests[0].ProcessName);
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

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust);

        await service.HandleAsync(
            CreateObservation(
                "svchost.exe",
                @"C:\Windows\System32\svchost.exe"));

        Assert.Empty(
            decisions.Requests);

        Assert.Equal(
            0,
            trust.CallCount);

        Assert.Single(
            audit.Entries);

        Assert.Equal(
            SecurityAction.Block,
            audit.Entries[0].Action);

        Assert.Equal(
            "Outbound connection matched block rule",
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
            CreateObservation(
                "svchost.exe",
                @"C:\Windows\System32\svchost.exe"));

        Assert.Single(
            decisions.Requests);

        Assert.Equal(
            0,
            trust.CallCount);
    }

    [Fact]
    public async Task Wfp_application_path_is_used_when_process_executable_path_is_empty()
    {
        var rules =
            new FakeRuleEngine(
                RuleEvaluationResult.NoMatch());

        var decisions =
            new FakeDecisionRequestRepository();

        var audit =
            new FakeAuditService();

        var applicationPath =
            @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.00000.0-0\MsMpEng.exe";

        var trust =
            new FakeWindowsSystemProcessTrustService(
                request =>
                {
                    Assert.Equal(
                        applicationPath,
                        request.ExecutablePath);

                    return true;
                });

        var service =
            CreateService(
                rules,
                decisions,
                audit,
                trust);

        var observation =
            new NetworkConnectionObservation(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                50000,
                "20.42.1.1",
                443,
                new ProcessInfo(
                    100,
                    null,
                    "MsMpEng.exe",
                    "",
                    null,
                    null,
                    null),
                applicationPath);

        await service.HandleAsync(
            observation);

        Assert.Empty(
            decisions.Requests);

        Assert.Equal(
            1,
            trust.CallCount);

        Assert.Single(
            audit.Entries);

        Assert.Equal(
            "Trusted Windows process outbound connection",
            audit.Entries[0].Title);

        Assert.Equal(
            SecurityAction.Allow,
            audit.Entries[0].Action);
    }

    private static TransferPolicyService CreateService(
        IRuleEngine ruleEngine,
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        IWindowsSystemProcessTrustService trustService,
        FakeTransferGuardRuntimeState? runtimeState = null)
    {
        return new TransferPolicyService(
            new TransferRuleContextFactory(),
            ruleEngine,
            decisionRepository,
            auditService,
            new TransferGuardOptions(),
            trustService,
            runtimeState ??
            new FakeTransferGuardRuntimeState());
    }

    private static NetworkConnectionObservation CreateObservation(
        string processName,
        string executablePath)
    {
        return new NetworkConnectionObservation(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            TransferProtocol.Tcp,
            NetworkAddressFamily.IPv4,
            "192.168.1.10",
            50000,
            "8.8.8.8",
            443,
            new ProcessInfo(
                100,
                null,
                processName,
                executablePath,
                null,
                null,
                null),
            executablePath);
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
        private readonly Func<
            WindowsSystemProcessTrustRequest,
            bool> _resultFactory;

        public int CallCount { get; private set; }

        public FakeWindowsSystemProcessTrustService(
            bool trusted)
            : this(
                _ => trusted)
        {
        }

        public FakeWindowsSystemProcessTrustService(
            Func<
                WindowsSystemProcessTrustRequest,
                bool> resultFactory)
        {
            _resultFactory =
                resultFactory;
        }

        public Task<WindowsSystemProcessTrustResult> EvaluateAsync(
            WindowsSystemProcessTrustRequest request,
            CancellationToken cancellationToken = default)
        {
            CallCount++;

            var trusted =
                _resultFactory(
                    request);

            return Task.FromResult(
                new WindowsSystemProcessTrustResult(
                    trusted,
                    trusted
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

    private sealed record AuditEntry(
        SecurityModuleKind Module,
        SecurityEventType Type,
        SecuritySeverity Severity,
        string Title,
        string Details,
        SecurityAction Action);

    private sealed class FakeTransferGuardRuntimeState
        : ITransferGuardRuntimeState
    {
        public TransferGuardSettings CurrentSettings { get; set; } =
            TransferGuardSettings.Default;
    }
}