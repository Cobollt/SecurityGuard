using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Service.Application;
using SecurityGuard.Storage.Database;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityDecisionServiceTests
{
    [Fact]
    public async Task Decision_is_forwarded_to_module_handler()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var handler =
            new FakeSecurityDecisionHandler();

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown script",
                "Execution blocked",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.AllowOnce,
                    SecurityAction.Quarantine
                ],
                DateTimeOffset.UtcNow);

        await requestRepository.AddAsync(
            request);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [handler],
                new AuditService(
                    eventRepository));

        var decision =
            new SecurityDecision(
                request.Id,
                SecurityAction.AllowOnce,
                false,
                DateTimeOffset.UtcNow);

        await service.ApplyAsync(
            decision);

        Assert.True(
            handler.WasCalled);

        Assert.Equal(
            SecurityAction.AllowOnce,
            handler.Decision?.Action);

        var stored =
            await requestRepository.GetByIdAsync(
                request.Id);

        Assert.Null(stored);
    }

    [Fact]
    public async Task Unsupported_action_is_rejected()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown script",
                "Execution blocked",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.AllowOnce
                ],
                DateTimeOffset.UtcNow);

        await requestRepository.AddAsync(
            request);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [new FakeSecurityDecisionHandler()],
                new AuditService(
                    eventRepository));

        var decision =
            new SecurityDecision(
                request.Id,
                SecurityAction.Delete,
                false,
                DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () =>
                await service.ApplyAsync(
                    decision));
    }

    [Fact]
    public async Task Allow_application_removes_pending_requests_for_same_program()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var firefox1 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:1");

        var firefox2 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:2");

        var firefox3 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:3");

        var chrome =
            CreateTransferRequest(
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "chrome.exe",
                "NET:CHROME:1");

        await requestRepository.AddAsync(
            firefox1);

        await requestRepository.AddAsync(
            firefox2);

        await requestRepository.AddAsync(
            firefox3);

        await requestRepository.AddAsync(
            chrome);

        var handler =
            new FakeSecurityDecisionHandler(
                SecurityModuleKind.TransferGuard);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [handler],
                new AuditService(
                    eventRepository));

        await service.ApplyAsync(
            new SecurityDecision(
                firefox1.Id,
                SecurityAction.AllowApplication,
                true,
                DateTimeOffset.UtcNow));

        var pending =
            await requestRepository.GetPendingAsync();

        var remaining =
            Assert.Single(
                pending);

        Assert.Equal(
            chrome.Id,
            remaining.Id);

        Assert.True(
            handler.WasCalled);

        Assert.Equal(
            SecurityAction.AllowApplication,
            handler.Decision?.Action);
    }

    [Fact]
    public async Task Allow_application_does_not_remove_same_process_name_from_other_path()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var installedFirefox =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:INSTALLED");

        var portableFirefox =
            CreateTransferRequest(
                @"D:\Portable\Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:PORTABLE");

        await requestRepository.AddAsync(
            installedFirefox);

        await requestRepository.AddAsync(
            portableFirefox);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [
                    new FakeSecurityDecisionHandler(
                    SecurityModuleKind.TransferGuard)
                ],
                new AuditService(
                    eventRepository));

        await service.ApplyAsync(
            new SecurityDecision(
                installedFirefox.Id,
                SecurityAction.AllowApplication,
                true,
                DateTimeOffset.UtcNow));

        var pending =
            await requestRepository.GetPendingAsync();

        var remaining =
            Assert.Single(
                pending);

        Assert.Equal(
            portableFirefox.Id,
            remaining.Id);

        Assert.Equal(
            @"D:\Portable\Firefox\firefox.exe",
            remaining.RuleContext?.ProcessPath);
    }

    [Fact]
    public async Task Block_application_removes_all_pending_requests_for_same_program()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var firefox1 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:BLOCK:1");

        var firefox2 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:BLOCK:2");

        var firefox3 =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:BLOCK:3");

        var chrome =
            CreateTransferRequest(
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "chrome.exe",
                "NET:CHROME:BLOCK:1");

        await requestRepository.AddAsync(
            firefox1);

        await requestRepository.AddAsync(
            firefox2);

        await requestRepository.AddAsync(
            firefox3);

        await requestRepository.AddAsync(
            chrome);

        var handler =
            new FakeSecurityDecisionHandler(
                SecurityModuleKind.TransferGuard);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [handler],
                new AuditService(
                    eventRepository));

        await service.ApplyAsync(
            new SecurityDecision(
                firefox1.Id,
                SecurityAction.BlockApplication,
                true,
                DateTimeOffset.UtcNow));

        var pending =
            await requestRepository.GetPendingAsync();

        var remaining =
            Assert.Single(
                pending);

        Assert.Equal(
            chrome.Id,
            remaining.Id);

        Assert.True(
            handler.WasCalled);

        Assert.Equal(
            SecurityAction.BlockApplication,
            handler.Decision?.Action);
    }

    [Fact]
    public async Task Block_application_does_not_remove_same_process_name_from_other_path()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var initializer =
            new DatabaseInitializer(
                environment.ConnectionFactory);

        await initializer.InitializeAsync();

        var requestRepository =
            new SqliteDecisionRequestRepository(
                environment.ConnectionFactory);

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var installedFirefox =
            CreateTransferRequest(
                @"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:BLOCK:INSTALLED");

        var portableFirefox =
            CreateTransferRequest(
                @"D:\Portable\Firefox\firefox.exe",
                "firefox.exe",
                "NET:FIREFOX:BLOCK:PORTABLE");

        await requestRepository.AddAsync(
            installedFirefox);

        await requestRepository.AddAsync(
            portableFirefox);

        var service =
            new SecurityDecisionService(
                requestRepository,
                [
                    new FakeSecurityDecisionHandler(
                    SecurityModuleKind.TransferGuard)
                ],
                new AuditService(
                    eventRepository));

        await service.ApplyAsync(
            new SecurityDecision(
                installedFirefox.Id,
                SecurityAction.BlockApplication,
                true,
                DateTimeOffset.UtcNow));

        var pending =
            await requestRepository.GetPendingAsync();

        var remaining =
            Assert.Single(
                pending);

        Assert.Equal(
            portableFirefox.Id,
            remaining.Id);

        Assert.Equal(
            @"D:\Portable\Firefox\firefox.exe",
            remaining.RuleContext?.ProcessPath);
    }

    private static SecurityDecisionRequest CreateTransferRequest(
    string processPath,
    string processName,
    string identity)
    {
        return new SecurityDecisionRequest(
            Guid.NewGuid(),
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            "Outbound connection requires decision",
            processPath,
            null,
            processName,
            [
            SecurityAction.Allow,
            SecurityAction.AllowApplication,
            SecurityAction.Block,
            SecurityAction.BlockApplication
            ],
            DateTimeOffset.UtcNow,
            new RuleMatchContext(
                Process:
                    processName,
                ProcessPath:
                    processPath,
                RemoteAddress:
                    "1.1.1.1",
                RemotePort:
                    443,
                Protocol:
                    "Tcp",
                TransferActivityKind:
                    "NetworkConnection"),
            identity);
    }

    [Fact]
    public async Task Concurrent_decisions_for_same_request_are_handled_once()
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

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Concurrent",
                "Concurrent",
                null,
                "powershell.exe",
                [
                    SecurityAction.AllowOnce
                ],
                DateTimeOffset.UtcNow);

        var requestRepository =
            new SingleDecisionRequestRepository(
                request);

        var handler =
            new BlockingSecurityDecisionHandler();

        var service =
            new SecurityDecisionService(
                requestRepository,
                [handler],
                new AuditService(
                    eventRepository));

        var decision =
            new SecurityDecision(
                request.Id,
                SecurityAction.AllowOnce,
                false,
                DateTimeOffset.UtcNow);

        var firstTask =
            service.ApplyAsync(
                decision);

        Assert.Equal(
            1,
            handler.CallCount);

        var secondTask =
            service.ApplyAsync(
                decision);

        var callsBeforeRelease =
            handler.CallCount;

        handler.ReleaseFirst();

        Exception? secondException =
            null;

        await firstTask;

        try
        {
            await secondTask;
        }
        catch (Exception exception)
        {
            secondException =
                exception;
        }

        Assert.Equal(
            1,
            callsBeforeRelease);

        Assert.IsType<InvalidOperationException>(
            secondException);

        Assert.Equal(
            1,
            handler.CallCount);
    }

    private sealed class SingleDecisionRequestRepository
        : IDecisionRequestRepository
    {
        private readonly object _sync =
            new();

        private SecurityDecisionRequest? _request;

        public SingleDecisionRequestRepository(
            SecurityDecisionRequest request)
        {
            _request =
                request;
        }

        public Task AddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                _request =
                    request;
            }

            return Task.CompletedTask;
        }

        public Task<bool> TryAddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (_request is not null)
                {
                    return Task.FromResult(
                        false);
                }

                _request =
                    request;

                return Task.FromResult(
                    true);
            }
        }

        public Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                IReadOnlyList<SecurityDecisionRequest> result =
                    _request is null
                        ? []
                        : [_request];

                return Task.FromResult(
                    result);
            }
        }

        public Task<SecurityDecisionRequest?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                return Task.FromResult(
                    _request?.Id == id
                        ? _request
                        : null);
            }
        }

        public Task<SecurityDecisionRequest?> GetByIdentityAsync(
            string identity,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                return Task.FromResult(
                    string.Equals(
                        _request?.Identity,
                        identity,
                        StringComparison.Ordinal)
                        ? _request
                        : null);
            }
        }

        public Task<int> RemoveOlderThanAsync(
            DateTimeOffset cutoffUtc,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (_request is null ||
                    _request.CreatedAtUtc >= cutoffUtc)
                {
                    return Task.FromResult(
                        0);
                }

                _request =
                    null;

                return Task.FromResult(
                    1);
            }
        }

        public Task RemoveAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (_request?.Id == id)
                {
                    _request =
                        null;
                }
            }

            return Task.CompletedTask;
        }
    }

    private sealed class BlockingSecurityDecisionHandler
        : ISecurityDecisionHandler
    {
        private readonly TaskCompletionSource _releaseFirst =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);

        private int _callCount;

        public SecurityModuleKind Module =>
            SecurityModuleKind.AlgorithmGuard;

        public int CallCount =>
            Volatile.Read(
                ref _callCount);

        public Task HandleAsync(
            SecurityDecisionRequest request,
            SecurityDecision decision,
            CancellationToken cancellationToken = default)
        {
            var call =
                Interlocked.Increment(
                    ref _callCount);

            return call == 1
                ? _releaseFirst.Task
                : Task.CompletedTask;
        }

        public void ReleaseFirst()
        {
            _releaseFirst.TrySetResult();
        }
    }
}
