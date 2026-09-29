using SecurityGuard.Core.Enums;
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
            SecurityAction.Block
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
}