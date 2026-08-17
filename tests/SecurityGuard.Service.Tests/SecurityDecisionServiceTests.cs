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
}