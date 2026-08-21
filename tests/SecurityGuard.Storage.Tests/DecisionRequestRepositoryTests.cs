using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class DecisionRequestRepositoryTests
{
    [Fact]
    public async Task Pending_request_can_be_saved_and_removed()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

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
                    SecurityAction.Allow,
                    SecurityAction.Quarantine,
                    SecurityAction.Delete
                ],
                DateTimeOffset.UtcNow);

        await repository.AddAsync(request);

        var pending =
            await repository.GetPendingAsync();

        var stored =
            Assert.Single(pending);

        Assert.Equal(
            request.Id,
            stored.Id);

        Assert.Contains(
            SecurityAction.Quarantine,
            stored.AvailableActions);

        await repository.RemoveAsync(
            request.Id);

        pending =
            await repository.GetPendingAsync();

        Assert.Empty(pending);
    }

    [Fact]
    public async Task Decision_request_preserves_rule_context()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown script",
                "powershell.exe -File test.ps1",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.Allow,
                    SecurityAction.Block
                ],
                DateTimeOffset.UtcNow,
                new RuleMatchContext(
                    FileHash:
                        "ABC",
                    Process:
                        "powershell.exe",
                    ParentProcess:
                        "explorer.exe",
                    UserName:
                        @"DESKTOP\User"));

        await repository.AddAsync(
            request);

        var stored =
            await repository.GetByIdAsync(
                request.Id);

        Assert.NotNull(
            stored);

        Assert.NotNull(
            stored.RuleContext);

        Assert.Equal(
            @"DESKTOP\User",
            stored.RuleContext.UserName);

        Assert.Equal(
            "explorer.exe",
            stored.RuleContext.ParentProcess);
    }

    [Fact]
    public async Task Duplicate_identity_is_not_added()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

        var first =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown",
                "powershell.exe -File test.ps1",
                @"C:\Temp\test.ps1",
                "powershell.exe",
                [
                    SecurityAction.Allow,
                    SecurityAction.Block
                ],
                DateTimeOffset.UtcNow,
                null,
                "ALG:ABC");

        var second =
            first with
            {
                Id =
                    Guid.NewGuid()
            };

        var firstAdded =
            await repository.TryAddAsync(
                first);

        var secondAdded =
            await repository.TryAddAsync(
                second);

        Assert.True(
            firstAdded);

        Assert.False(
            secondAdded);

        var pending =
            await repository.GetPendingAsync();

        Assert.Single(
            pending);
    }

    [Fact]
    public async Task Decision_can_be_found_by_identity()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Unknown",
                "powershell.exe",
                null,
                "powershell.exe",
                [
                    SecurityAction.AllowOnce
                ],
                DateTimeOffset.UtcNow,
                null,
                "ALG:123");

        await repository.AddAsync(
            request);

        var stored =
            await repository.GetByIdentityAsync(
                "ALG:123");

        Assert.NotNull(
            stored);

        Assert.Equal(
            request.Id,
            stored.Id);
    }

    [Fact]
    public async Task Old_decision_requests_are_removed()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteDecisionRequestRepository(
                database.ConnectionFactory);

        var oldRequest =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "Old",
                "Old",
                null,
                "powershell.exe",
                [
                    SecurityAction.AllowOnce
                ],
                DateTimeOffset.UtcNow -
                TimeSpan.FromHours(1),
                null,
                "ALG:OLD");

        var newRequest =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.AlgorithmExecution,
                "New",
                "New",
                null,
                "powershell.exe",
                [
                    SecurityAction.AllowOnce
                ],
                DateTimeOffset.UtcNow,
                null,
                "ALG:NEW");

        await repository.AddAsync(
            oldRequest);

        await repository.AddAsync(
            newRequest);

        var removed =
            await repository.RemoveOlderThanAsync(
                DateTimeOffset.UtcNow -
                TimeSpan.FromMinutes(10));

        Assert.Equal(
            1,
            removed);

        var remaining =
            await repository.GetPendingAsync();

        var request =
            Assert.Single(
                remaining);

        Assert.Equal(
            newRequest.Id,
            request.Id);
    }
}