using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Tests;

public sealed class ArchiveGuardExceptionServiceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_operation_removes_only_new_exception_even_when_cancelled(bool existing)
    {
        var repository = new RuleRepository();
        var service = new ArchiveGuardExceptionService(repository);
        var hash = new string('A', 64);
        if (existing)
            await service.AddSha256ExceptionAsync(hash, "sample.zip");
        var original = repository.Rules.ToArray();
        using var cancellation = new CancellationTokenSource();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            service.ExecuteWithSha256ExceptionAsync<string>(hash, "sample.zip", token =>
            {
                Assert.Single(repository.Rules);
                cancellation.Cancel();
                return Task.FromException<string>(new OperationCanceledException(token));
            }, cancellation.Token));

        Assert.Equal(original, repository.Rules);
        Assert.False(repository.CleanupWasCancelled);
    }

    [Fact]
    public async Task Successful_operation_keeps_exception_and_returns_result()
    {
        var repository = new RuleRepository();
        var service = new ArchiveGuardExceptionService(repository);
        var result = await service.ExecuteWithSha256ExceptionAsync(
            new string('B', 64), "sample.zip", _ =>
            {
                Assert.Single(repository.Rules);
                return Task.FromResult("restored.zip");
            });
        Assert.Equal("restored.zip", result);
        Assert.Single(repository.Rules);
    }

    [Fact]
    public async Task Concurrent_add_waits_for_failed_restore_then_creates_its_own_exception()
    {
        var repository = new RuleRepository();
        var service = new ArchiveGuardExceptionService(repository);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fail = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var hash = new string('C', 64);
        var restore = service.ExecuteWithSha256ExceptionAsync(hash, "sample.zip", _ =>
        {
            entered.SetResult();
            return fail.Task;
        });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var add = service.AddSha256ExceptionAsync(hash, "sample.zip");
        Assert.False(add.IsCompleted);
        fail.SetException(new IOException("Restoration failed"));
        await Assert.ThrowsAsync<IOException>(() => restore);
        await add.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(repository.Rules);
    }

    [Fact]
    public async Task Rollback_failure_preserves_both_errors()
    {
        var repository = new RuleRepository { FailDelete = true };
        var service = new ArchiveGuardExceptionService(repository);
        var error = await Assert.ThrowsAsync<AggregateException>(() =>
            service.ExecuteWithSha256ExceptionAsync<string>(new string('D', 64), "sample.zip",
                _ => Task.FromException<string>(new IOException("Restore failed"))));
        Assert.Collection(error.InnerExceptions,
            exception => Assert.IsType<IOException>(exception),
            exception => Assert.IsType<InvalidOperationException>(exception));
    }

    private sealed class RuleRepository : IRuleRepository
    {
        public List<SecurityRule> Rules { get; } = [];
        public bool FailDelete { get; init; }
        public bool CleanupWasCancelled { get; private set; }
        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<SecurityRule>>(Rules.ToArray());
        public Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(CancellationToken cancellationToken = default)
            => GetAllAsync(cancellationToken);
        public Task<SecurityRule?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
            => Task.FromResult(Rules.Find(rule => rule.Id == id));
        public Task UpsertAsync(SecurityRule rule, CancellationToken cancellationToken = default)
        {
            Rules.RemoveAll(item => item.Id == rule.Id);
            Rules.Add(rule);
            return Task.CompletedTask;
        }
        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            CleanupWasCancelled |= cancellationToken.IsCancellationRequested;
            cancellationToken.ThrowIfCancellationRequested();
            if (FailDelete) throw new InvalidOperationException("Delete failed");
            Rules.RemoveAll(rule => rule.Id == id);
            return Task.CompletedTask;
        }
    }
}
