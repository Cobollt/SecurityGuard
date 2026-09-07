using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardDecisionExecutorTests
{
    [Fact]
    public async Task Quarantine_action_is_executed()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request);

        var actions =
            new FakeFileActions();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                new FakeAuditSink());

        var result =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.Quarantine);

        Assert.True(
            result.Success);

        Assert.Equal(
            request.FilePath,
            actions.QuarantinedFile);

        Assert.Null(
            await repository.GetByIdAsync(
                request.Id));
    }

    [Fact]
    public async Task Delete_action_is_executed()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request);

        var actions =
            new FakeFileActions();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                new FakeAuditSink());

        var result =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.Delete);

        Assert.True(
            result.Success);

        Assert.Equal(
            request.FilePath,
            actions.DeletedFile);
    }

    [Fact]
    public async Task Allow_once_keeps_file()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request);

        var actions =
            new FakeFileActions();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                new FakeAuditSink());

        var result =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.AllowOnce);

        Assert.True(
            result.Success);

        Assert.Equal(
            request.FilePath,
            actions.KeptFile);
    }

    private static SecurityDecisionRequest CreateRequest()
    {
        var filePath =
            Path.Combine(
                Path.GetTempPath(),
                "sample.exe");

        return new SecurityDecisionRequest(
            Guid.NewGuid(),
            SecurityModuleKind.ArchiveGuard,
            SecurityEventType.ArchiveScan,
            "Test",
            "Test",
            filePath,
            null,
            [
                SecurityAction.AllowOnce,
                SecurityAction.Quarantine,
                SecurityAction.Delete
            ],
            DateTimeOffset.UtcNow,
            new RuleMatchContext(
                FilePath:
                    filePath),
            "ARCHIVE:TEST");
    }

    private sealed class FakeFileActions
        : IArchiveGuardFileActionService
    {
        public string? KeptFile { get; private set; }

        public string? QuarantinedFile { get; private set; }

        public string? DeletedFile { get; private set; }

        public Task KeepAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            KeptFile =
                filePath;

            return Task.CompletedTask;
        }

        public Task QuarantineAsync(
            string filePath,
            string reason,
            CancellationToken cancellationToken = default)
        {
            QuarantinedFile =
                filePath;

            return Task.CompletedTask;
        }

        public Task DeleteAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            DeletedFile =
                filePath;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeAuditSink
        : IArchiveGuardAuditSink
    {
        public Task WriteAsync(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string title,
            string details,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FakeDecisionRepository
        : IDecisionRequestRepository
    {
        private SecurityDecisionRequest? _request;

        public FakeDecisionRepository(
            SecurityDecisionRequest request)
        {
            _request =
                request;
        }

        public Task AddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            _request =
                request;

            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<SecurityDecisionRequest> result =
                _request is null
                    ? []
                    : [_request];

            return Task.FromResult(
                result);
        }

        public Task<SecurityDecisionRequest?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _request?.Id ==
                id
                    ? _request
                    : null);
        }

        public Task RemoveAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            if (_request?.Id ==
                id)
            {
                _request =
                    null;
            }

            return Task.CompletedTask;
        }
    }
}