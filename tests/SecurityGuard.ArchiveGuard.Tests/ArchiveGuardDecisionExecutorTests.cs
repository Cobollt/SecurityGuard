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
                new FakeExceptionService(),
                new FakeAuditSink(),
                new FakeQuarantineRepository());

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
                new FakeExceptionService(),
                new FakeAuditSink(),
                new FakeQuarantineRepository());

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
                new FakeExceptionService(),
                new FakeAuditSink(),
                new FakeQuarantineRepository());

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
                SecurityAction.Allow,
                SecurityAction.Quarantine,
                SecurityAction.Delete
            ],
            DateTimeOffset.UtcNow,
            new RuleMatchContext(
                FileHash:
                    new string(
                        'A',
                        64),
                FilePath:
                    filePath));
    }

    private sealed class FakeFileActions
        : IArchiveGuardFileActionService
    {
        public string? KeptFile { get; private set; }

        public string? QuarantinedFile { get; private set; }

        public int QuarantineCallCount { get; private set; }

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
            QuarantineCallCount++;
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
        private int _remainingRemoveFailures;

        public int RemoveCallCount { get; private set; }

        private SecurityDecisionRequest? _request;

        public FakeDecisionRepository(
            SecurityDecisionRequest request,
            int removeFailures = 0)
        {
            _request =
                request;

            _remainingRemoveFailures =
                removeFailures;
        }

        public Task AddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _request =
                request;

            return Task.CompletedTask;
        }

        public Task<bool> TryAddAsync(
            SecurityDecisionRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_request is not null &&
                !string.IsNullOrWhiteSpace(
                    request.Identity) &&
                string.Equals(
                    _request.Identity,
                    request.Identity,
                    StringComparison.Ordinal))
            {
                return Task.FromResult(
                    false);
            }

            _request =
                request;

            return Task.FromResult(
                true);
        }

        public Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

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
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                _request?.Id ==
                id
                    ? _request
                    : null);
        }

        public Task<SecurityDecisionRequest?> GetByIdentityAsync(
            string identity,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_request is null ||
                !string.Equals(
                    _request.Identity,
                    identity,
                    StringComparison.Ordinal))
            {
                return Task.FromResult<
                    SecurityDecisionRequest?>(
                    null);
            }

            return Task.FromResult<
                SecurityDecisionRequest?>(
                    _request);
        }

        public Task<int> RemoveOlderThanAsync(
            DateTimeOffset cutoffUtc,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_request is null ||
                _request.CreatedAtUtc >=
                cutoffUtc)
            {
                return Task.FromResult(
                    0);
            }

            _request =
                null;

            return Task.FromResult(
                1);
        }

        public Task RemoveAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            RemoveCallCount++;

            if (_remainingRemoveFailures > 0)
            {
                _remainingRemoveFailures--;

                throw new InvalidOperationException(
                    "Simulated decision cleanup failure.");
            }

            if (_request?.Id ==
                id)
            {
                _request =
                    null;
            }

            return Task.CompletedTask;
        }
    }

    private sealed class FakeQuarantineRepository
        : IQuarantineRepository
    {
        private readonly List<QuarantineRecord> _records =
            [];

        public void Add(
            QuarantineRecord record)
        {
            _records.Add(
                record);
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _records.Add(
                record);

            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyList<QuarantineRecord> result =
                _records.ToArray();

            return Task.FromResult(
                result);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                _records.FirstOrDefault(
                    record =>
                        record.Id ==
                        id));
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                _records.Count);
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _records.RemoveAll(
                record =>
                    record.Id ==
                    id);

            return Task.CompletedTask;
        }
    }

    private sealed class FakeExceptionService
        : IArchiveGuardExceptionService
    {
        public string? Sha256 { get; private set; }

        public Task AddSha256ExceptionAsync(
            string sha256,
            string fileName,
            CancellationToken cancellationToken = default)
        {
            Sha256 =
                sha256;

            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Persistent_cleanup_failure_does_not_repeat_quarantine()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request,
                removeFailures:
                    3);

        var actions =
            new FakeFileActions();

        var quarantineRepository =
            new FakeQuarantineRepository();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                new FakeExceptionService(),
                new FakeAuditSink(),
                quarantineRepository);

        var firstResult =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.Quarantine);

        Assert.False(
            firstResult.Success);

        Assert.Equal(
            1,
            actions.QuarantineCallCount);

        Assert.Equal(
            3,
            repository.RemoveCallCount);

        Assert.NotNull(
            await repository.GetByIdAsync(
                request.Id));

        var storedPath =
            Path.GetTempFileName();

        try
        {
            quarantineRepository.Add(
                new QuarantineRecord(
                    Guid.NewGuid(),
                    Path.GetFullPath(
                        request.FilePath!),
                    storedPath,
                    Path.GetFileName(
                        request.FilePath!),
                    request.RuleContext!.FileHash!,
                    1,
                    SecurityModuleKind.ArchiveGuard.ToString(),
                    $"ArchiveGuard decision {request.Id}: {request.Title}",
                    request.CreatedAtUtc.AddMilliseconds(
                        1)));

            var secondResult =
                await executor.ExecuteAsync(
                    request.Id,
                    SecurityAction.Quarantine);

            Assert.True(
                secondResult.Success);

            Assert.Equal(
                1,
                actions.QuarantineCallCount);

            Assert.Equal(
                4,
                repository.RemoveCallCount);

            Assert.Null(
                await repository.GetByIdAsync(
                    request.Id));
        }
        finally
        {
            if (File.Exists(
                    storedPath))
            {
                File.Delete(
                    storedPath);
            }
        }
    }

    [Fact]
    public async Task Cleanup_failure_does_not_repeat_successful_quarantine()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request,
                removeFailures:
                    1);

        var actions =
            new FakeFileActions();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                new FakeExceptionService(),
                new FakeAuditSink(),
                new FakeQuarantineRepository());

        await executor.ExecuteAsync(
            request.Id,
            SecurityAction.Quarantine);

        Assert.Equal(
            1,
            actions.QuarantineCallCount);

        await executor.ExecuteAsync(
            request.Id,
            SecurityAction.Quarantine);

        Assert.Equal(
            1,
            actions.QuarantineCallCount);
    }

    [Fact]
    public async Task Allow_action_creates_sha256_exception()
    {
        var request =
            CreateRequest();

        var repository =
            new FakeDecisionRepository(
                request);

        var actions =
            new FakeFileActions();

        var exceptions =
            new FakeExceptionService();

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                actions,
                exceptions,
                new FakeAuditSink(),
                new FakeQuarantineRepository());

        var result =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.Allow);

        Assert.True(
            result.Success);

        Assert.Equal(
            request.RuleContext!.FileHash,
            exceptions.Sha256);

        Assert.Equal(
            request.FilePath,
            actions.KeptFile);
    }

    [Fact]
    public async Task Allow_without_sha256_fails()
    {
        var filePath =
            Path.Combine(
                Path.GetTempPath(),
                "sample.exe");

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.ArchiveGuard,
                SecurityEventType.ArchiveScan,
                "Test",
                "Test",
                filePath,
                null,
                [
                    SecurityAction.Allow
                ],
                DateTimeOffset.UtcNow,
                new RuleMatchContext(
                    FilePath:
                        filePath),
                "ARCHIVE:TEST");

        var repository =
            new FakeDecisionRepository(
                request);

        var executor =
            new ArchiveGuardDecisionExecutor(
                repository,
                new FakeFileActions(),
                new FakeExceptionService(),
                new FakeAuditSink(),
                new FakeQuarantineRepository());

        var result =
            await executor.ExecuteAsync(
                request.Id,
                SecurityAction.Allow);

        Assert.False(
            result.Success);

        Assert.NotNull(
            await repository.GetByIdAsync(
                request.Id));
    }
}