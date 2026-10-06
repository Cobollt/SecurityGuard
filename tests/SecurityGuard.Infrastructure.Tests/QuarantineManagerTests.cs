using SecurityGuard.Core.Enums;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Infrastructure.Hashing;
using SecurityGuard.Infrastructure.Quarantine;
using SecurityGuard.Storage.Repositories;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Infrastructure.FileSystem;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Infrastructure.Tests;

public sealed class QuarantineManagerTests
{
    [Fact]
    public async Task File_is_moved_to_quarantine()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var hashService =
            new Sha256FileHashService();

        var auditService =
            new AuditService(
                eventRepository);

        var manager =
            new QuarantineManager(
                environment.Paths,
                hashService,
                quarantineRepository,
                auditService,
                new NoOpFileAccessProtectionService());

        var source =
            Path.Combine(
                environment.RootDirectory,
                "test.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host test");

        var record =
            await manager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        Assert.False(
            File.Exists(source));

        Assert.True(
            File.Exists(record.StoredPath));

        var stored =
            await quarantineRepository.GetByIdAsync(
                record.Id);

        Assert.NotNull(stored);
    }

    [Fact]
    public async Task Quarantined_file_can_be_restored()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var hashService =
            new Sha256FileHashService();

        var manager =
            new QuarantineManager(
                environment.Paths,
                hashService,
                quarantineRepository,
                new AuditService(eventRepository),
                new NoOpFileAccessProtectionService());

        var source =
            Path.Combine(
                environment.RootDirectory,
                "restore-test.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host restore");

        var record =
            await manager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        Assert.False(
            File.Exists(source));

        var restoredPath =
            await manager.RestoreAsync(
                record.Id);

        Assert.Equal(
            source,
            restoredPath);

        Assert.True(
            File.Exists(source));

        Assert.False(
            File.Exists(record.StoredPath));

        var stored =
            await quarantineRepository.GetByIdAsync(
                record.Id);

        Assert.Null(stored);
    }

    [Fact]
    public async Task Quarantined_file_can_be_deleted()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(eventRepository),
                new NoOpFileAccessProtectionService());

        var source =
            Path.Combine(
                environment.RootDirectory,
                "delete-test.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host delete");

        var record =
            await manager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        await manager.DeleteAsync(
            record.Id);

        Assert.False(
            File.Exists(record.StoredPath));

        var stored =
            await quarantineRepository.GetByIdAsync(
                record.Id);

        Assert.Null(stored);
    }

    [Fact]
    public async Task Audit_failure_does_not_fail_completed_quarantine()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new ThrowingAuditService(),
                new NoOpFileAccessProtectionService());

        var source =
            Path.Combine(
                environment.RootDirectory,
                "audit-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host audit");

        var record =
            await manager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        Assert.False(
            File.Exists(
                source));

        Assert.True(
            File.Exists(
                record.StoredPath));

        Assert.NotNull(
            await quarantineRepository.GetByIdAsync(
                record.Id));
    }

    private sealed class ThrowingAuditService
        : IAuditService
    {
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
            throw new InvalidOperationException(
                "Simulated audit failure.");
        }
    }

    [Fact]
    public async Task Audit_failure_does_not_fail_completed_restore()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "restore-audit-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host restore");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    eventRepository),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var restoreManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new ThrowingAuditService(),
                new NoOpFileAccessProtectionService());

        var restoredPath =
            await restoreManager.RestoreAsync(
                record.Id);

        Assert.Equal(
            source,
            restoredPath);

        Assert.True(
            File.Exists(
                source));

        Assert.False(
            File.Exists(
                record.StoredPath));

        Assert.Null(
            await quarantineRepository.GetByIdAsync(
                record.Id));
    }

    [Fact]
    public async Task Audit_failure_does_not_fail_completed_delete()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var eventRepository =
            new SqliteSecurityEventRepository(
                environment.ConnectionFactory);

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "delete-audit-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host delete");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    eventRepository),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var deleteManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new ThrowingAuditService(),
                new NoOpFileAccessProtectionService());

        await deleteManager.DeleteAsync(
            record.Id);

        Assert.False(
            File.Exists(
                record.StoredPath));

        Assert.Null(
            await quarantineRepository.GetByIdAsync(
                record.Id));
    }

    private sealed class ThrowingFileAccessProtectionService
        : IFileAccessProtectionService
    {
        public void ProtectDirectory(
            string path)
        {
        }

        public void ProtectFile(
            string path)
        {
            throw new InvalidOperationException(
                "Simulated file protection failure.");
        }
    }

    [Fact]
    public async Task Protection_failure_does_not_leave_orphan_quarantine_file()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "protection-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host protection");

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new ThrowingFileAccessProtectionService());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                manager.QuarantineAsync(
                    source,
                    SecurityModuleKind.AlgorithmGuard,
                    "Test"));

        Assert.True(
            File.Exists(
                source));

        Assert.Equal(
            0,
            await quarantineRepository.CountAsync());

        Assert.Empty(
            Directory.GetFiles(
                environment.Paths.QuarantineDirectory,
                "*.sgq"));
    }

    private sealed class ThrowingQuarantineRepository
        : IQuarantineRepository
    {
        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException(
                "Simulated quarantine repository failure.");
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<QuarantineRecord>>(
                []);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<QuarantineRecord?>(
                null);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Stored_file_cleanup_failure_does_not_leave_untracked_quarantine_file()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "quarantine-cleanup-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host quarantine");

        using var sourceLock =
            new FileStream(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new ReadOnlyStoredFileAfterDeleteRepository(
                    quarantineRepository,
                    environment.Paths.QuarantineDirectory),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        try
        {
            await Assert.ThrowsAnyAsync<Exception>(
                () =>
                    manager.QuarantineAsync(
                        source,
                        SecurityModuleKind.AlgorithmGuard,
                        "Test"));

            Assert.Equal(
                1,
                await quarantineRepository.CountAsync());

            var records =
                await quarantineRepository.GetAllAsync();

            var record =
                Assert.Single(
                    records);

            Assert.True(
                File.Exists(
                    record.StoredPath));
        }
        finally
        {
            foreach (var path in
                     Directory.EnumerateFiles(
                         environment.Paths.QuarantineDirectory,
                         "*.sgq"))
            {
                File.SetAttributes(
                    path,
                    FileAttributes.Normal);
            }
        }
    }

    [Fact]
    public async Task Repository_failure_does_not_leave_orphan_quarantine_file()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var source =
            Path.Combine(
                environment.RootDirectory,
                "repository-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host repository");

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new ThrowingQuarantineRepository(),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                manager.QuarantineAsync(
                    source,
                    SecurityModuleKind.AlgorithmGuard,
                    "Test"));

        Assert.True(
            File.Exists(
                source));

        Assert.Empty(
            Directory.GetFiles(
                environment.Paths.QuarantineDirectory,
                "*.sgq"));
    }

    private sealed class DeleteFailingQuarantineRepository
        : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;

        public DeleteFailingQuarantineRepository(
            IQuarantineRepository inner)
        {
            _inner =
                inner;
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return _inner.AddAsync(
                record,
                cancellationToken);
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException(
                "Simulated quarantine delete failure.");
        }
    }

    [Fact]
    public async Task Repository_delete_failure_rolls_back_restore_target()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "restore-delete-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host restore");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var restoreManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new DeleteFailingQuarantineRepository(
                    quarantineRepository),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                restoreManager.RestoreAsync(
                    record.Id));

        Assert.False(
            File.Exists(
                source));

        Assert.True(
            File.Exists(
                record.StoredPath));

        Assert.NotNull(
            await quarantineRepository.GetByIdAsync(
                record.Id));
    }

    [Fact]
    public async Task Repository_delete_failure_preserves_quarantined_file()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "delete-repository-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host delete");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var deleteManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new DeleteFailingQuarantineRepository(
                    quarantineRepository),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                deleteManager.DeleteAsync(
                    record.Id));

        Assert.True(
            File.Exists(
                record.StoredPath));

        Assert.NotNull(
            await quarantineRepository.GetByIdAsync(
                record.Id));
    }

    private sealed class ReadOnlyStagedFileQuarantineRepository
    : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;
        private readonly string _storedPath;

        public ReadOnlyStagedFileQuarantineRepository(
            IQuarantineRepository inner,
            string storedPath)
        {
            _inner =
                inner;

            _storedPath =
                storedPath;
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return _inner.AddAsync(
                record,
                cancellationToken);
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public async Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            var directory =
                Path.GetDirectoryName(
                    _storedPath)!;

            var fileName =
                Path.GetFileName(
                    _storedPath);

            var stagedPath =
                Directory
                    .EnumerateFiles(
                        directory,
                        $"{fileName}.*.delete")
                    .Single();

            File.SetAttributes(
                stagedPath,
                File.GetAttributes(
                    stagedPath) |
                FileAttributes.ReadOnly);

            await _inner.DeleteAsync(
                id,
                cancellationToken);
        }
    }

    [Fact]
    public async Task Final_delete_failure_does_not_leave_untracked_quarantine_file()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "final-delete-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host delete");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var deleteManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new ReadOnlyStagedFileQuarantineRepository(
                    quarantineRepository,
                    record.StoredPath),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        try
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () =>
                    deleteManager.DeleteAsync(
                        record.Id));

            Assert.NotNull(
                await quarantineRepository.GetByIdAsync(
                    record.Id));

            Assert.True(
                File.Exists(
                    record.StoredPath));
        }
        finally
        {
            var directory =
                Path.GetDirectoryName(
                    record.StoredPath)!;

            var fileName =
                Path.GetFileName(
                    record.StoredPath);

            foreach (var path in
                     Directory.EnumerateFiles(
                         directory,
                         $"{fileName}*"))
            {
                File.SetAttributes(
                    path,
                    FileAttributes.Normal);
            }
        }
    }

    private sealed class CancelAfterDeleteQuarantineRepository
        : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;
        private readonly string _storedPath;
        private readonly CancellationTokenSource _cancellationTokenSource;

        public CancelAfterDeleteQuarantineRepository(
            IQuarantineRepository inner,
            string storedPath,
            CancellationTokenSource cancellationTokenSource)
        {
            _inner =
                inner;

            _storedPath =
                storedPath;

            _cancellationTokenSource =
                cancellationTokenSource;
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return _inner.AddAsync(
                record,
                cancellationToken);
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public async Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            await _inner.DeleteAsync(
                id,
                cancellationToken);

            File.SetAttributes(
                _storedPath,
                File.GetAttributes(
                    _storedPath) |
                FileAttributes.ReadOnly);

            _cancellationTokenSource.Cancel();
        }
    }

    [Fact]
    public async Task Cancellation_during_restore_rollback_does_not_lose_quarantine_record()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "restore-cancellation.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host restore");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        using var cancellationTokenSource =
            new CancellationTokenSource();

        var restoreManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new CancelAfterDeleteQuarantineRepository(
                    quarantineRepository,
                    record.StoredPath,
                    cancellationTokenSource),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        try
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () =>
                    restoreManager.RestoreAsync(
                        record.Id,
                        cancellationToken:
                            cancellationTokenSource.Token));

            Assert.False(
                File.Exists(
                    source));

            Assert.True(
                File.Exists(
                    record.StoredPath));

            Assert.NotNull(
                await quarantineRepository.GetByIdAsync(
                    record.Id));
        }
        finally
        {
            if (File.Exists(
                    record.StoredPath))
            {
                File.SetAttributes(
                    record.StoredPath,
                    FileAttributes.Normal);
            }
        }
    }

    private sealed class ReadOnlyRestoreFilesAfterDeleteRepository
        : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;
        private readonly string _storedPath;
        private readonly string _targetPath;

        public ReadOnlyRestoreFilesAfterDeleteRepository(
            IQuarantineRepository inner,
            string storedPath,
            string targetPath)
        {
            _inner =
                inner;

            _storedPath =
                storedPath;

            _targetPath =
                targetPath;
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return _inner.AddAsync(
                record,
                cancellationToken);
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public async Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            await _inner.DeleteAsync(
                id,
                cancellationToken);

            File.SetAttributes(
                _storedPath,
                File.GetAttributes(
                    _storedPath) |
                FileAttributes.ReadOnly);

            File.SetAttributes(
                _targetPath,
                File.GetAttributes(
                    _targetPath) |
                FileAttributes.ReadOnly);
        }
    }

    [Fact]
    public async Task Restore_rollback_cleanup_failure_does_not_lose_quarantine_record()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "restore-double-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host restore");

        var setupManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                quarantineRepository,
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        var record =
            await setupManager.QuarantineAsync(
                source,
                SecurityModuleKind.AlgorithmGuard,
                "Test");

        var restoreManager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new ReadOnlyRestoreFilesAfterDeleteRepository(
                    quarantineRepository,
                    record.StoredPath,
                    source),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        try
        {
            await Assert.ThrowsAnyAsync<Exception>(
                () =>
                    restoreManager.RestoreAsync(
                        record.Id));

            Assert.True(
                File.Exists(
                    record.StoredPath));

            Assert.True(
                File.Exists(
                    source));

            Assert.NotNull(
                await quarantineRepository.GetByIdAsync(
                    record.Id));
        }
        finally
        {
            if (File.Exists(
                    record.StoredPath))
            {
                File.SetAttributes(
                    record.StoredPath,
                    FileAttributes.Normal);
            }

            if (File.Exists(
                    source))
            {
                File.SetAttributes(
                    source,
                    FileAttributes.Normal);
            }
        }
    }

    [Fact]
    public async Task Repository_rollback_failure_preserves_quarantined_file()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "quarantine-rollback-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host quarantine");

        using var sourceLock =
            new FileStream(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new DeleteFailingQuarantineRepository(
                    quarantineRepository),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () =>
                    manager.QuarantineAsync(
                        source,
                        SecurityModuleKind.AlgorithmGuard,
                        "Test"));

            Assert.True(
                File.Exists(
                    source));

            var records =
                await quarantineRepository.GetAllAsync();

            var record =
                Assert.Single(
                    records);

            Assert.True(
                File.Exists(
                    record.StoredPath));
        }
        finally
        {
            var records =
                await quarantineRepository.GetAllAsync();

            foreach (var record in records)
            {
                if (File.Exists(
                        record.StoredPath))
                {
                    File.SetAttributes(
                        record.StoredPath,
                        FileAttributes.Normal);
                }
            }
        }
    }

    private sealed class ReadOnlyStoredFileAfterDeleteRepository
        : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;
        private readonly string _quarantineDirectory;

        public ReadOnlyStoredFileAfterDeleteRepository(
            IQuarantineRepository inner,
            string quarantineDirectory)
        {
            _inner =
                inner;

            _quarantineDirectory =
                quarantineDirectory;
        }

        public Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            return _inner.AddAsync(
                record,
                cancellationToken);
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public async Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            await _inner.DeleteAsync(
                id,
                cancellationToken);

            var storedPath =
                Directory
                    .EnumerateFiles(
                        _quarantineDirectory,
                        "*.sgq")
                    .Single();

            File.SetAttributes(
                storedPath,
                File.GetAttributes(
                    storedPath) |
                FileAttributes.ReadOnly);
        }
    }

    private sealed class PersistThenThrowQuarantineRepository
        : IQuarantineRepository
    {
        private readonly IQuarantineRepository _inner;

        public PersistThenThrowQuarantineRepository(
            IQuarantineRepository inner)
        {
            _inner =
                inner;
        }

        public async Task AddAsync(
            QuarantineRecord record,
            CancellationToken cancellationToken = default)
        {
            await _inner.AddAsync(
                record,
                cancellationToken);

            throw new InvalidOperationException(
                "Simulated failure after persistence.");
        }

        public Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.GetAllAsync(
                cancellationToken);
        }

        public Task<QuarantineRecord?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.GetByIdAsync(
                id,
                cancellationToken);
        }

        public Task<int> CountAsync(
            CancellationToken cancellationToken = default)
        {
            return _inner.CountAsync(
                cancellationToken);
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return _inner.DeleteAsync(
                id,
                cancellationToken);
        }
    }

    [Fact]
    public async Task Post_persist_failure_does_not_leave_record_without_quarantine_file()
    {
        await using var environment =
            await TestEnvironment.CreateAsync();

        var quarantineRepository =
            new SqliteQuarantineRepository(
                environment.ConnectionFactory);

        var source =
            Path.Combine(
                environment.RootDirectory,
                "post-persist-failure.ps1");

        await File.WriteAllTextAsync(
            source,
            "Write-Host quarantine");

        var manager =
            new QuarantineManager(
                environment.Paths,
                new Sha256FileHashService(),
                new PersistThenThrowQuarantineRepository(
                    quarantineRepository),
                new AuditService(
                    new SqliteSecurityEventRepository(
                        environment.ConnectionFactory)),
                new NoOpFileAccessProtectionService());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                manager.QuarantineAsync(
                    source,
                    SecurityModuleKind.AlgorithmGuard,
                    "Test"));

        Assert.True(
            File.Exists(
                source));

        var records =
            await quarantineRepository.GetAllAsync();

        var record =
            Assert.Single(
                records);

        Assert.True(
            File.Exists(
                record.StoredPath));
    }
}