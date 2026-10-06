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
}