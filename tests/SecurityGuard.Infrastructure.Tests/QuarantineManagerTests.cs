using SecurityGuard.Core.Enums;
using SecurityGuard.Infrastructure.Audit;
using SecurityGuard.Infrastructure.Hashing;
using SecurityGuard.Infrastructure.Quarantine;
using SecurityGuard.Storage.Repositories;

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
}