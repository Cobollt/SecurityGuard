using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Infrastructure.FileSystem;

namespace SecurityGuard.Infrastructure.Quarantine;

public sealed class QuarantineManager
    : IQuarantineService
{
    private readonly SecurityGuardPaths _paths;
    private readonly IFileHashService _hashService;
    private readonly IQuarantineRepository _repository;
    private readonly IAuditService _auditService;
    private readonly IFileAccessProtectionService _protectionService;

    public QuarantineManager(
        SecurityGuardPaths paths,
        IFileHashService hashService,
        IQuarantineRepository repository,
        IAuditService auditService,
        IFileAccessProtectionService protectionService)
    {
        _paths = paths;
        _hashService = hashService;
        _repository = repository;
        _auditService = auditService;
        _protectionService = protectionService;
    }

    public async Task<QuarantineRecord> QuarantineAsync(
        string filePath,
        SecurityModuleKind sourceModule,
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        var sourcePath =
            Path.GetFullPath(filePath);

        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                sourcePath);
        }

        Directory.CreateDirectory(
            _paths.QuarantineDirectory);

        var fileInfo =
            new FileInfo(sourcePath);

        var hash =
            await _hashService.ComputeSha256Async(
                sourcePath,
                cancellationToken);

        var id =
            Guid.NewGuid();

        var storedFileName =
            $"{id:N}.sgq";

        var storedPath =
            Path.Combine(
                _paths.QuarantineDirectory,
                storedFileName);

        var temporaryPath =
            Path.Combine(
                _paths.QuarantineDirectory,
                $"{id:N}.tmp");

        var recordPersisted =
            false;

        try
        {
            File.Copy(
                sourcePath,
                temporaryPath,
                false);

            var copiedHash =
                await _hashService.ComputeSha256Async(
                    temporaryPath,
                    cancellationToken);

            if (!string.Equals(
                    hash,
                    copiedHash,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "Quarantine copy hash validation failed.");
            }

            File.Move(
                temporaryPath,
                storedPath);

            _protectionService.ProtectFile(
                storedPath);

            var record =
                new QuarantineRecord(
                    id,
                    sourcePath,
                    storedPath,
                    fileInfo.Name,
                    hash,
                    fileInfo.Length,
                    sourceModule.ToString(),
                    reason,
                    DateTimeOffset.UtcNow);

            try
            {
                await _repository.AddAsync(
                    record,
                    cancellationToken);

                recordPersisted =
                    true;
            }
            catch
            {
                try
                {
                    recordPersisted =
                        await _repository.GetByIdAsync(
                            record.Id,
                            CancellationToken.None) is not null;
                }
                catch
                {
                    recordPersisted =
                        true;
                }

                throw;
            }

            try
            {
                File.Delete(sourcePath);
            }
            catch (Exception sourceDeleteException)
            {
                await _repository.DeleteAsync(
                    record.Id,
                    CancellationToken.None);

                recordPersisted =
                    false;

                try
                {
                    if (File.Exists(
                            storedPath))
                    {
                        File.Delete(
                            storedPath);
                    }
                }
                catch (Exception storedDeleteException)
                {
                    try
                    {
                        await _repository.AddAsync(
                            record,
                            CancellationToken.None);

                        recordPersisted =
                            true;
                    }
                    catch (Exception repositoryRestoreException)
                    {
                        throw new AggregateException(
                            "Quarantine creation rollback failed.",
                            sourceDeleteException,
                            storedDeleteException,
                            repositoryRestoreException);
                    }

                    throw new AggregateException(
                        "Quarantine file cleanup failed and the quarantine record was restored.",
                        sourceDeleteException,
                        storedDeleteException);
                }

                throw;
            }

            try
            {
                await _auditService.WriteAsync(
                    sourceModule,
                    SecurityEventType.Quarantine,
                    SecuritySeverity.High,
                    "File quarantined",
                    $"{sourcePath} -> {storedPath}",
                    SecurityAction.Quarantine,
                    cancellationToken: cancellationToken);
            }
            catch
            {
            }

            return record;
        }
        catch
        {
            if (File.Exists(temporaryPath))
            {
                try
                {
                    File.Delete(
                        temporaryPath);
                }
                catch
                {
                }
            }

            if (!recordPersisted &&
                File.Exists(
                    storedPath))
            {
                try
                {
                    File.Delete(
                        storedPath);
                }
                catch
                {
                }
            }

            throw;
        }
    }

    public async Task<string> RestoreAsync(
        Guid quarantineId,
        string? destinationPath = null,
        CancellationToken cancellationToken = default)
    {
        var record =
            await _repository.GetByIdAsync(
                quarantineId,
                cancellationToken);

        if (record is null)
        {
            throw new InvalidOperationException(
                $"Quarantine item '{quarantineId}' was not found.");
        }

        if (!File.Exists(record.StoredPath))
        {
            throw new FileNotFoundException(
                "Quarantined file is missing.",
                record.StoredPath);
        }

        var targetPath =
            Path.GetFullPath(
                destinationPath ??
                record.OriginalPath);

        if (File.Exists(targetPath))
        {
            throw new IOException(
                $"Destination file already exists: {targetPath}");
        }

        var targetDirectory =
            Path.GetDirectoryName(targetPath);

        if (string.IsNullOrWhiteSpace(targetDirectory))
        {
            throw new InvalidOperationException(
                "Destination directory could not be determined.");
        }

        Directory.CreateDirectory(
            targetDirectory);

        var temporaryPath =
            Path.Combine(
                targetDirectory,
                $".sg_restore_{Guid.NewGuid():N}.tmp");

        try
        {
            File.Copy(
                record.StoredPath,
                temporaryPath,
                false);

            var restoredHash =
                await _hashService.ComputeSha256Async(
                    temporaryPath,
                    cancellationToken);

            if (!string.Equals(
                    record.Sha256,
                    restoredHash,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "Restored file hash validation failed.");
            }

            File.Move(
                temporaryPath,
                targetPath);

            try
            {
                await _repository.DeleteAsync(
                    record.Id,
                    cancellationToken);
            }
            catch (Exception repositoryDeleteException)
            {
                try
                {
                    var persistedRecord =
                        await _repository.GetByIdAsync(
                            record.Id,
                            CancellationToken.None);

                    if (persistedRecord is null)
                    {
                        await _repository.AddAsync(
                            record,
                            CancellationToken.None);
                    }
                }
                catch (Exception repositoryRollbackException)
                {
                    throw new AggregateException(
                        "Quarantine restore repository rollback failed.",
                        repositoryDeleteException,
                        repositoryRollbackException);
                }

                if (File.Exists(
                        targetPath))
                {
                    try
                    {
                        File.Delete(
                            targetPath);
                    }
                    catch (Exception targetDeleteException)
                    {
                        throw new AggregateException(
                            "Quarantine restore target rollback failed.",
                            repositoryDeleteException,
                            targetDeleteException);
                    }
                }

                throw;
            }

            try
            {
                File.Delete(
                    record.StoredPath);
            }
            catch (Exception storedDeleteException)
            {
                Exception? targetDeleteException =
                    null;

                if (File.Exists(
                        targetPath))
                {
                    try
                    {
                        File.Delete(
                            targetPath);
                    }
                    catch (Exception ex)
                    {
                        targetDeleteException =
                            ex;
                    }
                }

                try
                {
                    await _repository.AddAsync(
                        record,
                        CancellationToken.None);
                }
                catch (Exception repositoryException)
                {
                    if (targetDeleteException is not null)
                    {
                        throw new AggregateException(
                            "Quarantine restore rollback failed.",
                            storedDeleteException,
                            targetDeleteException,
                            repositoryException);
                    }

                    throw new AggregateException(
                        "Quarantine restore rollback failed.",
                        storedDeleteException,
                        repositoryException);
                }

                if (targetDeleteException is not null)
                {
                    throw new AggregateException(
                        "Quarantine restore cleanup failed.",
                        storedDeleteException,
                        targetDeleteException);
                }

                throw;
            }

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.Core,
                    SecurityEventType.Quarantine,
                    SecuritySeverity.Info,
                    "File restored from quarantine",
                    $"{record.StoredPath} -> {targetPath}",
                    SecurityAction.Allow,
                    cancellationToken: cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
            }

            return targetPath;
        }
        catch
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }

            throw;
        }
    }

    public async Task DeleteAsync(
        Guid quarantineId,
        CancellationToken cancellationToken = default)
    {
        var record =
            await _repository.GetByIdAsync(
                quarantineId,
                cancellationToken);

        if (record is null)
        {
            return;
        }

        string? stagedPath =
    null;

        if (File.Exists(
                record.StoredPath))
        {
            stagedPath =
                $"{record.StoredPath}.{Guid.NewGuid():N}.delete";

            File.Move(
                record.StoredPath,
                stagedPath);
        }

        try
        {
            await _repository.DeleteAsync(
                record.Id,
                cancellationToken);
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(
                    stagedPath) &&
                File.Exists(
                    stagedPath) &&
                !File.Exists(
                    record.StoredPath))
            {
                try
                {
                    File.Move(
                        stagedPath,
                        record.StoredPath);
                }
                catch
                {
                }
            }

            throw;
        }

        if (!string.IsNullOrWhiteSpace(
                stagedPath) &&
            File.Exists(
                stagedPath))
        {
            try
            {
                File.Delete(
                    stagedPath);
            }
            catch (Exception deleteException)
            {
                try
                {
                    if (!File.Exists(
                            record.StoredPath) &&
                        File.Exists(
                            stagedPath))
                    {
                        File.Move(
                            stagedPath,
                            record.StoredPath);
                    }

                    if (!File.Exists(
                            record.StoredPath))
                    {
                        throw new IOException(
                            "Failed to restore the quarantined file after delete failure.");
                    }

                    await _repository.AddAsync(
                        record,
                        CancellationToken.None);
                }
                catch (Exception rollbackException)
                {
                    throw new AggregateException(
                        "Quarantine delete failed and rollback could not restore a consistent state.",
                        deleteException,
                        rollbackException);
                }

                throw;
            }
        }

        try
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.Quarantine,
                SecuritySeverity.Info,
                "Quarantined file deleted",
                record.OriginalPath,
                SecurityAction.Delete,
                cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
        }
    }
}