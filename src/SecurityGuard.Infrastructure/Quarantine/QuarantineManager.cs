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
                try
                {
                    await _repository.DeleteAsync(
                        record.Id,
                        CancellationToken.None);

                    recordPersisted =
                        false;
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

                        recordPersisted =
                            true;
                    }
                    catch (Exception repositoryRollbackException)
                    {
                        recordPersisted =
                            true;

                        throw new AggregateException(
                            "Quarantine creation repository rollback failed.",
                            sourceDeleteException,
                            repositoryDeleteException,
                            repositoryRollbackException);
                    }

                    throw;
                }

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
                    var attributes =
                        File.GetAttributes(
                            temporaryPath);

                    if ((attributes &
                         FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(
                            temporaryPath,
                            attributes &
                            ~FileAttributes.ReadOnly);
                    }

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
                    var attributes =
                        File.GetAttributes(
                            storedPath);

                    if ((attributes &
                         FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(
                            storedPath,
                            attributes &
                            ~FileAttributes.ReadOnly);
                    }

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
                Exception? repositoryRestoreException =
                    null;

                var repositoryRestored =
                    false;

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

                    repositoryRestored =
                        true;
                }
                catch (Exception ex)
                {
                    repositoryRestoreException =
                        ex;

                    try
                    {
                        repositoryRestored =
                            await _repository.GetByIdAsync(
                                record.Id,
                                CancellationToken.None) is not null;
                    }
                    catch (Exception repositoryLookupException)
                    {
                        throw new AggregateException(
                            "Quarantine restore rollback state could not be determined.",
                            repositoryDeleteException,
                            repositoryRestoreException,
                            repositoryLookupException);
                    }
                }

                if (!repositoryRestored)
                {
                    try
                    {
                        if (File.Exists(
                                record.StoredPath))
                        {
                            var attributes =
                                File.GetAttributes(
                                    record.StoredPath);

                            if ((attributes &
                                 FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(
                                    record.StoredPath,
                                    attributes &
                                    ~FileAttributes.ReadOnly);
                            }

                            File.Delete(
                                record.StoredPath);
                        }
                    }
                    catch (Exception storedCleanupException)
                    {
                        throw new AggregateException(
                            "Quarantine restore repository rollback failed and the orphaned quarantine file could not be removed.",
                            repositoryDeleteException,
                            repositoryRestoreException!,
                            storedCleanupException);
                    }

                    throw new AggregateException(
                        "Quarantine restore repository rollback failed; restored target was preserved.",
                        repositoryDeleteException,
                        repositoryRestoreException!);
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
                        if (repositoryRestoreException is not null)
                        {
                            throw new AggregateException(
                                "Quarantine restore rollback failed.",
                                repositoryDeleteException,
                                repositoryRestoreException,
                                targetDeleteException);
                        }

                        throw new AggregateException(
                            "Quarantine restore target rollback failed.",
                            repositoryDeleteException,
                            targetDeleteException);
                    }
                }

                if (repositoryRestoreException is not null)
                {
                    throw new AggregateException(
                        "Quarantine restore rollback persistence reported a failure after the record was restored.",
                        repositoryDeleteException,
                        repositoryRestoreException);
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
                Exception? repositoryRestoreException =
                    null;

                var repositoryRestored =
                    false;

                try
                {
                    await _repository.AddAsync(
                        record,
                        CancellationToken.None);

                    repositoryRestored =
                        true;
                }
                catch (Exception ex)
                {
                    repositoryRestoreException =
                        ex;

                    try
                    {
                        repositoryRestored =
                            await _repository.GetByIdAsync(
                                record.Id,
                                CancellationToken.None) is not null;
                    }
                    catch (Exception repositoryLookupException)
                    {
                        throw new AggregateException(
                            "Quarantine restore rollback state could not be determined.",
                            storedDeleteException,
                            repositoryRestoreException,
                            repositoryLookupException);
                    }
                }

                if (!repositoryRestored)
                {
                    try
                    {
                        if (File.Exists(
                                record.StoredPath))
                        {
                            var attributes =
                                File.GetAttributes(
                                    record.StoredPath);

                            if ((attributes &
                                 FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(
                                    record.StoredPath,
                                    attributes &
                                    ~FileAttributes.ReadOnly);
                            }

                            File.Delete(
                                record.StoredPath);
                        }
                    }
                    catch (Exception storedCleanupException)
                    {
                        throw new AggregateException(
                            "Quarantine restore rollback failed and the orphaned quarantine file could not be removed.",
                            storedDeleteException,
                            repositoryRestoreException!,
                            storedCleanupException);
                    }

                    throw new AggregateException(
                        "Quarantine restore repository rollback failed; restored target was preserved.",
                        storedDeleteException,
                        repositoryRestoreException!);
                }

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

                if (targetDeleteException is not null)
                {
                    if (repositoryRestoreException is not null)
                    {
                        throw new AggregateException(
                            "Quarantine restore rollback failed.",
                            storedDeleteException,
                            repositoryRestoreException,
                            targetDeleteException);
                    }

                    throw new AggregateException(
                        "Quarantine restore cleanup failed.",
                        storedDeleteException,
                        targetDeleteException);
                }

                if (repositoryRestoreException is not null)
                {
                    throw new AggregateException(
                        "Quarantine restore rollback persistence reported a failure after the record was restored.",
                        storedDeleteException,
                        repositoryRestoreException);
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
            if (File.Exists(
                    temporaryPath))
            {
                try
                {
                    var attributes =
                        File.GetAttributes(
                            temporaryPath);

                    if ((attributes &
                         FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(
                            temporaryPath,
                            attributes &
                            ~FileAttributes.ReadOnly);
                    }

                    File.Delete(
                        temporaryPath);
                }
                catch
                {
                }
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
        catch (Exception repositoryDeleteException)
        {
            Exception? fileRollbackException =
                null;

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
                catch (Exception ex)
                {
                    fileRollbackException =
                        ex;
                }
            }

            if (fileRollbackException is not null)
            {
                QuarantineRecord? persistedRecord;

                try
                {
                    persistedRecord =
                        await _repository.GetByIdAsync(
                            record.Id,
                            CancellationToken.None);
                }
                catch (Exception repositoryStateException)
                {
                    throw new AggregateException(
                        "Quarantine delete rollback state could not be determined.",
                        repositoryDeleteException,
                        fileRollbackException,
                        repositoryStateException);
                }

                if (persistedRecord is null)
                {
                    try
                    {
                        if (!string.IsNullOrWhiteSpace(
                                stagedPath) &&
                            File.Exists(
                                stagedPath))
                        {
                            var stagedAttributes =
                                File.GetAttributes(
                                    stagedPath);

                            if ((stagedAttributes &
                                 FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(
                                    stagedPath,
                                    stagedAttributes &
                                    ~FileAttributes.ReadOnly);
                            }

                            File.Delete(
                                stagedPath);
                        }
                    }
                    catch (Exception stagedCleanupException)
                    {
                        throw new AggregateException(
                            "Quarantine delete file rollback failed and the staged file could not be cleaned up.",
                            repositoryDeleteException,
                            fileRollbackException,
                            stagedCleanupException);
                    }

                    throw new AggregateException(
                        "Quarantine delete file rollback failed after the repository record was removed.",
                        repositoryDeleteException,
                        fileRollbackException);
                }
            }

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
                QuarantineRecord? persistedRecord;

                try
                {
                    persistedRecord =
                        await _repository.GetByIdAsync(
                            record.Id,
                            CancellationToken.None);
                }
                catch (Exception repositoryStateException)
                {
                    if (fileRollbackException is not null)
                    {
                        throw new AggregateException(
                            "Quarantine delete rollback state could not be determined.",
                            repositoryDeleteException,
                            fileRollbackException,
                            repositoryRollbackException,
                            repositoryStateException);
                    }

                    throw new AggregateException(
                        "Quarantine delete rollback state could not be determined.",
                        repositoryDeleteException,
                        repositoryRollbackException,
                        repositoryStateException);
                }

                if (persistedRecord is null)
                {
                    try
                    {
                        if (File.Exists(
                                record.StoredPath))
                        {
                            var attributes =
                                File.GetAttributes(
                                    record.StoredPath);

                            if ((attributes &
                                 FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(
                                    record.StoredPath,
                                    attributes &
                                    ~FileAttributes.ReadOnly);
                            }

                            File.Delete(
                                record.StoredPath);
                        }

                        if (!string.IsNullOrWhiteSpace(
                                stagedPath) &&
                            File.Exists(
                                stagedPath))
                        {
                            var stagedAttributes =
                                File.GetAttributes(
                                    stagedPath);

                            if ((stagedAttributes &
                                 FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(
                                    stagedPath,
                                    stagedAttributes &
                                    ~FileAttributes.ReadOnly);
                            }

                            File.Delete(
                                stagedPath);
                        }
                    }
                    catch (Exception cleanupException)
                    {
                        if (fileRollbackException is not null)
                        {
                            throw new AggregateException(
                                "Quarantine delete rollback cleanup failed.",
                                repositoryDeleteException,
                                fileRollbackException,
                                repositoryRollbackException,
                                cleanupException);
                        }

                        throw new AggregateException(
                            "Quarantine delete repository rollback cleanup failed.",
                            repositoryDeleteException,
                            repositoryRollbackException,
                            cleanupException);
                    }
                }

                if (fileRollbackException is not null)
                {
                    throw new AggregateException(
                        "Quarantine delete rollback failed.",
                        repositoryDeleteException,
                        fileRollbackException,
                        repositoryRollbackException);
                }

                throw new AggregateException(
                    "Quarantine delete repository rollback failed.",
                    repositoryDeleteException,
                    repositoryRollbackException);
            }

            if (fileRollbackException is not null)
            {
                throw new AggregateException(
                    "Quarantine delete file rollback failed.",
                    repositoryDeleteException,
                    fileRollbackException);
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
                    try
                    {
                        var persistedRecord =
                            await _repository.GetByIdAsync(
                                record.Id,
                                CancellationToken.None);

                        if (persistedRecord is null)
                        {
                            if (File.Exists(
                                    record.StoredPath))
                            {
                                var attributes =
                                    File.GetAttributes(
                                        record.StoredPath);

                                if ((attributes &
                                     FileAttributes.ReadOnly) != 0)
                                {
                                    File.SetAttributes(
                                        record.StoredPath,
                                        attributes &
                                        ~FileAttributes.ReadOnly);
                                }

                                File.Delete(
                                    record.StoredPath);
                            }

                            if (!string.IsNullOrWhiteSpace(
                                    stagedPath) &&
                                File.Exists(
                                    stagedPath))
                            {
                                var stagedAttributes =
                                    File.GetAttributes(
                                        stagedPath);

                                if ((stagedAttributes &
                                     FileAttributes.ReadOnly) != 0)
                                {
                                    File.SetAttributes(
                                        stagedPath,
                                        stagedAttributes &
                                        ~FileAttributes.ReadOnly);
                                }

                                File.Delete(
                                    stagedPath);
                            }
                        }
                    }
                    catch (Exception cleanupException)
                    {
                        throw new AggregateException(
                            "Quarantine delete failed and rollback cleanup could not restore a consistent state.",
                            deleteException,
                            rollbackException,
                            cleanupException);
                    }

                    throw new AggregateException(
                        "Quarantine delete failed and repository rollback did not complete.",
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