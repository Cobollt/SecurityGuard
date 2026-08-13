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

            await _repository.AddAsync(
                record,
                cancellationToken);

            try
            {
                File.Delete(sourcePath);
            }
            catch
            {
                await _repository.DeleteAsync(
                    record.Id,
                    cancellationToken);

                if (File.Exists(storedPath))
                {
                    File.Delete(storedPath);
                }

                throw;
            }

            await _auditService.WriteAsync(
                sourceModule,
                SecurityEventType.Quarantine,
                SecuritySeverity.High,
                "File quarantined",
                $"{sourcePath} -> {storedPath}",
                SecurityAction.Quarantine,
                cancellationToken: cancellationToken);

            return record;
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

            await _repository.DeleteAsync(
                record.Id,
                cancellationToken);

            try
            {
                File.Delete(
                    record.StoredPath);
            }
            catch
            {
                if (File.Exists(targetPath))
                {
                    File.Delete(targetPath);
                }

                await _repository.AddAsync(
                    record,
                    cancellationToken);

                throw;
            }

            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.Quarantine,
                SecuritySeverity.Info,
                "File restored from quarantine",
                $"{record.StoredPath} -> {targetPath}",
                SecurityAction.Allow,
                cancellationToken: cancellationToken);

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

        if (File.Exists(record.StoredPath))
        {
            File.Delete(record.StoredPath);
        }

        await _repository.DeleteAsync(
            record.Id,
            cancellationToken);

        await _auditService.WriteAsync(
            SecurityModuleKind.Core,
            SecurityEventType.Quarantine,
            SecuritySeverity.Info,
            "Quarantined file deleted",
            record.OriginalPath,
            SecurityAction.Delete,
            cancellationToken: cancellationToken);
    }
}