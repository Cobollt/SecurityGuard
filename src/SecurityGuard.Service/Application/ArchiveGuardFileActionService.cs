using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardFileActionService
    : IArchiveGuardFileActionService
{
    private readonly IQuarantineService _quarantineService;

    public ArchiveGuardFileActionService(
        IQuarantineService quarantineService)
    {
        _quarantineService =
            quarantineService;
    }

    public Task KeepAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fullPath =
            Normalize(
                filePath);

        if (!File.Exists(
                fullPath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                fullPath);
        }

        return Task.CompletedTask;
    }

    public async Task QuarantineAsync(
        string filePath,
        string reason,
        CancellationToken cancellationToken = default)
    {
        var fullPath =
            Normalize(
                filePath);

        if (!File.Exists(
                fullPath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                fullPath);
        }

        await _quarantineService.QuarantineAsync(
            fullPath,
            SecurityModuleKind.ArchiveGuard,
            reason,
            cancellationToken);
    }

    public Task DeleteAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fullPath =
            Normalize(
                filePath);

        if (!File.Exists(
                fullPath))
        {
            return Task.CompletedTask;
        }

        File.Delete(
            fullPath);

        return Task.CompletedTask;
    }

    private static string Normalize(
        string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        return Path.GetFullPath(
            filePath);
    }
}