using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferObservationService
{
    private readonly ITransferProcessResolver _processResolver;
    private readonly ITransferPathNormalizer _pathNormalizer;

    public TransferObservationService(
        ITransferProcessResolver processResolver,
        ITransferPathNormalizer pathNormalizer)
    {
        _processResolver =
            processResolver;

        _pathNormalizer =
            pathNormalizer;
    }

    public async Task<NetworkConnectionObservation> EnrichAsync(
        FilteringPlatformConnectionEvent connection,
        CancellationToken cancellationToken = default)
    {
        var process =
            await _processResolver.GetAsync(
                connection.ProcessId,
                cancellationToken);

        var applicationPath =
            _pathNormalizer.Normalize(
                connection.ApplicationPath);

        if (process is not null)
        {
            var executablePath =
                _pathNormalizer.Normalize(
                    process.ExecutablePath);

            process =
                process with
                {
                    ExecutablePath =
                        executablePath ??
                        process.ExecutablePath
                };
        }

        if (process is null)
        {
            process =
                CreateFallbackProcess(
                    connection,
                    applicationPath);
        }

        return new NetworkConnectionObservation(
            Guid.NewGuid(),
            connection.DetectedAtUtc,
            connection.Protocol,
            connection.AddressFamily,
            connection.LocalAddress,
            connection.LocalPort,
            connection.RemoteAddress,
            connection.RemotePort,
            process,
            applicationPath);
    }

    private static ProcessInfo? CreateFallbackProcess(
        FilteringPlatformConnectionEvent connection,
        string? applicationPath)
    {
        if (string.IsNullOrWhiteSpace(
                applicationPath))
        {
            return null;
        }

        return new ProcessInfo(
            connection.ProcessId,
            null,
            Path.GetFileName(
                applicationPath),
            applicationPath,
            null,
            null,
            null);
    }
}