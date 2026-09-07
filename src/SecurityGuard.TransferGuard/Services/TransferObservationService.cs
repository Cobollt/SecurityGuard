using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferObservationService
{
    private readonly ITransferProcessResolver _processResolver;
    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly ITransferProcessInstanceRegistry _processRegistry;

    public TransferObservationService(
        ITransferProcessResolver processResolver,
        ITransferPathNormalizer pathNormalizer,
        ITransferProcessInstanceRegistry processRegistry)
    {
        _processResolver =
            processResolver;

        _pathNormalizer =
            pathNormalizer;

        _processRegistry =
            processRegistry;
    }

    public async Task<NetworkConnectionObservation> EnrichAsync(
        FilteringPlatformConnectionEvent connection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            connection);

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

        var processInstance =
            _processRegistry.Resolve(
                connection.ProcessId);

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
            applicationPath,
            processInstance);
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

        var processName =
            Path.GetFileNameWithoutExtension(
                applicationPath);

        if (string.IsNullOrWhiteSpace(
                processName))
        {
            processName =
                $"PID-{connection.ProcessId}";
        }

        return new ProcessInfo(
            connection.ProcessId,
            null,
            processName,
            applicationPath,
            null,
            null,
            null);
    }
}