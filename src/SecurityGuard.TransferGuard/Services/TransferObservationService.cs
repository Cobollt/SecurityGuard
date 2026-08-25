using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferObservationService
{
    private readonly ITransferProcessResolver _processResolver;

    public TransferObservationService(
        ITransferProcessResolver processResolver)
    {
        _processResolver =
            processResolver;
    }

    public async Task<NetworkConnectionObservation> EnrichAsync(
        FilteringPlatformConnectionEvent connection,
        CancellationToken cancellationToken = default)
    {
        var process =
            await _processResolver.GetAsync(
                connection.ProcessId,
                cancellationToken);

        if (process is null)
        {
            process =
                CreateFallbackProcess(
                    connection);
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
            connection.ApplicationPath);
    }

    private static ProcessInfo? CreateFallbackProcess(
        FilteringPlatformConnectionEvent connection)
    {
        if (string.IsNullOrWhiteSpace(
                connection.ApplicationPath))
        {
            return null;
        }

        var name =
            Path.GetFileName(
                connection.ApplicationPath);

        return new ProcessInfo(
            connection.ProcessId,
            null,
            name,
            connection.ApplicationPath,
            null,
            null,
            null);
    }
}