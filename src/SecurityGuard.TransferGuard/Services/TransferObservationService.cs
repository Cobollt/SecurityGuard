using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferObservationService
{
    private readonly ITransferProcessResolver _processResolver;
    private readonly IAuditService _auditService;

    public TransferObservationService(
        ITransferProcessResolver processResolver,
        IAuditService auditService)
    {
        _processResolver =
            processResolver;

        _auditService =
            auditService;
    }

    public async Task<NetworkConnectionObservation> HandleAsync(
        TcpConnectionSnapshot connection,
        CancellationToken cancellationToken = default)
    {
        var process =
            await _processResolver.GetAsync(
                connection.ProcessId,
                cancellationToken);

        var observation =
            new NetworkConnectionObservation(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                TransferProtocol.Tcp,
                connection.AddressFamily,
                connection.LocalAddress,
                connection.LocalPort,
                connection.RemoteAddress,
                connection.RemotePort,
                connection.State,
                process);

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            SecuritySeverity.Info,
            "Network connection detected",
            BuildDetails(
                observation),
            SecurityAction.None,
            cancellationToken:
                cancellationToken);

        return observation;
    }

    private static string BuildDetails(
        NetworkConnectionObservation observation)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Protocol: {observation.Protocol}",
                $"Address family: {observation.AddressFamily}",
                $"PID: {observation.Process?.ProcessId.ToString() ?? "Unknown"}",
                $"Process: {observation.Process?.ProcessName ?? "Unknown"}",
                $"Executable: {observation.Process?.ExecutablePath ?? "Unknown"}",
                $"Local: {observation.LocalAddress}:{observation.LocalPort}",
                $"Remote: {observation.RemoteAddress}:{observation.RemotePort}",
                $"TCP state: {observation.TcpState}"
            });
    }
}