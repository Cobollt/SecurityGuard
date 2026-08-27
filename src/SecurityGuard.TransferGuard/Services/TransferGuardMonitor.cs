using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardMonitor
    : ITransferGuardMonitor
{
    private readonly IOutboundConnectionEventSource _eventSource;
    private readonly IFileReadActivitySource _fileReadSource;
    private readonly TransferObservationService _observationService;
    private readonly TransferCorrelationService _correlationService;
    private readonly TransferPolicyService _policyService;
    private readonly IAuditService _auditService;

    public TransferGuardMonitor(
        IOutboundConnectionEventSource eventSource,
        IFileReadActivitySource fileReadSource,
        TransferObservationService observationService,
        TransferCorrelationService correlationService,
        TransferPolicyService policyService,
        IAuditService auditService)
    {
        _eventSource =
            eventSource;

        _fileReadSource =
            fileReadSource;

        _observationService =
            observationService;

        _correlationService =
            correlationService;

        _policyService =
            policyService;

        _auditService =
            auditService;
    }

    public async Task RunAsync(
        CancellationToken cancellationToken = default)
    {
        var fileReadTask =
            TrackFileReadsAsync(
                cancellationToken);

        try
        {
            await foreach (
                var connection in
                _eventSource.WatchAsync(
                    cancellationToken))
            {
                try
                {
                    var observation =
                        await _observationService.EnrichAsync(
                            connection,
                            cancellationToken);

                    await _correlationService.HandleConnectionAsync(
                        observation,
                        cancellationToken);

                    await _policyService.HandleAsync(
                        observation,
                        cancellationToken);
                }
                catch (OperationCanceledException)
                    when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception)
                {
                    await WriteMonitorWarningAsync(
                        "TransferGuard connection processing failed",
                        exception.Message);
                }
            }
        }
        finally
        {
            try
            {
                await fileReadTask;
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private async Task TrackFileReadsAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await foreach (
                var activity in
                _fileReadSource.WatchAsync(
                    cancellationToken))
            {
                await _correlationService.HandleFileReadAsync(
                    activity,
                    cancellationToken);
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            await WriteMonitorWarningAsync(
                "TransferGuard file correlation unavailable",
                exception.Message);
        }
    }

    private Task WriteMonitorWarningAsync(
        string title,
        string details)
    {
        return _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.System,
            SecuritySeverity.Medium,
            title,
            details,
            cancellationToken:
                CancellationToken.None);
    }
}