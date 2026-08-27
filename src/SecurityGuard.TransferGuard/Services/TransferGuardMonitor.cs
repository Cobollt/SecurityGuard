using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardMonitor
    : ITransferGuardMonitor
{
    private readonly IOutboundConnectionEventSource _eventSource;
    private readonly ITransferKernelTelemetrySource _kernelTelemetrySource;
    private readonly TransferObservationService _observationService;
    private readonly TransferCorrelationService _correlationService;
    private readonly TransferPolicyService _policyService;
    private readonly IAuditService _auditService;

    public TransferGuardMonitor(
        IOutboundConnectionEventSource eventSource,
        ITransferKernelTelemetrySource kernelTelemetrySource,
        TransferObservationService observationService,
        TransferCorrelationService correlationService,
        TransferPolicyService policyService,
        IAuditService auditService)
    {
        _eventSource =
            eventSource;

        _kernelTelemetrySource =
            kernelTelemetrySource;

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
        var kernelTask =
            TrackKernelTelemetryAsync(
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
                    await WriteWarningAsync(
                        "TransferGuard connection processing failed",
                        exception.Message);
                }
            }
        }
        finally
        {
            try
            {
                await kernelTask;
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private async Task TrackKernelTelemetryAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await foreach (
                var activity in
                _kernelTelemetrySource.WatchAsync(
                    cancellationToken))
            {
                switch (activity)
                {
                    case FileReadKernelActivity fileRead:
                        await _correlationService.HandleFileReadAsync(
                            fileRead.Activity,
                            cancellationToken);

                        break;

                    case NetworkSendKernelActivity networkSend:
                        await _correlationService.HandleNetworkSendAsync(
                            networkSend.Activity,
                            cancellationToken);

                        break;
                }
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            await WriteWarningAsync(
                "TransferGuard kernel telemetry unavailable",
                exception.Message);
        }
    }

    private Task WriteWarningAsync(
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