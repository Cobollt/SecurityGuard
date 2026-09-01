using System.Runtime.ExceptionServices;
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
    private readonly ITransferCorrelationState _correlationState;
    private readonly ITransferTelemetryHealthTracker _healthTracker;

    public TransferGuardMonitor(
        IOutboundConnectionEventSource eventSource,
        ITransferKernelTelemetrySource kernelTelemetrySource,
        TransferObservationService observationService,
        TransferCorrelationService correlationService,
        TransferPolicyService policyService,
        ITransferCorrelationState correlationState,
        ITransferTelemetryHealthTracker healthTracker,
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
        
        _correlationState =
            correlationState;
        
        _healthTracker =
            healthTracker;

        _auditService =
            auditService;
    }

    public async Task RunAsync(
        CancellationToken cancellationToken = default)
    {
        using var linkedCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);

        var connectionTask =
            TrackConnectionsAsync(
                linkedCancellation.Token);

        var kernelTask =
            TrackKernelTelemetryAsync(
                linkedCancellation.Token);

        var completed =
            await Task.WhenAny(
                connectionTask,
                kernelTask);

        if (cancellationToken.IsCancellationRequested)
        {
            await linkedCancellation.CancelAsync();

            await IgnoreCancellationAsync(
                connectionTask);

            await IgnoreCancellationAsync(
                kernelTask);

            return;
        }

        Exception? failure =
            null;

        try
        {
            await completed;
        }
        catch (Exception exception)
        {
            failure =
                exception;
        }

        await linkedCancellation.CancelAsync();

        var other =
            ReferenceEquals(
                completed,
                connectionTask)
                ? kernelTask
                : connectionTask;

        try
        {
            await other;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            failure ??=
                exception;
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo
                .Capture(
                    failure)
                .Throw();
        }

        throw new InvalidOperationException(
            "TransferGuard monitoring source stopped unexpectedly.");
    }

    private async Task TrackConnectionsAsync(
        CancellationToken cancellationToken)
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
                return;
            }
            catch (TransferFileEnforcementException)
            {
                throw;
            }
            catch (Exception exception)
            {
                _healthTracker.RecordCorrelationFailure();

                await WriteWarningAsync(
                    "TransferGuard kernel activity processing failed",
                    exception.Message);
            }
        }
    }

    private async Task TrackKernelTelemetryAsync(
        CancellationToken cancellationToken)
    {
        await foreach (
            var activity in
            _kernelTelemetrySource.WatchAsync(
                cancellationToken))
        {
            try
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

                    case ProcessStartedKernelActivity processStarted:
                        _correlationState.ResetProcess(
                            processStarted.ProcessInstance);

                        break;

                    case ProcessStoppedKernelActivity processStopped:
                        _correlationState.RemoveProcess(
                            processStopped.ProcessInstance);

                        break;
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (TransferFileEnforcementException)
            {
                throw;
            }
            catch (Exception exception)
            {
                _healthTracker.RecordCorrelationFailure();

                await WriteWarningAsync(
                    "TransferGuard kernel activity processing failed",
                    exception.Message);
            }
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

    private static async Task IgnoreCancellationAsync(
        Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }
}