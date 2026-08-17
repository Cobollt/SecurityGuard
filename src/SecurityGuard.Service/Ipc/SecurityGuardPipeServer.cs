using System.IO.Pipes;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Service.Ipc;

public sealed class SecurityGuardPipeServer
    : BackgroundService
{
    private readonly PipeRequestHandler _requestHandler;
    private readonly ILogger<SecurityGuardPipeServer> _logger;

    public SecurityGuardPipeServer(
        PipeRequestHandler requestHandler,
        ILogger<SecurityGuardPipeServer> logger)
    {
        _requestHandler = requestHandler;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessConnectionAsync(
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(
                    exception,
                    "Named Pipe server failure");

                await Task.Delay(
                    TimeSpan.FromSeconds(1),
                    stoppingToken);
            }
        }
    }

    private async Task ProcessConnectionAsync(
        CancellationToken cancellationToken)
    {
        await using var pipe =
            new NamedPipeServerStream(
                PipeProtocol.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

        await pipe.WaitForConnectionAsync(
            cancellationToken);

        try
        {
            var request =
                await PipeMessageIO.ReadAsync<PipeRequest>(
                    pipe,
                    cancellationToken);

            var response =
                await _requestHandler.HandleAsync(
                    request,
                    cancellationToken);

            await PipeMessageIO.WriteAsync(
                pipe,
                response,
                cancellationToken);
        }
        catch (EndOfStreamException)
        {
            _logger.LogWarning(
                "IPC client disconnected before completing request");
        }
        catch (InvalidDataException exception)
        {
            _logger.LogWarning(
                exception,
                "Invalid IPC message received");
        }
    }
}