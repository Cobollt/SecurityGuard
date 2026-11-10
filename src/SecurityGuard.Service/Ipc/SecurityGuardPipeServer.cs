using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityGuard.Core.Ipc;
using System.IO.Pipes;

namespace SecurityGuard.Service.Ipc;

public sealed class SecurityGuardPipeServer
    : BackgroundService
{
    private const int MaxConcurrentClients = 32;
    private static readonly TimeSpan ClientIoTimeout = TimeSpan.FromSeconds(10);
    private readonly ILogger<SecurityGuardPipeServer> _logger;
    private readonly SemaphoreSlim _clientSlots = new(MaxConcurrentClients);
    private readonly PipeRequestHandler _requestHandler;
    private readonly SecurityGuardPipeFactory _pipeFactory;
    private readonly PipeClientContextFactory _clientContextFactory;
    private readonly PipeAuthorizationService _authorizationService;

    public SecurityGuardPipeServer(
        PipeRequestHandler requestHandler,
        SecurityGuardPipeFactory pipeFactory,
        PipeClientContextFactory clientContextFactory,
        PipeAuthorizationService authorizationService,
        ILogger<SecurityGuardPipeServer> logger)
    {
        _logger = logger;

        _requestHandler =
            requestHandler;

        _pipeFactory =
            pipeFactory;

        _clientContextFactory =
            clientContextFactory;

        _authorizationService =
            authorizationService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        using var clientsCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var clients = new List<Task>();

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await _clientSlots.WaitAsync(stoppingToken);
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = _pipeFactory.Create();
                    await pipe.WaitForConnectionAsync(stoppingToken);
                    clients.RemoveAll(task => task.IsCompleted);
                    clients.Add(HandleAndReleaseAsync(pipe, clientsCancellation.Token));
                }
                catch
                {
                    if (pipe is not null)
                    {
                        await pipe.DisposeAsync();
                    }
                    _clientSlots.Release();
                    throw;
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            await clientsCancellation.CancelAsync();
            await Task.WhenAll(clients);
        }
    }

    private async Task HandleAndReleaseAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        try
        {
            await HandleClientAsync(pipe, cancellationToken);
        }
        finally
        {
            _clientSlots.Release();
        }
    }

    private async Task HandleClientAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        await using (pipe)
        {
            try
            {
                PipeRequest request;
                using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    readTimeout.CancelAfter(ClientIoTimeout);
                    request = await PipeMessageIO.ReadAsync<PipeRequest>(pipe, readTimeout.Token);
                }

                var context =
                    _clientContextFactory.Create(
                        pipe);

                PipeResponse response;

                if (!_authorizationService.IsAuthorized(
                        request.Type,
                        context))
                {
                    response =
                        PipeResponse.Fail(
                            request.Id,
                            "Administrator privileges are required for this operation.");
                }
                else
                {
                    response =
                        await _requestHandler.HandleAsync(
                            request,
                            cancellationToken);
                }

                // A long scan may be legitimate; bound transport I/O separately.
                using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                writeTimeout.CancelAfter(ClientIoTimeout);
                await PipeMessageIO.WriteAsync(pipe, response, writeTimeout.Token);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("IPC client exceeded its I/O deadline.");
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "IPC client request failed.");
            }
        }
    }
}