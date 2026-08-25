using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Service.Ipc;

public sealed class SecurityGuardPipeServer
    : BackgroundService
{
    private readonly PipeRequestHandler _requestHandler;
    private readonly SecurityGuardPipeFactory _pipeFactory;
    private readonly PipeClientContextFactory _clientContextFactory;
    private readonly PipeAuthorizationService _authorizationService;

    public SecurityGuardPipeServer(
        PipeRequestHandler requestHandler,
        SecurityGuardPipeFactory pipeFactory,
        PipeClientContextFactory clientContextFactory,
        PipeAuthorizationService authorizationService)
    {
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
        while (!stoppingToken.IsCancellationRequested)
        {
            var pipe =
                _pipeFactory.Create();

            try
            {
                await pipe.WaitForConnectionAsync(
                    stoppingToken);
            }
            catch
            {
                await pipe.DisposeAsync();
                throw;
            }

            _ =
                HandleClientAsync(
                    pipe,
                    stoppingToken);
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
                var request =
                    await PipeMessageIO.ReadAsync<PipeRequest>(
                        pipe,
                        cancellationToken);

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

                await PipeMessageIO.WriteAsync(
                    pipe,
                    response,
                    cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
            }
            catch
            {
            }
        }
    }
}