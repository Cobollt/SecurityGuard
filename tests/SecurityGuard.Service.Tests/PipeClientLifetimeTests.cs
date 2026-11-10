using System.IO.Pipes;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using SecurityGuard.Service.Ipc;

namespace SecurityGuard.Service.Tests;

public sealed class PipeClientLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Incomplete_request_disconnects_on_deadline_or_service_shutdown(bool shutdown)
    {
        var name = "SecurityGuard-Test-" + Guid.NewGuid().ToString("N");
        await using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = pipe.WaitForConnectionAsync();
        using var testDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.ConnectAsync(testDeadline.Token);
        await connected.WaitAsync(testDeadline.Token);
        using var stopping = new CancellationTokenSource();
        using var server = new SecurityGuardPipeServer(null!, null!, null!, new PipeAuthorizationService(),
            NullLogger<SecurityGuardPipeServer>.Instance);
        var handling = (Task)typeof(SecurityGuardPipeServer)
            .GetMethod("HandleClientAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(server, [pipe, stopping.Token])!;
        // On Windows, an unbuffered pipe write needs an active reader.
        // Declare a payload, but send only part of its body.
        await client.WriteAsync(new byte[] { 20, 0, 0, 0, (byte)'{' }, testDeadline.Token);
        await client.FlushAsync(testDeadline.Token);
        if (shutdown) await stopping.CancelAsync();
        await handling.WaitAsync(testDeadline.Token);
        try
        {
            Assert.Equal(0, await client.ReadAsync(new byte[1], testDeadline.Token));
        }
        catch (IOException)
        {
            // Windows may report a broken pipe instead of EOF after disconnect.
        }
        Assert.False(testDeadline.IsCancellationRequested);
    }
}
