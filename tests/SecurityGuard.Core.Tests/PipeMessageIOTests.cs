using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Core.Tests;

public sealed class PipeMessageIOTests
{
    [Fact]
    public async Task Message_can_be_written_and_read()
    {
        await using var stream =
            new MemoryStream();

        var request =
            PipeRequest.Create(
                PipeMessageType.Ping);

        await PipeMessageIO.WriteAsync(
            stream,
            request);

        stream.Position = 0;

        var restored =
            await PipeMessageIO.ReadAsync<PipeRequest>(
                stream);

        Assert.Equal(
            request.Id,
            restored.Id);

        Assert.Equal(
            PipeMessageType.Ping,
            restored.Type);
    }

    [Fact]
    public async Task Invalid_message_length_is_rejected()
    {
        await using var stream =
            new MemoryStream();

        var invalidLength =
            BitConverter.GetBytes(
                PipeProtocol.MaxMessageBytes + 1);

        await stream.WriteAsync(
            invalidLength);

        stream.Position = 0;

        await Assert.ThrowsAsync<InvalidDataException>(
            async () =>
                await PipeMessageIO.ReadAsync<PipeRequest>(
                    stream));
    }
}