using System.Buffers.Binary;
using System.Text.Json;

namespace SecurityGuard.Core.Ipc;

public static class PipeMessageIO
{
    private static readonly JsonSerializerOptions Options =
        CreateOptions();

    public static async Task WriteAsync<T>(
        Stream stream,
        T message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);

        var payload =
            JsonSerializer.SerializeToUtf8Bytes(
                message,
                Options);

        if (payload.Length >
            PipeProtocol.MaxMessageBytes)
        {
            throw new InvalidOperationException(
                "IPC message is too large.");
        }

        var header =
            new byte[sizeof(int)];

        BinaryPrimitives.WriteInt32LittleEndian(
            header,
            payload.Length);

        await stream.WriteAsync(
            header,
            cancellationToken);

        await stream.WriteAsync(
            payload,
            cancellationToken);

        await stream.FlushAsync(
            cancellationToken);
    }

    public static async Task<T> ReadAsync<T>(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header =
            new byte[sizeof(int)];

        await stream.ReadExactlyAsync(
            header,
            cancellationToken);

        var length =
            BinaryPrimitives.ReadInt32LittleEndian(
                header);

        if (length <= 0 ||
            length > PipeProtocol.MaxMessageBytes)
        {
            throw new InvalidDataException(
                "Invalid IPC message length.");
        }

        var payload =
            new byte[length];

        await stream.ReadExactlyAsync(
            payload,
            cancellationToken);

        var message =
            JsonSerializer.Deserialize<T>(
                payload,
                Options);

        return message ??
               throw new InvalidDataException(
                   $"Unable to deserialize {typeof(T).Name}.");
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options =
            new JsonSerializerOptions(
                JsonSerializerDefaults.Web)
            {
                PropertyNameCaseInsensitive = true
            };

        options.Converters.Add(
            new System.Text.Json.Serialization.JsonStringEnumConverter());

        return options;
    }
}