using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityGuard.Core.Ipc;

public static class PipeJsonSerializer
{
    private static readonly JsonSerializerOptions Options =
        CreateOptions();

    public static string Serialize<T>(T value)
    {
        return JsonSerializer.Serialize(
            value,
            Options);
    }

    public static T Deserialize<T>(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        var result =
            JsonSerializer.Deserialize<T>(
                json,
                Options);

        return result ??
               throw new InvalidOperationException(
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
            new JsonStringEnumConverter());

        return options;
    }
}