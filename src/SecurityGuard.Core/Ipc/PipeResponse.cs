namespace SecurityGuard.Core.Ipc;

public sealed record PipeResponse(
    bool Success,
    string? Error,
    string? Payload)
{
    public static PipeResponse Ok(string? payload = null)
    {
        return new PipeResponse(
            true,
            null,
            payload);
    }

    public static PipeResponse Fail(string error)
    {
        return new PipeResponse(
            false,
            error,
            null);
    }
}