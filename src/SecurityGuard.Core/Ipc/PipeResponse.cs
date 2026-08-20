namespace SecurityGuard.Core.Ipc;

public sealed record PipeResponse(
    Guid RequestId,
    bool Success,
    string? Error,
    string? Payload)
{
    public static PipeResponse Ok(
        Guid requestId,
        string? payload = null)
    {
        return new PipeResponse(
            requestId,
            true,
            null,
            payload);
    }

    public static PipeResponse Fail(
        Guid requestId,
        string error)
    {
        return new PipeResponse(
            requestId,
            false,
            error,
            null);
    }
}