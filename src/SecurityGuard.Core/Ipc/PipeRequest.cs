namespace SecurityGuard.Core.Ipc;

public sealed record PipeRequest(
    Guid Id,
    PipeMessageType Type,
    string? Payload = null)
{
    public static PipeRequest Create(
        PipeMessageType type,
        string? payload = null)
    {
        return new PipeRequest(
            Guid.NewGuid(),
            type,
            payload);
    }
}