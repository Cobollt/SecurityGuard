namespace SecurityGuard.Core.Ipc;

public sealed record PipeRequest(
    string Type,
    string? Payload = null);