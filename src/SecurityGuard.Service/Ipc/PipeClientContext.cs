namespace SecurityGuard.Service.Ipc;

public sealed record PipeClientContext(
    string? UserName,
    bool IsAdministrator);