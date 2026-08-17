namespace SecurityGuard.Core.Ipc;

public enum PipeMessageType
{
    Ping = 0,
    GetSnapshot = 1,
    SubmitDecision = 2
}