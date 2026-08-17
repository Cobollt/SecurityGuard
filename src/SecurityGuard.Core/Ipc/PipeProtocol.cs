namespace SecurityGuard.Core.Ipc;

public static class PipeProtocol
{
    public const string PipeName =
        "SecurityGuard.Local";

    public const int MaxMessageBytes =
        1024 * 1024;

    public const int ProtocolVersion =
        1;
}