namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferFileEnforcementException
    : Exception
{
    public TransferFileEnforcementException(
        string message)
        : base(
            message)
    {
    }

    public TransferFileEnforcementException(
        string message,
        Exception innerException)
        : base(
            message,
            innerException)
    {
    }
}