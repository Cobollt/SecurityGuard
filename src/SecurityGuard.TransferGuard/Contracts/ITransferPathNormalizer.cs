namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferPathNormalizer
{
    string? Normalize(
        string? path);
}