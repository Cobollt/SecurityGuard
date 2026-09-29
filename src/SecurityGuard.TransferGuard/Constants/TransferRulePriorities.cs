namespace SecurityGuard.TransferGuard.Constants;

public static class TransferRulePriorities
{
    public const int NetworkAllow = 100;
    public const int FileTransferAllow = 150;
    public const int NetworkBlock = 200;
    public const int FileTransferBlock = 250;
}