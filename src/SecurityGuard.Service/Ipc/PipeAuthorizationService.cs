using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Service.Ipc;

public sealed class PipeAuthorizationService
{
    public bool IsAuthorized(
        PipeMessageType messageType,
        PipeClientContext context)
    {
        return messageType switch
        {
            PipeMessageType.SubmitDecision =>
                context.IsAdministrator,

            PipeMessageType.DeleteRule =>
                context.IsAdministrator,

            PipeMessageType.UpdateAlgorithmGuardSettings =>
                context.IsAdministrator,

            PipeMessageType.UpdateTransferGuardSettings =>
                context.IsAdministrator,
            
            PipeMessageType.CreateTransferGuardRule =>
                context.IsAdministrator,

            PipeMessageType.UpdateArchiveGuardSettings =>
                context.IsAdministrator,
            
            PipeMessageType.ExportSecurityLists =>
                context.IsAdministrator,

            PipeMessageType.ImportSecurityLists =>
                context.IsAdministrator,

            PipeMessageType.RestoreArchiveFromQuarantineWithException =>
                context.IsAdministrator,

            PipeMessageType.Ping or
            PipeMessageType.GetSnapshot or
            PipeMessageType.GetRules or
            PipeMessageType.GetAlgorithmGuardSettings or
            PipeMessageType.GetTransferGuardSettings or
            PipeMessageType.GetScanResults or
            PipeMessageType.GetScanResult or
            PipeMessageType.ScanFile or
            PipeMessageType.GetArchiveGuardSettings or
            PipeMessageType.ValidateSecurityLists or
            PipeMessageType.GetSecurityListsFolder or
            PipeMessageType.GetArchiveGuardQuarantineItems => true,

            _ => false
        };
    }
}
