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

            _ =>
                true
        };
    }
}