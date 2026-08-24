namespace SecurityGuard.Core.Ipc;

public enum PipeMessageType
{
    Ping = 0,
    GetSnapshot = 1,
    SubmitDecision = 2,
    GetRules = 3,
    DeleteRule = 4,
    GetAlgorithmGuardSettings = 5,
    UpdateAlgorithmGuardSettings = 6
}