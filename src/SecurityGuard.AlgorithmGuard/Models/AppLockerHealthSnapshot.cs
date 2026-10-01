namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AppLockerHealthSnapshot(
    bool IsWindows,
    bool EngineInstalled,
    bool EngineRunning,
    bool ApplicationIdentityInstalled,
    bool ApplicationIdentityRunning,
    bool PowerShellAvailable,
    bool ManagementCmdletsAvailable,
    bool PolicyReadable,
    string? Error)
{
    public bool EngineReady =>
        IsWindows &&
        EngineInstalled &&
        EngineRunning &&
        ApplicationIdentityInstalled &&
        ApplicationIdentityRunning;

    public bool ManagementReady =>
        PowerShellAvailable &&
        ManagementCmdletsAvailable &&
        PolicyReadable;

    public bool EnforcementReady =>
        EngineReady &&
        ManagementReady;
}