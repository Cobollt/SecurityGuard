namespace SecurityGuard.Service.Application;

public sealed record WindowsServiceHostInspectionResult(
    bool Succeeded,
    IReadOnlyList<WindowsHostedServiceInfo> Services,
    string Reason);