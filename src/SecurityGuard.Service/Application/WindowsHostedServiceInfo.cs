namespace SecurityGuard.Service.Application;

public sealed record WindowsHostedServiceInfo(
    string ServiceName,
    string? ServiceDllPath);