namespace SecurityGuard.Service.Application;

public interface IWindowsServiceHostInspector
{
    Task<WindowsServiceHostInspectionResult> InspectAsync(
        int processId,
        CancellationToken cancellationToken = default);
}