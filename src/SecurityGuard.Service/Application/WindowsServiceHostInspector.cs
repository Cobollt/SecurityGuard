using System.Management;
using Microsoft.Win32;

namespace SecurityGuard.Service.Application;

public sealed class WindowsServiceHostInspector
    : IWindowsServiceHostInspector
{
    public Task<WindowsServiceHostInspectionResult> InspectAsync(
        int processId,
        CancellationToken cancellationToken = default)
    {
        if (processId <= 0)
        {
            return Task.FromResult(
                new WindowsServiceHostInspectionResult(
                    false,
                    [],
                    "Process ID is invalid"));
        }

        try
        {
            var services =
                new List<WindowsHostedServiceInfo>();

            using var searcher =
                new ManagementObjectSearcher(
                    "root\\CIMV2",
                    $"SELECT Name FROM Win32_Service WHERE ProcessId = {processId}");

            using var results =
                searcher.Get();

            foreach (ManagementObject service in results)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (service)
                {
                    var serviceName =
                        Convert.ToString(
                            service["Name"]);

                    if (string.IsNullOrWhiteSpace(
                            serviceName))
                    {
                        continue;
                    }

                    services.Add(
                        new WindowsHostedServiceInfo(
                            serviceName,
                            GetServiceDllPath(
                                serviceName)));
                }
            }

            if (services.Count == 0)
            {
                return Task.FromResult(
                    new WindowsServiceHostInspectionResult(
                        false,
                        [],
                        "No Windows services are associated with the process"));
            }

            return Task.FromResult(
                new WindowsServiceHostInspectionResult(
                    true,
                    services,
                    "Hosted Windows services resolved"));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return Task.FromResult(
                new WindowsServiceHostInspectionResult(
                    false,
                    [],
                    "Windows service host inspection failed"));
        }
    }

    private static string? GetServiceDllPath(
        string serviceName)
    {
        var path =
            ReadServiceDllPath(
                serviceName);

        if (!string.IsNullOrWhiteSpace(
                path))
        {
            return NormalizeServiceDllPath(
                path);
        }

        var separatorIndex =
            serviceName.LastIndexOf(
                '_');

        if (separatorIndex <= 0)
        {
            return null;
        }

        var baseServiceName =
            serviceName[..separatorIndex];

        path =
            ReadServiceDllPath(
                baseServiceName);

        return string.IsNullOrWhiteSpace(
                path)
            ? null
            : NormalizeServiceDllPath(
                path);
    }

    private static string? ReadServiceDllPath(
        string serviceName)
    {
        var parametersPath =
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters";

        using var parametersKey =
            Registry.LocalMachine.OpenSubKey(
                parametersPath);

        var value =
            parametersKey?.GetValue(
                "ServiceDll",
                null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);

        if (value is not null)
        {
            return Convert.ToString(
                value);
        }

        var servicePath =
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}";

        using var serviceKey =
            Registry.LocalMachine.OpenSubKey(
                servicePath);

        value =
            serviceKey?.GetValue(
                "ServiceDll",
                null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);

        return Convert.ToString(
            value);
    }

    private static string NormalizeServiceDllPath(
        string path)
    {
        return Environment
            .ExpandEnvironmentVariables(
                path.Trim())
            .Trim('"');
    }
}