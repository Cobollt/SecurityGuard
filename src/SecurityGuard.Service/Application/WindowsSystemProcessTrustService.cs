using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class WindowsSystemProcessTrustService
    : IWindowsSystemProcessTrustService
{
    private static readonly HashSet<string> NeverTrustAutomatically =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            "cmd",
            "powershell",
            "powershell_ise",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "certutil",
            "bitsadmin",
            "schtasks",
            "msiexec",
            "wmic",
            "reg",
            "sc"
        };

    private readonly IAuthenticodeSignatureService _signatureService;
    private readonly IWindowsServiceHostInspector _serviceHostInspector;
    private readonly string _windowsDirectory;

    public WindowsSystemProcessTrustService(
        IAuthenticodeSignatureService signatureService,
        IWindowsServiceHostInspector serviceHostInspector)
    {
        _signatureService =
            signatureService;

        _serviceHostInspector =
            serviceHostInspector;

        _windowsDirectory =
            NormalizeDirectory(
                Environment.GetEnvironmentVariable(
                    "WINDIR") ??
                @"C:\Windows");
    }

    public async Task<WindowsSystemProcessTrustResult> EvaluateAsync(
        WindowsSystemProcessTrustRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var processName =
            NormalizeProcessName(
                request.ProcessName);

        if (request.ProcessId == 4 &&
            string.Equals(
                processName,
                "system",
                StringComparison.OrdinalIgnoreCase))
        {
            return new WindowsSystemProcessTrustResult(
                true,
                "Windows kernel system process");
        }

        if (NeverTrustAutomatically.Contains(
                processName))
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Sensitive Windows executable");
        }

        if (string.IsNullOrWhiteSpace(
                request.ExecutablePath))
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Executable path is unavailable");
        }

        string fullPath;

        try
        {
            fullPath =
                Path.GetFullPath(
                    request.ExecutablePath);
        }
        catch
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Executable path is invalid");
        }

        if (!IsTrustedWindowsLocation(
                fullPath))
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Executable is outside trusted Windows locations");
        }

        var publisher =
            request.Publisher;

        var signatureStatus =
            request.SignatureStatus;

        if (!IsValidSignature(
                signatureStatus) ||
            !IsMicrosoftPublisher(
                publisher))
        {
            try
            {
                var signature =
                    await _signatureService.GetAsync(
                        fullPath,
                        cancellationToken);

                publisher =
                    signature.Publisher;

                signatureStatus =
                    signature.Status;
            }
            catch
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    "Executable signature could not be verified");
            }
        }

        if (!IsValidSignature(
                signatureStatus))
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Executable signature is not valid");
        }

        if (!IsMicrosoftPublisher(
                publisher))
        {
            return new WindowsSystemProcessTrustResult(
                false,
                "Executable is not signed by Microsoft");
        }

        if (string.Equals(
        processName,
        "svchost",
        StringComparison.OrdinalIgnoreCase))
        {
            return await EvaluateServiceHostAsync(
                request.ProcessId,
                cancellationToken);
        }

        return new WindowsSystemProcessTrustResult(
            true,
            "Trusted Microsoft Windows executable");
    }

    private async Task<WindowsSystemProcessTrustResult> EvaluateServiceHostAsync(
        int processId,
        CancellationToken cancellationToken)
    {
        var inspection =
            await _serviceHostInspector.InspectAsync(
                processId,
                cancellationToken);

        if (!inspection.Succeeded ||
            inspection.Services.Count == 0)
        {
            return new WindowsSystemProcessTrustResult(
                false,
                inspection.Reason);
        }

        foreach (var service in inspection.Services)
        {
            if (string.IsNullOrWhiteSpace(
                    service.ServiceDllPath))
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL is unavailable for {service.ServiceName}");
            }

            string fullPath;

            try
            {
                fullPath =
                    Path.GetFullPath(
                        service.ServiceDllPath);
            }
            catch
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL path is invalid for {service.ServiceName}");
            }

            if (!IsTrustedWindowsServiceDllLocation(
                    fullPath))
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL is outside trusted Windows locations for {service.ServiceName}");
            }

            string? publisher;
            string? status;

            try
            {
                var signature =
                    await _signatureService.GetAsync(
                        fullPath,
                        cancellationToken);

                publisher =
                    signature.Publisher;

                status =
                    signature.Status;
            }
            catch
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL signature could not be verified for {service.ServiceName}");
            }

            if (!IsValidSignature(
                    status))
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL signature is not valid for {service.ServiceName}");
            }

            if (!IsMicrosoftPublisher(
                    publisher))
            {
                return new WindowsSystemProcessTrustResult(
                    false,
                    $"Service DLL is not signed by Microsoft for {service.ServiceName}");
            }
        }

        return new WindowsSystemProcessTrustResult(
            true,
            "Trusted Microsoft Windows service host");
    }

    private bool IsTrustedWindowsServiceDllLocation(
        string fullPath)
    {
        return IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "System32")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "SysWOW64"));
    }

    private bool IsTrustedWindowsLocation(
        string fullPath)
    {
        var explorerPath =
            Path.Combine(
                _windowsDirectory,
                "explorer.exe");

        if (string.Equals(
                fullPath,
                explorerPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var programFiles =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);

        var programData =
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);

        return IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "System32")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "SysWOW64")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "SystemApps")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       _windowsDirectory,
                       "ImmersiveControlPanel")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       programFiles,
                       "WindowsApps")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       programFiles,
                       "Windows Defender")) ||
               IsInsideDirectory(
                   fullPath,
                   Path.Combine(
                       programData,
                       "Microsoft",
                       "Windows Defender"));
    }
    private static bool IsInsideDirectory(
        string filePath,
        string directory)
    {
        var normalizedDirectory =
            NormalizeDirectory(
                directory) +
            Path.DirectorySeparatorChar;

        return filePath.StartsWith(
            normalizedDirectory,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectory(
        string path)
    {
        return Path.GetFullPath(
                path)
            .TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);
    }

    private static string NormalizeProcessName(
        string processName)
    {
        var fileName =
            Path.GetFileNameWithoutExtension(
                processName);

        return string.IsNullOrWhiteSpace(
                fileName)
            ? processName
            : fileName;
    }

    private static bool IsValidSignature(
        string? status)
    {
        return string.Equals(
            status,
            "Valid",
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsMicrosoftPublisher(
        string? publisher)
    {
        if (string.IsNullOrWhiteSpace(
                publisher))
        {
            return false;
        }

        return publisher.Contains(
                   "O=Microsoft Corporation",
                   StringComparison.OrdinalIgnoreCase) ||
               publisher.Contains(
                   "CN=Microsoft Windows",
                   StringComparison.OrdinalIgnoreCase) ||
               publisher.Contains(
                   "CN=Microsoft Corporation",
                   StringComparison.OrdinalIgnoreCase) ||
               string.Equals(
                   publisher.Trim(),
                   "Microsoft Corporation",
                   StringComparison.OrdinalIgnoreCase);
    }
}