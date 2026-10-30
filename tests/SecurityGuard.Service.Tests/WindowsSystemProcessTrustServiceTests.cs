using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Tests;

public sealed class WindowsSystemProcessTrustServiceTests
{
    [Fact]
    public async Task Windows_system_process_is_trusted()
    {
        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    4,
                    "System",
                    null));

        Assert.True(
            result.IsTrusted);
    }

    [Fact]
    public async Task Microsoft_signed_system32_process_is_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var executablePath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "trusted-test.exe");

        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "trusted-test.exe",
                    executablePath));

        Assert.True(
            result.IsTrusted);
    }

    [Fact]
    public async Task Cmd_is_never_automatically_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var executablePath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "cmd.exe");

        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "cmd.exe",
                    executablePath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Sensitive Windows executable",
            result.Reason);
    }

    [Fact]
    public async Task Non_microsoft_system32_process_is_not_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var executablePath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "foreign-test.exe");

        var service =
            CreateService(
                filePath =>
                    new AuthenticodeSignatureInfo(
                        filePath,
                        true,
                        true,
                        "Valid",
                        "CN=Example Corporation",
                        "TEST"));

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "foreign-test.exe",
                    executablePath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Executable is not signed by Microsoft",
            result.Reason);
    }

    [Fact]
    public async Task Process_outside_windows_directories_is_not_trusted()
    {
        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "application.exe",
                    @"C:\Program Files\Application\application.exe"));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Executable is outside trusted Windows locations",
            result.Reason);
    }

    [Fact]
    public async Task Microsoft_signed_immersive_control_panel_process_is_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var executablePath =
            Path.Combine(
                windowsDirectory,
                "ImmersiveControlPanel",
                "SystemSettings.exe");

        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "SystemSettings.exe",
                    executablePath));

        Assert.True(
            result.IsTrusted);
    }

    [Fact]
    public async Task Microsoft_signed_windows_apps_process_is_trusted()
    {
        var programFiles =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);

        var executablePath =
            Path.Combine(
                programFiles,
                "WindowsApps",
                "Microsoft.Test_1.0.0.0_x64__8wekyb3d8bbwe",
                "TestApp.exe");

        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "TestApp.exe",
                    executablePath));

        Assert.True(
            result.IsTrusted);
    }

    [Fact]
    public async Task Microsoft_signed_windows_defender_process_is_trusted()
    {
        var programData =
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);

        var executablePath =
            Path.Combine(
                programData,
                "Microsoft",
                "Windows Defender",
                "Platform",
                "4.18.00000.0-0",
                "MsMpEng.exe");

        var service =
            CreateService(
                CreateValidMicrosoftSignature);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "MsMpEng.exe",
                    executablePath));

        Assert.True(
            result.IsTrusted);
    }

    [Fact]
    public async Task Non_microsoft_windows_apps_process_is_not_trusted()
    {
        var programFiles =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);

        var executablePath =
            Path.Combine(
                programFiles,
                "WindowsApps",
                "ThirdParty.Application_1.0.0.0_x64__test",
                "Application.exe");

        var service =
            CreateService(
                filePath =>
                    new AuthenticodeSignatureInfo(
                        filePath,
                        true,
                        true,
                        "Valid",
                        "CN=Example Corporation",
                        "TEST"));

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "Application.exe",
                    executablePath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Executable is not signed by Microsoft",
            result.Reason);
    }

    [Fact]
    public async Task Svchost_with_trusted_microsoft_service_dll_is_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var svchostPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "svchost.exe");

        var serviceDllPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "trustedservice.dll");

        var inspector =
            new FakeWindowsServiceHostInspector(
                new WindowsServiceHostInspectionResult(
                    true,
                    [
                        new WindowsHostedServiceInfo(
                        "TrustedService",
                        serviceDllPath)
                    ],
                    "Hosted Windows services resolved"));

        var service =
            CreateService(
                CreateValidMicrosoftSignature,
                inspector);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "svchost.exe",
                    svchostPath));

        Assert.True(
            result.IsTrusted);

        Assert.Equal(
            "Trusted Microsoft Windows service host",
            result.Reason);

        Assert.Equal(
            1,
            inspector.CallCount);
    }

    [Fact]
    public async Task Svchost_without_resolved_services_is_not_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var svchostPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "svchost.exe");

        var inspector =
            new FakeWindowsServiceHostInspector(
                new WindowsServiceHostInspectionResult(
                    false,
                    [],
                    "No Windows services are associated with the process"));

        var service =
            CreateService(
                CreateValidMicrosoftSignature,
                inspector);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "svchost.exe",
                    svchostPath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "No Windows services are associated with the process",
            result.Reason);

        Assert.Equal(
            1,
            inspector.CallCount);
    }

    [Fact]
    public async Task Svchost_with_missing_service_dll_is_not_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var svchostPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "svchost.exe");

        var inspector =
            new FakeWindowsServiceHostInspector(
                new WindowsServiceHostInspectionResult(
                    true,
                    [
                        new WindowsHostedServiceInfo(
                        "UnknownService",
                        null)
                    ],
                    "Hosted Windows services resolved"));

        var service =
            CreateService(
                CreateValidMicrosoftSignature,
                inspector);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "svchost.exe",
                    svchostPath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Service DLL is unavailable for UnknownService",
            result.Reason);
    }

    [Fact]
    public async Task Svchost_with_non_microsoft_service_dll_is_not_trusted()
    {
        var windowsDirectory =
            Environment.GetEnvironmentVariable(
                "WINDIR") ??
            @"C:\Windows";

        var svchostPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "svchost.exe");

        var serviceDllPath =
            Path.Combine(
                windowsDirectory,
                "System32",
                "thirdpartyservice.dll");

        var inspector =
            new FakeWindowsServiceHostInspector(
                new WindowsServiceHostInspectionResult(
                    true,
                    [
                        new WindowsHostedServiceInfo(
                        "ThirdPartyService",
                        serviceDllPath)
                    ],
                    "Hosted Windows services resolved"));

        var service =
            CreateService(
                filePath =>
                {
                    if (string.Equals(
                            filePath,
                            serviceDllPath,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return new AuthenticodeSignatureInfo(
                            filePath,
                            true,
                            true,
                            "Valid",
                            "CN=Example Corporation",
                            "TEST");
                    }

                    return CreateValidMicrosoftSignature(
                        filePath);
                },
                inspector);

        var result =
            await service.EvaluateAsync(
                new WindowsSystemProcessTrustRequest(
                    100,
                    "svchost.exe",
                    svchostPath));

        Assert.False(
            result.IsTrusted);

        Assert.Equal(
            "Service DLL is not signed by Microsoft for ThirdPartyService",
            result.Reason);
    }

    private static WindowsSystemProcessTrustService CreateService(
        Func<string, AuthenticodeSignatureInfo> signatureFactory,
        IWindowsServiceHostInspector? serviceHostInspector = null)
    {
        return new WindowsSystemProcessTrustService(
            new FakeSignatureService(
                signatureFactory),
            serviceHostInspector ??
            new FakeWindowsServiceHostInspector(
                new WindowsServiceHostInspectionResult(
                    true,
                    [
                        new WindowsHostedServiceInfo(
                        "TestService",
                        Path.Combine(
                            Environment.GetEnvironmentVariable("WINDIR") ??
                            @"C:\Windows",
                            "System32",
                            "testservice.dll"))
                    ],
                    "Hosted Windows services resolved")));
    }

    private static AuthenticodeSignatureInfo CreateValidMicrosoftSignature(
        string filePath)
    {
        return new AuthenticodeSignatureInfo(
            filePath,
            true,
            true,
            "Valid",
            "CN=Microsoft Windows, O=Microsoft Corporation, C=US",
            "TEST");
    }

    private sealed class FakeSignatureService
        : IAuthenticodeSignatureService
    {
        private readonly Func<string, AuthenticodeSignatureInfo> _factory;

        public FakeSignatureService(
            Func<string, AuthenticodeSignatureInfo> factory)
        {
            _factory =
                factory;
        }

        public Task<AuthenticodeSignatureInfo> GetAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _factory(
                    filePath));
        }
    }

    private sealed class FakeWindowsServiceHostInspector
        : IWindowsServiceHostInspector
    {
        private readonly WindowsServiceHostInspectionResult _result;

        public int CallCount { get; private set; }

        public FakeWindowsServiceHostInspector(
            WindowsServiceHostInspectionResult result)
        {
            _result =
                result;
        }

        public Task<WindowsServiceHostInspectionResult> InspectAsync(
            int processId,
            CancellationToken cancellationToken = default)
        {
            CallCount++;

            return Task.FromResult(
                _result);
        }
    }
}