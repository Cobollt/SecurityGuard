using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecurityGuard.Service.DependencyInjection;

var builder =
    Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(
    options =>
    {
        options.ServiceName =
            "SecurityGuard";
    });

builder.Services.AddSecurityGuard();

var host =
    builder.Build();

await host.RunAsync();