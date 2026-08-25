using System.IO.Pipes;
using System.Security.Principal;

namespace SecurityGuard.Service.Ipc;

public sealed class PipeClientContextFactory
{
    private static readonly SecurityIdentifier AdministratorsSid =
        new(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);

    public PipeClientContext Create(
        NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(
            pipe);

        string? userName =
            null;

        var administrator =
            false;

        try
        {
            userName =
                pipe.GetImpersonationUserName();
        }
        catch
        {
        }

        try
        {
            pipe.RunAsClient(
                () =>
                {
                    using var identity =
                        WindowsIdentity.GetCurrent(
                            true);

                    if (identity is null)
                    {
                        return;
                    }

                    userName ??=
                        identity.Name;

                    var principal =
                        new WindowsPrincipal(
                            identity);

                    administrator =
                        principal.IsInRole(
                            AdministratorsSid);
                });
        }
        catch
        {
            administrator =
                false;
        }

        return new PipeClientContext(
            userName,
            administrator);
    }
}