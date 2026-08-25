using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Service.Ipc;

public sealed class SecurityGuardPipeFactory
{
    public NamedPipeServerStream Create()
    {
        var security =
            new PipeSecurity();

        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.AuthenticatedUserSid,
                    null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

        security.AddAccessRule(
            new PipeAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.NetworkSid,
                    null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Deny));

        return NamedPipeServerStreamAcl.Create(
            PipeProtocol.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security,
            HandleInheritability.None);
    }
}