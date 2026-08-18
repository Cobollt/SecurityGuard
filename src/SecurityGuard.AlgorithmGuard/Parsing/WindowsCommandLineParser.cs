using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SecurityGuard.AlgorithmGuard.Parsing;

public sealed partial class WindowsCommandLineParser
{
    public IReadOnlyList<string> Parse(
        string commandLine)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            commandLine);

        var pointer =
            CommandLineToArgvW(
                commandLine,
                out var argumentCount);

        if (pointer == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error());
        }

        try
        {
            var arguments =
                new string[argumentCount];

            for (var index = 0;
                 index < argumentCount;
                 index++)
            {
                var itemPointer =
                    Marshal.ReadIntPtr(
                        pointer,
                        index * IntPtr.Size);

                arguments[index] =
                    Marshal.PtrToStringUni(
                        itemPointer) ?? string.Empty;
            }

            return arguments;
        }
        finally
        {
            LocalFree(pointer);
        }
    }

    [LibraryImport(
        "shell32.dll",
        EntryPoint = "CommandLineToArgvW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr CommandLineToArgvW(
        string commandLine,
        out int argumentCount);

    [LibraryImport(
        "kernel32.dll")]
    private static partial IntPtr LocalFree(
        IntPtr memory);
}