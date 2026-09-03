using System.Buffers.Binary;
using System.Text;

namespace SecurityGuard.ArchiveGuard.Tests;

internal static class PeTestFileFactory
{
    public static byte[] Create(
        bool writableExecutable = false,
        byte[]? sectionData = null)
    {
        sectionData ??=
            new byte[512];

        var data =
            new byte[
                0x200 +
                sectionData.Length];

        data[0] =
            0x4D;

        data[1] =
            0x5A;

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0x3C,
                4),
            0x80);

        data[0x80] =
            0x50;

        data[0x81] =
            0x45;

        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(
                0x84,
                2),
            0x8664);

        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(
                0x86,
                2),
            1);

        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(
                0x94,
                2),
            0xF0);

        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(
                0x98,
                2),
            0x20B);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0xA8,
                4),
            0x1000);

        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(
                0xB0,
                8),
            0x140000000);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0xB8,
                4),
            0x1000);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0xBC,
                4),
            0x200);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0xD0,
                4),
            0x2000);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0xD4,
                4),
            0x200);

        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(
                0xDC,
                2),
            3);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                0x104,
                4),
            16);

        var section =
            0x188;

        Encoding.ASCII
            .GetBytes(
                ".text")
            .CopyTo(
                data,
                section);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                section + 8,
                4),
            (uint)sectionData.Length);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                section + 12,
                4),
            0x1000);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                section + 16,
                4),
            (uint)sectionData.Length);

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                section + 20,
                4),
            0x200);

        var characteristics =
            writableExecutable
                ? 0xE0000020u
                : 0x60000020u;

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(
                section + 36,
                4),
            characteristics);

        sectionData.CopyTo(
            data,
            0x200);

        return data;
    }
}