using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace SafeScan.Services;

public sealed record SignatureInfo(string Status, string Publisher, bool IsMicrosoft);

public static class ProtectionService
{
    private static readonly string WindowsRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd('\\') + "\\";
    private static readonly string ProgramFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd('\\') + "\\";
    private static readonly string ProgramFilesX86 = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)).TrimEnd('\\') + "\\";

    public static bool IsSystemPath(string path) => IsUnder(path, WindowsRoot) || IsUnder(path, ProgramFiles) || IsUnder(path, ProgramFilesX86);
    private static bool IsUnder(string path, string root)
    {
        try { return Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase); }
        catch { return true; }
    }

    public static SignatureInfo GetSignature(string path)
    {
        if (!File.Exists(path) || !new[] { ".exe", ".dll", ".scr" }.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase))
            return new("不适用", "", false);
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            var publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
            var trusted = VerifyEmbeddedSignature(path);
            var microsoft = trusted && publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            return new(trusted ? "签名有效" : "签名无效/不受信任", publisher, microsoft);
        }
        catch (CryptographicException) { return new("未签名", "", false); }
        catch { return new("签名未知", "", false); }
    }

    private static bool VerifyEmbeddedSignature(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO(path);
        var data = new WINTRUST_DATA(fileInfo);
        try { return WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, data) == 0; }
        finally { data.Dispose(); fileInfo.Dispose(); }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, WINTRUST_DATA data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WINTRUST_FILE_INFO : IDisposable
    {
        public uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
        public IntPtr pcwszFilePath;
        public IntPtr hFile = IntPtr.Zero;
        public IntPtr pgKnownSubject = IntPtr.Zero;
        public WINTRUST_FILE_INFO(string path) => pcwszFilePath = Marshal.StringToCoTaskMemUni(path);
        public void Dispose() { if (pcwszFilePath != IntPtr.Zero) { Marshal.FreeCoTaskMem(pcwszFilePath); pcwszFilePath = IntPtr.Zero; } }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WINTRUST_DATA : IDisposable
    {
        public uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
        public IntPtr pPolicyCallbackData = IntPtr.Zero, pSIPClientData = IntPtr.Zero;
        public uint dwUIChoice = 2, fdwRevocationChecks = 0, dwUnionChoice = 1;
        public IntPtr pFile;
        public uint dwStateAction = 0, dwProvFlags = 0x00000010, dwUIContext = 0;
        public WINTRUST_DATA(WINTRUST_FILE_INFO file) { pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>()); Marshal.StructureToPtr(file, pFile, false); }
        public void Dispose() { if (pFile != IntPtr.Zero) { Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile); Marshal.FreeCoTaskMem(pFile); pFile = IntPtr.Zero; } }
    }
}
