using Microsoft.Win32;
using SafeScan.Models;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SafeScan.Services;

public sealed class ScannerService
{
    private static readonly HashSet<string> Interesting = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".scr", ".com", ".hta", ".lnk" };
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);

    public async Task ScanAsync(Action<ScanFinding> found, Action<string> progress, CancellationToken token)
    {
        _seen.Clear();
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new[]
        {
            user, Path.Combine(user, "Downloads"), Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

        await Task.Run(() =>
        {
            foreach (var root in roots) { token.ThrowIfCancellationRequested(); progress($"正在检查 {root}"); ScanDirectory(root, found, token); }
            progress("正在检查 Run / RunOnce 注册表项"); ScanRegistry(found);
            progress("正在检查可疑后台进程和服务"); ScanRunningProcesses(found); ScanServices(found);
            progress("正在检查计划任务"); ScanScheduledTasks(found, token);
            progress("正在检查浏览器密码风险与扩展"); ScanBrowserCredentialRisk(user, found); ScanBrowserExtensions(user, found, token);
        }, token);
    }

    private void ScanDirectory(string root, Action<ScanFinding> found, CancellationToken token)
    {
        var dirs = new Stack<string>(); dirs.Push(root);
        var count = 0;
        while (dirs.Count > 0)
        {
            token.ThrowIfCancellationRequested();
            var dir = dirs.Pop();
            try { foreach (var child in Directory.EnumerateDirectories(dir)) if (!IsExcluded(child)) dirs.Push(child); } catch { }
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    if ((++count & 127) == 0) token.ThrowIfCancellationRequested();
                    if (Interesting.Contains(Path.GetExtension(file))) AnalyzeFile(file, found);
                }
            } catch { }
        }
    }

    private static bool IsExcluded(string p) => p.Contains("\\SafeScan\\Quarantine", StringComparison.OrdinalIgnoreCase)
        || p.Contains("\\AppData\\Local\\Packages\\", StringComparison.OrdinalIgnoreCase)
        || p.Contains("\\node_modules\\", StringComparison.OrdinalIgnoreCase)
        || HasDirectorySegment(p, "OneDrive")
        || HasDirectorySegment(p, "OneDriveTemp")
        || HasDirectorySegment(p, "WPS Cloud Files")
        || HasDirectorySegment(p, "WPSDrive")
        || HasDirectorySegment(p, "WPS Cloud Drive")
        || HasDirectorySegment(p, "Kingsoft Cloud Files");

    private static bool HasDirectorySegment(string path, string name)
    {
        var normalized = path.TrimEnd('\\', '/');
        return normalized.EndsWith($"\\{name}", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains($"\\{name}\\", StringComparison.OrdinalIgnoreCase);
    }

    private void AnalyzeFile(string path, Action<ScanFinding> found, string? extraReason = null, FindingKind kind = FindingKind.File)
    {
        if (!_seen.Add(path)) return;
        try
        {
            var fi = new FileInfo(path);
            var sig = ProtectionService.GetSignature(path);
            var system = ProtectionService.IsSystemPath(path);
            var ext = fi.Extension.ToLowerInvariant();
            var recent = fi.CreationTimeUtc > DateTime.UtcNow.AddDays(-30);
            var temp = path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase);
            var startup = path.Contains("\\Start Menu\\Programs\\Startup\\", StringComparison.OrdinalIgnoreCase);
            var doubleExt = Path.GetFileNameWithoutExtension(path).Contains('.');
            var script = new[] { ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta" }.Contains(ext);
            var reasons = new List<string>();
            if (extraReason is not null) reasons.Add(extraReason);
            if (temp) reasons.Add("位于临时目录");
            if (startup) reasons.Add("位于启动目录");
            if (script) reasons.Add("可执行脚本类型");
            if (doubleExt) reasons.Add("疑似双扩展名");
            if (recent) reasons.Add("近 30 天创建");
            if (sig.Status == "未签名" && new[] { ".exe", ".dll", ".scr" }.Contains(ext)) reasons.Add("未发现数字签名");
            var capability = InspectCapabilities(fi, sig.IsMicrosoft);
            if (capability.Reason is not null) reasons.Add(capability.Reason);
            var score = (temp ? 2 : 0) + (startup ? 3 : 0) + (script ? 1 : 0) + (doubleExt ? 2 : 0) + (recent ? 1 : 0) + (sig.Status == "未签名" ? 1 : 0) + (extraReason is null ? 0 : 2) + capability.Score;
            if (score < 2 && extraReason is null) return;
            var protectedFile = system || sig.IsMicrosoft;
            found(new ScanFinding
            {
                Risk = score >= 6 ? RiskLevel.High : score >= 4 ? RiskLevel.Medium : RiskLevel.Low,
                Kind = kind, Path = path, Reason = string.Join("；", reasons), Sha256 = Hash(path),
                SignatureStatus = sig.Status, Publisher = sig.Publisher, Created = fi.CreationTime, Modified = fi.LastWriteTime,
                Protected = protectedFile, ProtectionReason = system ? "系统/程序目录受保护" : sig.IsMicrosoft ? "Microsoft 签名文件受保护" : ""
            });
        } catch { }
    }

    private static (int Score, string? Reason) InspectCapabilities(FileInfo file, bool isMicrosoft)
    {
        if (isMicrosoft || file.Length <= 0 || file.Length > 20 * 1024 * 1024 || !new[] { ".exe", ".dll", ".scr" }.Contains(file.Extension, StringComparer.OrdinalIgnoreCase)) return (0, null);
        try
        {
            var text = Encoding.ASCII.GetString(File.ReadAllBytes(file.FullName));
            var keyboard = text.Contains("GetAsyncKeyState", StringComparison.Ordinal) || text.Contains("SetWindowsHookEx", StringComparison.Ordinal) || text.Contains("GetRawInputData", StringComparison.Ordinal);
            var credential = text.Contains("Login Data", StringComparison.OrdinalIgnoreCase) && (text.Contains("CryptUnprotectData", StringComparison.Ordinal) || text.Contains("Local State", StringComparison.OrdinalIgnoreCase));
            if (keyboard && credential) return (5, "同时包含键盘监听与浏览器凭据访问特征");
            if (credential) return (4, "包含浏览器凭据数据库及解密 API 特征");
            if (keyboard) return (3, "包含键盘输入监听 API 特征（也可能是正常热键软件）");
        }
        catch { }
        return (0, null);
    }

    private static string Hash(string path)
    {
        try { using var s = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(s)); } catch { return "无法读取"; }
    }

    private void ScanRegistry(Action<ScanFinding> found)
    {
        var locations = new[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        };
        foreach (var (hive, sub) in locations)
        {
            try
            {
                using var key = hive.OpenSubKey(sub);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var command = key.GetValue(name)?.ToString() ?? "";
                    var file = ExtractPath(command);
                    if (file is not null && File.Exists(file)) AnalyzeFile(file, found, $"自启动注册表项：{name}", FindingKind.Registry);
                    else found(new ScanFinding { Risk = RiskLevel.Medium, Kind = FindingKind.Registry, Path = $"{hive.Name}\\{sub} | {name} = {command}", Reason = "自启动命令，目标路径无法直接验证", SignatureStatus = "未知" });
                }
            } catch { }
        }
    }

    private static string? ExtractPath(string command)
    {
        command = Environment.ExpandEnvironmentVariables(command.Trim());
        if (command.StartsWith('"')) { var end = command.IndexOf('"', 1); return end > 1 ? command[1..end] : null; }
        foreach (var ext in Interesting) { var i = command.IndexOf(ext, StringComparison.OrdinalIgnoreCase); if (i >= 0) return command[..(i + ext.Length)].Trim(); }
        return null;
    }

    private void ScanRunningProcesses(Action<ScanFinding> found)
    {
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (path is null || !File.Exists(path) || IsExcluded(path)) continue;
                var inUserArea = path.StartsWith(user, StringComparison.OrdinalIgnoreCase) || path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase);
                if (!inUserArea) continue;
                var sig = ProtectionService.GetSignature(path);
                if (sig.Status != "签名有效") AnalyzeFile(path, found, $"当前运行进程：{process.ProcessName}（未验证到可信签名）", FindingKind.Process);
            }
            catch { }
            finally { process.Dispose(); }
        }
    }

    private void ScanServices(Action<ScanFinding> found)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return;
            foreach (var name in services.GetSubKeyNames())
            {
                try
                {
                    using var key = services.OpenSubKey(name);
                    var command = key?.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrWhiteSpace(command) || IsExcluded(command)) continue;
                    var path = ExtractPath(command);
                    if (path is null || !File.Exists(path)) continue;
                    var userWritable = path.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase);
                    if (userWritable) AnalyzeFile(path, found, $"Windows 服务 {name} 从用户可写目录启动", FindingKind.Service);
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanBrowserCredentialRisk(string user, Action<ScanFinding> found)
    {
        var profiles = new[]
        {
            ("Chrome", Path.Combine(user, @"AppData\Local\Google\Chrome\User Data")),
            ("Edge", Path.Combine(user, @"AppData\Local\Microsoft\Edge\User Data"))
        };
        foreach (var (browser, root) in profiles.Where(x => Directory.Exists(x.Item2)))
        {
            try
            {
                var databases = Directory.EnumerateFiles(root, "Login Data", SearchOption.AllDirectories).ToList();
                if (databases.Count == 0) continue;
                found(new ScanFinding
                {
                    Risk = RiskLevel.Info, Kind = FindingKind.PasswordExposure, Path = $"{browser} 保存的密码数据库（{databases.Count} 个配置文件）",
                    Reason = "检测到本机保存密码。数据通常受 Windows 加密保护，但若信息窃取木马曾以当前用户身份运行，密码可能已被读取；本机扫描无法证明是否已外传。建议在可信设备上更换重要密码并撤销会话。",
                    SignatureStatus = "不适用", Protected = true, ProtectionReason = "浏览器数据只检查，不允许删除", Status = "需采取账户措施"
                });
            }
            catch { }
        }
    }

    private void ScanScheduledTasks(Action<ScanFinding> found, CancellationToken token)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /V") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true, StandardOutputEncoding = Encoding.Unicode };
            using var p = Process.Start(psi); if (p is null) return;
            var output = p.StandardOutput.ReadToEnd(); p.WaitForExit(15000); token.ThrowIfCancellationRequested();
            foreach (var line in output.Split('\n').Where(x => x.Contains("AppData", StringComparison.OrdinalIgnoreCase) || x.Contains("Temp", StringComparison.OrdinalIgnoreCase) || x.Contains("powershell", StringComparison.OrdinalIgnoreCase) || x.Contains("wscript", StringComparison.OrdinalIgnoreCase)))
                found(new ScanFinding { Risk = RiskLevel.Medium, Kind = FindingKind.ScheduledTask, Path = line.Trim(), Reason = "计划任务命令包含用户目录、临时目录或脚本宿主", SignatureStatus = "需人工复核" });
        } catch { }
    }

    private void ScanBrowserExtensions(string user, Action<ScanFinding> found, CancellationToken token)
    {
        var roots = new[]
        {
            Path.Combine(user, @"AppData\Local\Google\Chrome\User Data"),
            Path.Combine(user, @"AppData\Local\Microsoft\Edge\User Data")
        };
        foreach (var root in roots.Where(Directory.Exists))
        {
            try
            {
                foreach (var manifest in Directory.EnumerateFiles(root, "manifest.json", SearchOption.AllDirectories).Where(x => x.Contains("\\Extensions\\", StringComparison.OrdinalIgnoreCase)))
                {
                    token.ThrowIfCancellationRequested();
                    var text = File.ReadAllText(manifest);
                    var risky = text.Contains("nativeMessaging", StringComparison.OrdinalIgnoreCase) || text.Contains("<all_urls>", StringComparison.OrdinalIgnoreCase) || text.Contains("webRequest", StringComparison.OrdinalIgnoreCase);
                    if (risky) found(new ScanFinding { Risk = RiskLevel.Low, Kind = FindingKind.BrowserExtension, Path = manifest, Reason = "扩展申请高权限（不代表恶意，需核对扩展来源）", Sha256 = Hash(manifest), Created = File.GetCreationTime(manifest), Modified = File.GetLastWriteTime(manifest), SignatureStatus = "浏览器扩展" });
                }
            } catch { }
        }
    }
}
