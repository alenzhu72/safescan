using SafeScan.Models;
using System.Diagnostics;

namespace SafeScan.Services;

public static class DefenderService
{
    public static async Task<ScanFinding> QuickScanAsync(CancellationToken token)
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft Defender\MpCmdRun.exe")
        };
        var exe = candidates.FirstOrDefault(File.Exists) ?? "MpCmdRun.exe";
        try
        {
            var psi = new ProcessStartInfo(exe, "-Scan -ScanType 1") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("无法启动 Defender");
            var stdout = p.StandardOutput.ReadToEndAsync(token); var stderr = p.StandardError.ReadToEndAsync(token);
            await p.WaitForExitAsync(token);
            var detail = ((await stdout) + " " + (await stderr)).Trim();
            return new ScanFinding { Risk = p.ExitCode == 0 ? RiskLevel.Info : RiskLevel.High, Kind = FindingKind.Defender, Path = "Microsoft Defender 快速扫描", Reason = p.ExitCode == 0 ? "Defender 扫描完成，未报告命令错误" : $"Defender 返回代码 {p.ExitCode}：{detail}", SignatureStatus = "Microsoft Defender", Status = "已完成" };
        }
        catch (Exception ex) { return new ScanFinding { Risk = RiskLevel.Medium, Kind = FindingKind.Defender, Path = "Microsoft Defender 快速扫描", Reason = $"无法完成：{ex.Message}", SignatureStatus = "未知", Status = "失败" }; }
    }
}
