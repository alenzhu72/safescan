using SafeScan.Models;
using System.Text.Json;

namespace SafeScan.Services;

public sealed class QuarantineService
{
    public string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafeScan", "Quarantine");

    public string Quarantine(ScanFinding finding)
    {
        EnsureSafe(finding);
        if (!File.Exists(finding.Path)) throw new InvalidOperationException("仅文件结果可隔离。");
        Directory.CreateDirectory(Root);
        var id = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}";
        var itemDir = Path.Combine(Root, id); Directory.CreateDirectory(itemDir);
        var destination = Path.Combine(itemDir, "payload.bin");
        File.Move(finding.Path, destination);
        var metadata = JsonSerializer.Serialize(new { finding.Path, finding.Sha256, finding.Reason, QuarantinedUtc = DateTime.UtcNow }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(itemDir, "metadata.json"), metadata);
        return destination;
    }

    public void Delete(ScanFinding finding)
    {
        EnsureSafe(finding);
        if (!File.Exists(finding.Path)) throw new InvalidOperationException("仅文件结果可删除。");
        File.Delete(finding.Path);
    }

    private static void EnsureSafe(ScanFinding finding)
    {
        if (finding.Protected || ProtectionService.IsSystemPath(finding.Path)) throw new InvalidOperationException($"受保护项目不可处理：{finding.ProtectionReason}");
    }
}
