using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SafeScan.Models;

public enum RiskLevel { Info, Low, Medium, High, Critical }
public enum FindingKind { File, Registry, Startup, ScheduledTask, BrowserExtension, PasswordExposure, Process, Service, Defender }

public sealed class ScanFinding : INotifyPropertyChanged
{
    private bool _isSelected;
    public bool IsSelected { get => _isSelected; set { _isSelected = value; OnChanged(); } }
    public RiskLevel Risk { get; init; }
    public FindingKind Kind { get; init; }
    public string Path { get; init; } = "";
    public string Reason { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public string SignatureStatus { get; init; } = "不适用";
    public string Publisher { get; init; } = "";
    public DateTime? Created { get; init; }
    public DateTime? Modified { get; init; }
    public bool Protected { get; init; }
    public string ProtectionReason { get; init; } = "";
    public string Status { get; set; } = "待处理";
    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
