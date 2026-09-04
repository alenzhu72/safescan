using Microsoft.Win32;
using SafeScan.Models;
using SafeScan.Services;
using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace SafeScan;

public partial class MainWindow : Window
{
    public ObservableCollection<ScanFinding> Findings { get; } = new();
    private CancellationTokenSource? _cts;
    private readonly ScannerService _scanner = new();
    private readonly QuarantineService _quarantine = new();

    public MainWindow() { InitializeComponent(); DataContext = this; }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        Findings.Clear(); SetBusy(true, "准备扫描…"); _cts = new CancellationTokenSource();
        try
        {
            await _scanner.ScanAsync(f => Dispatcher.Invoke(() => { Findings.Add(f); CountText.Text = $"{Findings.Count} 项结果"; }), s => Dispatcher.Invoke(() => StatusText.Text = s), _cts.Token);
            StatusText.Text = $"扫描完成。发现 {Findings.Count} 个需复核项目；结果是启发式判断，不等同于确诊。";
        }
        catch (OperationCanceledException) { StatusText.Text = "扫描已停止。"; }
        catch (Exception ex) { MessageBox.Show(ex.Message, "扫描错误", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { SetBusy(false, StatusText.Text); }
    }

    private async void Defender_Click(object sender, RoutedEventArgs e)
    {
        SetBusy(true, "Microsoft Defender 正在快速扫描（可能需要数分钟）…"); _cts = new CancellationTokenSource();
        var result = await DefenderService.QuickScanAsync(_cts.Token);
        Findings.Add(result); CountText.Text = $"{Findings.Count} 项结果"; SetBusy(false, result.Reason);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
    private void SelectAll_Click(object sender, RoutedEventArgs e) { foreach (var f in Findings.Where(x => !x.Protected && File.Exists(x.Path))) f.IsSelected = true; ResultsGrid.Items.Refresh(); }
    private void ClearSelection_Click(object sender, RoutedEventArgs e) { foreach (var f in Findings) f.IsSelected = false; ResultsGrid.Items.Refresh(); }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        var selected = Findings.Where(x => x.IsSelected).ToList();
        if (selected.Count == 0) { MessageBox.Show("请先选择可处理的文件。", "SafeScan"); return; }
        if (MessageBox.Show($"将 {selected.Count} 个所选项目移入隔离区？原路径会保存到隔离清单。", "确认隔离", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        ProcessSelected(selected, f => _quarantine.Quarantine(f), "已隔离");
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        var selected = Findings.Where(x => x.IsSelected).ToList();
        if (selected.Count == 0) { MessageBox.Show("请先选择可处理的文件。", "SafeScan"); return; }
        if (MessageBox.Show($"永久删除 {selected.Count} 个所选项目？此操作无法从 SafeScan 恢复。建议改用隔离。", "永久删除确认", MessageBoxButton.YesNo, MessageBoxImage.Stop) != MessageBoxResult.Yes) return;
        ProcessSelected(selected, f => { _quarantine.Delete(f); return ""; }, "已删除");
    }

    private void ProcessSelected(IEnumerable<ScanFinding> selected, Func<ScanFinding, string> action, string success)
    {
        var ok = 0; var failed = new List<string>();
        foreach (var f in selected)
        {
            try { action(f); f.Status = success; f.IsSelected = false; ok++; }
            catch (Exception ex) { f.Status = "失败"; failed.Add($"{f.Path}: {ex.Message}"); }
        }
        ResultsGrid.Items.Refresh(); StatusText.Text = $"{success} {ok} 项，失败 {failed.Count} 项。";
        if (failed.Count > 0) MessageBox.Show(string.Join("\n", failed.Take(10)), "部分项目未处理", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "JSON 报告|*.json|CSV 报告|*.csv", FileName = $"SafeScan-report-{DateTime.Now:yyyyMMdd-HHmmss}.json" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            if (Path.GetExtension(dialog.FileName).Equals(".csv", StringComparison.OrdinalIgnoreCase))
            {
                var sb = new StringBuilder("Risk,Kind,Path,Reason,SHA256,Signature,Publisher,Created,Modified,Protected,Status\r\n");
                foreach (var f in Findings) sb.AppendLine(string.Join(',', new[] { f.Risk.ToString(), f.Kind.ToString(), f.Path, f.Reason, f.Sha256, f.SignatureStatus, f.Publisher, f.Created?.ToString("O") ?? "", f.Modified?.ToString("O") ?? "", f.Protected.ToString(), f.Status }.Select(Csv)));
                File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
            }
            else File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(new { GeneratedAt = DateTimeOffset.Now, Machine = Environment.MachineName, Findings }, new JsonSerializerOptions { WriteIndented = true }));
            StatusText.Text = $"报告已导出：{dialog.FileName}";
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "导出失败", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
    private void SetBusy(bool busy, string status) { ScanButton.IsEnabled = DefenderButton.IsEnabled = !busy; CancelButton.IsEnabled = busy; BusyBar.Visibility = busy ? Visibility.Visible : Visibility.Collapsed; StatusText.Text = status; }
}
