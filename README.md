# SafeScan

SafeScan 是一个 Windows 本地安全排查 MVP，面向信息窃取木马、Chrome/Edge 凭据盗取后的文件与持久化项复核。

扫描重点包括浏览器密码风险、具有键盘监听 API 特征的可疑程序、用户目录中的未签名运行进程、用户可写目录启动的 Windows 服务以及常见持久化项。OneDrive、WPS Cloud Files、WPSDrive 等网盘同步目录会被跳过。

## 安全边界

- 启发式结果不是恶意软件确诊；请结合 Microsoft Defender 或专业事件响应复核。
- 扫描不会自动修改系统。隔离或删除必须由用户勾选并再次确认。
- Windows、Program Files 与 Microsoft 签名文件被强制保护，不能通过界面处理。
- 注册表项、计划任务和浏览器扩展仅展示，不会被本工具直接删除。
- 浏览器密码数据库只检查是否存在，不读取密码内容，也不允许删除。
- 本机扫描不能证明密码是否已被上传或出现在外部泄露库；若曾确认中毒，应在可信设备上更换密码、撤销会话并启用双重验证。
- 隔离文件保存于 `%LOCALAPPDATA%\SafeScan\Quarantine`，并附原路径与哈希清单。

## 构建

```powershell
dotnet build SafeScan\SafeScan.csproj -c Release
dotnet publish SafeScan\SafeScan.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o outputs\publish
Compress-Archive outputs\publish\* outputs\SafeScan-win-x64-publish.zip
```

建议以普通用户身份运行；读取部分系统级注册表项可能受权限限制。Defender 按钮调用 Windows 自带的 `MpCmdRun.exe`。
