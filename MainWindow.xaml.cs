using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using Renci.SshNet;
using System.Net.Sockets;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Threading;

namespace RemoteBMC
{
    public partial class MainWindow : Window
    {
        private CancellationTokenSource _cancellationTokenSource;
        private const int LOCAL_HTTP_PORT = 8880;
        private const int LOCAL_HTTPS_PORT = 8443;
        private const int REMOTE_HTTP_PORT = 80;
        private const int REMOTE_HTTPS_PORT = 443;

        private List<NetworkInterface> networkInterfaces;
        private DhcpServerManager dhcpManager;
        private NetworkConfigurationManager networkConfigManager;
        private SshConnectionManager sshConnectionManager;
        private DeviceDiscoveryManager deviceDiscoveryManager;

        public MainWindow()
        {
            // 检查是否具有管理员权限
            if (!IsRunAsAdministrator())
            {
                // 如果没有管理员权限，重启程序并请求权限
                RestartAsAdministrator();
                Application.Current.Shutdown();
                return;
            }

            InitializeComponent();
            this.Closing += MainWindow_Closing;
            dhcpManager = new DhcpServerManager(LogMessage);
            networkConfigManager = new NetworkConfigurationManager(LogMessage);
            sshConnectionManager = new SshConnectionManager(LogMessage);
            deviceDiscoveryManager = new DeviceDiscoveryManager(LogMessage);
            LoadNetworkInterfaces();
        }

        private bool IsRunAsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void RestartAsAdministrator()
        {
            try
            {
                // Get current executable path
                var exePath = Process.GetCurrentProcess().MainModule.FileName;
                
                // Create startup info
                var startInfo = new ProcessStartInfo
                {
                    UseShellExecute = true,
                    WorkingDirectory = Environment.CurrentDirectory,
                    FileName = exePath,
                    Verb = "runas" // This will trigger UAC prompt
                };

                // Start new process
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Unable to restart with administrator privileges: {ex.Message}\n\nPlease run the program manually as administrator.", 
                              "Permission Error", 
                              MessageBoxButton.OK, 
                              MessageBoxImage.Error);
            }
        }

        private void LoadNetworkInterfaces()
        {
            RefreshNetworkInterfaces();
        }

        private void RefreshNetworkInterfaces()
        {
            try
            {
                string previouslySelectedInterface = NetworkInterfaceCombo.SelectedItem?.ToString();
                NetworkInterfaceCombo.Items.Clear();
                
                networkInterfaces = networkConfigManager.GetNetworkInterfaces();

                foreach (var ni in networkInterfaces)
                {
                    NetworkInterfaceCombo.Items.Add(ni.Name);
                }

                if (!string.IsNullOrEmpty(previouslySelectedInterface))
                {
                    int index = NetworkInterfaceCombo.Items.IndexOf(previouslySelectedInterface);
                    if (index >= 0)
                    {
                        NetworkInterfaceCombo.SelectedIndex = index;
                    }
                    else if (NetworkInterfaceCombo.Items.Count > 0)
                    {
                        NetworkInterfaceCombo.SelectedIndex = 0;
                    }
                }
                else if (NetworkInterfaceCombo.Items.Count > 0)
                {
                    NetworkInterfaceCombo.SelectedIndex = 0;
                }

                LogMessage("Network interfaces refreshed");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to refresh network interfaces: {ex.Message}");
                MessageBox.Show($"Failed to refresh network interfaces: {ex.Message}", 
                               "Error", 
                               MessageBoxButton.OK, 
                               MessageBoxImage.Error);
            }
        }

        private void RefreshInterfacesButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshNetworkInterfaces();
        }

        private async void ClearIpConfigButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedInterface = NetworkInterfaceCombo.SelectedItem?.ToString();
                if (string.IsNullOrEmpty(selectedInterface))
                {
                    MessageBox.Show("Please select a network interface", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (selectedNic == null)
                {
                    MessageBox.Show("Selected network interface not found", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // 设置为DHCP客户端模式
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"interface ip set address \"{selectedInterface}\" dhcp",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);
                
                LogMessage("Network interface has been set to DHCP client mode");
                AutoDhcpRadio.IsChecked = true;
                
                // 刷新网络接口状态
                RefreshNetworkInterfaces();
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to clear IP configuration: {ex.Message}");
                MessageBox.Show($"Failed to clear IP configuration: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StartButton.IsEnabled = false;
                ClearButton.Content = "Abort";
                ClearButton.IsEnabled = true;
                OpenBrowserButton.IsEnabled = false;
                
                _cancellationTokenSource = new CancellationTokenSource();

                // Clean up existing connections
                await CleanupExistingConnections();
                LogTextBox.Clear();

                if (NetworkInterfaceCombo.SelectedItem == null)
                {
                    MessageBox.Show("Please select a network interface", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // 只在用户选择作为DHCP服务器模式时检查DHCP状态
                if (ManualDhcpRadio.IsChecked == true)
                {
                    var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == NetworkInterfaceCombo.SelectedItem.ToString());
                    if (selectedNic != null)
                    {
                        bool hasIpFromDhcp;
                        if (dhcpManager.IsInterfaceUsingDhcp(selectedNic, out hasIpFromDhcp) && hasIpFromDhcp)
                        {
                            LogMessage($"Warning: Selected interface {selectedNic.Name} is using DHCP and has a valid IP address");
                            MessageBox.Show(
                                "The selected network interface is currently using DHCP and has a valid IP address.\n" +
                                "To avoid conflicts, you cannot run as DHCP server on this interface.\n" +
                                "Please either:\n" +
                                "1. Select a different network interface\n" +
                                "2. Change the interface to use static IP\n",
                                "DHCP Configuration Warning",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                            return;
                        }
                    }
                }

                string smcIp = await GetSmcIp();
                if (string.IsNullOrEmpty(smcIp))
                {
                    return;
                }

                await ConfigureConnection(smcIp);
            }
            catch (Exception ex)
            {
                LogMessage($"Error occurred: {ex.Message}");
                MessageBox.Show($"Configuration error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartButton.IsEnabled = true;
                ClearButton.Content = "Clear Configuration";
                ClearButton.IsEnabled = true;
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
        }

        private void ManualDhcpRadio_Checked(object sender, RoutedEventArgs e)
        {
            // First check if required files exist
            string exePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dhcpsrv.exe");
            string iniPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dhcpsrv.ini");

            if (!System.IO.File.Exists(exePath) || !System.IO.File.Exists(iniPath))
            {
                LogMessage("Required DHCP server files are missing");
                MessageBox.Show(
                    "Required files are missing:\n" +
                    (!System.IO.File.Exists(exePath) ? "- dhcpsrv.exe\n" : "") +
                    (!System.IO.File.Exists(iniPath) ? "- dhcpsrv.ini\n" : "") +
                    "\nPlease ensure these files are in the same directory as the application.",
                    "Missing Files",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                
                // Switch back to Auto DHCP mode
                AutoDhcpRadio.IsChecked = true;
                return;
            }

            if (NetworkInterfaceCombo.SelectedItem != null)
            {
                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == NetworkInterfaceCombo.SelectedItem.ToString());
                if (selectedNic != null)
                {
                    bool hasIpFromDhcp;
                    if (dhcpManager.IsInterfaceUsingDhcp(selectedNic, out hasIpFromDhcp) && hasIpFromDhcp)
                    {
                        LogMessage($"Warning: Selected interface {selectedNic.Name} is using DHCP and has a valid IP address");
                        MessageBox.Show(
                            "The selected network interface is currently using DHCP and has a valid IP address.\n" +
                            "To avoid conflicts, you cannot run as DHCP server on this interface.\n" +
                            "Please either:\n" +
                            "1. Select a different network interface\n" +
                            "2. Change the interface to use static IP\n",
                            "DHCP Configuration Warning",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                        
                        // Switch back to Auto DHCP mode and disable Manual DHCP mode
                        AutoDhcpRadio.IsChecked = true;
                        ManualDhcpRadio.IsEnabled = false;
                    }
                    else
                    {
                        // If no DHCP conflict, ensure the radio button is enabled
                        ManualDhcpRadio.IsEnabled = true;
                    }
                }
            }
        }

        private void NetworkInterfaceCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            // Re-enable Manual DHCP mode when interface changes
            ManualDhcpRadio.IsEnabled = true;
            
            // If Manual DHCP is selected, check DHCP status for the new interface
            if (ManualDhcpRadio.IsChecked == true)
            {
                ManualDhcpRadio_Checked(sender, new RoutedEventArgs());
            }
        }

        private async Task<string> GetSmcIp()
        {
            string selectedInterface = NetworkInterfaceCombo.SelectedItem.ToString();
            var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);

            if (ManualIpRadio.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(SmcIpTextBox.Text))
                {
                    MessageBox.Show("Please enter SMC IP address", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return null;
                }
                return SmcIpTextBox.Text;
            }
            else if (AutoDhcpRadio.IsChecked == true)
            {
                LogMessage("Starting SMC device search...");
                string smcIp = await GetDhcpAssignedClientIp();
                if (string.IsNullOrEmpty(smcIp))
                {
                    LogMessage("Unable to find SMC device");
                    return null;
                }
                LogMessage($"Found SMC device, IP address: {smcIp}");
                return smcIp;
            }
            else // ManualDhcpRadio.IsChecked == true
            {
                LogMessage("Configuring network interface...");
                try
                {
                    // Save current network configuration
                    SaveNetworkConfiguration(selectedInterface);

                    // 如果当前是静态IP，先尝试DHCP模式
                    var ipv4Properties = selectedNic.GetIPProperties().GetIPv4Properties();
                    var ipAddress = selectedNic.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);
                    
                    if (!ipv4Properties.IsDhcpEnabled && ipAddress != null && ipAddress.Address.ToString() != "10.10.20.1")
                    {
                        LogMessage("Interface is using static IP, trying DHCP client mode first...");
                        
                        // 设置为DHCP客户端模式
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "netsh",
                                Arguments = $"interface ip set address \"{selectedInterface}\" dhcp",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true,
                                Verb = "runas"
                            }
                        };
                        
                        process.Start();
                        await WaitForProcessExit(process);
                        
                        // 等待一段时间看是否能获取到IP
                        LogMessage("Waiting for DHCP IP assignment...(Waiting for 10s)");
                        await Task.Delay(10000); // 等待10秒

                        // 检查是否获取到了IP
                        var newIpAddress = selectedNic.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                        if (newIpAddress != null && !newIpAddress.Address.ToString().StartsWith("169.254"))
                        {
                            LogMessage($"Obtained IP from DHCP: {newIpAddress.Address}");
                            MessageBox.Show(
                                "The network interface obtained an IP address from an existing DHCP server.\n" +
                                "To avoid conflicts, you cannot run as DHCP server on this interface.\n" +
                                "Please join the sub-net and use the \"As DHCP Client\" mode.",
                                "DHCP Configuration Warning",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                            
                            await RestoreNetworkConfiguration();
                            return null;
                        }
                        else
                        {
                            LogMessage("No valid IP obtained from DHCP, proceeding with DHCP server setup");
                        }
                    }

                    // Configure network interface IP address
                    if (!await dhcpManager.ConfigureInterface(selectedInterface))
                    {
                        await RestoreNetworkConfiguration();
                        return null;
                    }

                    await Task.Delay(2000); // Wait for network configuration to take effect

                    // Check for other DHCP servers
                    bool hasDhcpServer = await dhcpManager.CheckExistingDhcpServer(selectedNic);
                    if (hasDhcpServer)
                    {
                        await RestoreNetworkConfiguration();
                        return null;
                    }

                    LogMessage("Starting DHCP server...");
                    await dhcpManager.StartDhcpServer();
                    
                    // 尝试刺激SMC进行DHCP请求
                    await dhcpManager.StimulateSmcDhcpRequest(selectedInterface);
                    
                    // Wait for DHCP server to assign IP
                    LogMessage("Waiting for SMC to obtain IP address...");
                    try {
                        await Task.Delay(20000, _cancellationTokenSource.Token); // Wait 20 seconds
                    } catch (OperationCanceledException) {
                        LogMessage("Operation cancelled by user");
                        await dhcpManager.StopDhcpServer();
                        await RestoreNetworkConfiguration();
                        return null;
                    }

                    // Search for SMC device in subnet
                    var smcIp = await GetDhcpAssignedClientIp();
                    
                    // If first search fails, try stimulating DHCP request again
                    if (string.IsNullOrEmpty(smcIp))
                    {
                        LogMessage("First search found no device, retrying...");
                        await dhcpManager.StimulateSmcDhcpRequest(selectedInterface);
                        try {
                            await Task.Delay(20000, _cancellationTokenSource.Token); // Wait another 20 seconds
                        } catch (OperationCanceledException) {
                            LogMessage("Operation cancelled by user");
                            await dhcpManager.StopDhcpServer();
                            await RestoreNetworkConfiguration();
                            return null;
                        }
                        smcIp = await GetDhcpAssignedClientIp();
                    }

                    if (string.IsNullOrEmpty(smcIp))
                    {
                        LogMessage("Unable to find SMC device");
                        await dhcpManager.StopDhcpServer();
                        await RestoreNetworkConfiguration();
                        return null;
                    }

                    return smcIp;
                }
                catch (Exception ex)
                {
                    LogMessage($"Error configuring network interface: {ex.Message}");
                    MessageBox.Show($"Error configuring network interface: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    await RestoreNetworkConfiguration();
                    return null;
                }
            }
        }

        private string GetLocalIpAddress(string interfaceName)
        {
            try
            {
                var networkInterface = networkInterfaces.FirstOrDefault(ni => ni.Name == interfaceName);
                if (networkInterface != null)
                {
                    var ipProperties = networkInterface.GetIPProperties();
                    var ipAddress = ipProperties.UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);
                    
                    if (ipAddress != null)
                    {
                        return ipAddress.Address.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to get local IP address: {ex.Message}");
            }
            return null;
        }

        private async Task<string> GetDhcpAssignedClientIp()
        {
            string selectedInterface = NetworkInterfaceCombo.SelectedItem.ToString();
            bool isManualDhcp = ManualDhcpRadio.IsChecked == true;
            
            var smcIp = await deviceDiscoveryManager.GetDhcpAssignedClientIp(selectedInterface, networkInterfaces, isManualDhcp);
            
            if (!string.IsNullOrEmpty(smcIp))
            {
                Dispatcher.Invoke(() => SmcIpTextBox.Text = smcIp);
            }
            
            return smcIp;
        }

        private async Task<string> DetermineBmcIp(string smcIp)
        {
            return await deviceDiscoveryManager.DetermineBmcIp(smcIp);
        }

        private async Task ConfigureConnection(string smcIp)
        {
            string bmcIp = await DetermineBmcIp(smcIp);
            
            if (string.IsNullOrEmpty(bmcIp))
            {
                LogMessage("Unable to determine available management interface address");
                return;
            }

            LogMessage($"[Debug] Using BMC IP: {bmcIp}");

            try
            {
                await sshConnectionManager.SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTP_PORT, REMOTE_HTTP_PORT);
                await sshConnectionManager.SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTPS_PORT, REMOTE_HTTPS_PORT);

                OpenBrowserButton.IsEnabled = true;
                StartButton.Content = "Reconfigure";
                LogMessage("Port forwarding is set up, BMC interface is accessible");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to set up port forwarding: {ex.Message}");
                MessageBox.Show($"Failed to set up port forwarding: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task VerifyConnections(bool checkHttp, bool checkHttps)
        {
            LogMessage("Verifying connections...");

            // Give SSH connections more time to establish
            await Task.Delay(10000);
            
            if (checkHttp)
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        var connectTask = client.ConnectAsync("127.0.0.1", LOCAL_HTTP_PORT);
                        if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask)
                        {
                            LogMessage($"Port {LOCAL_HTTP_PORT} connection successful");
                        }
                        else
                        {
                            LogMessage($"Port {LOCAL_HTTP_PORT} connection timeout");
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Port {LOCAL_HTTP_PORT} connection failed: {ex.Message}");
                }
            }

            if (checkHttps)
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        var connectTask = client.ConnectAsync("127.0.0.1", LOCAL_HTTPS_PORT);
                        if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask)
                        {
                            LogMessage($"Port {LOCAL_HTTPS_PORT} connection successful");
                        }
                        else
                        {
                            LogMessage($"Port {LOCAL_HTTPS_PORT} connection timeout");
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Port {LOCAL_HTTPS_PORT} connection failed: {ex.Message}");
                }
            }

            // Enable browser button regardless of port verification results
            LogMessage("Port forwarding setup complete, you can now try to access the BMC interface");
            OpenBrowserButton.IsEnabled = true;
        }

        private void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Open BMC interface in system default browser
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://127.0.0.1:8443",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to open browser: {ex.Message}");
                MessageBox.Show("Failed to open browser, please manually visit https://127.0.0.1:8443", 
                              "Error", 
                              MessageBoxButton.OK, 
                              MessageBoxImage.Error);
            }
        }

        private async Task CleanupExistingConnections()
        {
            LogMessage("Cleaning up existing connections...");

            // 1. Clean up SSH connections and port forwarding
            await sshConnectionManager.CleanupConnections();

            // 2. Kill processes using ports
            await sshConnectionManager.KillPortProcess(LOCAL_HTTP_PORT);
            await sshConnectionManager.KillPortProcess(LOCAL_HTTPS_PORT);

            // 3. Stop DHCP server if running
            try
            {
                await dhcpManager.StopDhcpServer();
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping DHCP server: {ex.Message}");
            }

            // 4. Restore network configuration if previously configured
            await networkConfigManager.RestoreNetworkConfiguration();

            LogMessage("Cleanup complete");
        }

        private void KillPortProcess(int port)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :{port}') do taskkill /F /PID %a",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                var process = Process.Start(processInfo);
                process.WaitForExit();
            }
            catch (Exception ex)
            {
                LogMessage($"Error terminating process on port {port}: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => LogMessage(message));
                return;
            }

            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            LogTextBox.ScrollToEnd();
        }

        protected override async void OnClosed(EventArgs e)
        {
            await RestoreNetworkConfiguration(); // Restore network configuration when program closes
            await CleanupExistingConnections();
            base.OnClosed(e);
        }

        private void SetupSshForwarding(string smcIp, string bmcIp, int localPort, int remotePort)
        {
            LogMessage($"Setting up port forwarding: Local {localPort} -> Remote {remotePort}");

            // First check if local port is already in use
            try
            {
                var listener = new TcpListener(IPAddress.Loopback, localPort);
                listener.Start();
                listener.Stop();
            }
            catch (SocketException)
            {
                LogMessage($"Port {localPort} is in use, attempting to terminate existing connection");
                KillPortProcess(localPort);
            }

            try
            {
// 需要将方法声明改为 private async void SetupSshForwarding
                sshConnectionManager.SetupSshForwarding(smcIp, bmcIp, localPort, remotePort).Wait();
                LogMessage($"SSH connection and port forwarding established: {localPort} -> {remotePort}");

                // Monitor connection status
                
                {
                    try
                    {
                        while (sshConnectionManager.IsConnected)
                        {
                            Task.Delay(1000).Wait();
                        }
                        LogMessage($"SSH connection disconnected: {localPort} -> {remotePort}");
                    }
                    catch
                    {
                        // Ignore exceptions
                    }
                } 
            }
            catch (Exception ex)
            {
                LogMessage($"Error setting up SSH forwarding: {ex.Message}");
            }
        }

        private void SaveNetworkConfiguration(string interfaceName)
        {
            networkConfigManager.SaveNetworkConfiguration(interfaceName);
        }

        private async Task RestoreNetworkConfiguration()
        {
            await networkConfigManager.RestoreNetworkConfiguration();
        }

        private async Task WaitForProcessExit(Process process)
        {
            var tcs = new TaskCompletionSource<bool>();
            process.EnableRaisingEvents = true;
            process.Exited += (sender, args) => tcs.TrySetResult(true);
            if (process.HasExited) return;
            await tcs.Task;
        }

        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_cancellationTokenSource != null)
                {
                    // 如果正在执行操作，则中止操作
                    _cancellationTokenSource.Cancel();
                    LogMessage("Operation aborted by user");
                    return;
                }

                ClearButton.IsEnabled = false;
                LogMessage("Starting configuration cleanup...");

                // Clean up existing connections
                await CleanupExistingConnections();

                // Reset UI state
                OpenBrowserButton.IsEnabled = false;
                StartButton.Content = "Start Configuration";
                LogTextBox.Clear();
                LogMessage("Configuration cleared successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Error during cleanup: {ex.Message}");
                MessageBox.Show($"Error during cleanup: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ClearButton.IsEnabled = true;
            }
        }

        private async void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            try
            {
                // 防止窗口立即关闭，等待清理完成
                e.Cancel = true;
                
                // 显示等待提示
                LogMessage("Cleaning up before exit...");
                IsEnabled = false; // 禁用窗口输入
                
                // 执行清理操作
                await CleanupExistingConnections();
                
                // 确保程序真正退出
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                LogMessage($"Error during cleanup: {ex.Message}");
                // 发生错误时仍然允许程序退出
                Application.Current.Shutdown();
            }
        }
    }
}