using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
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

        private void HelpButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            string imagePath = button.Name == "AutoDhcpHelpButton" ? "client.png" : "server.png";
            var helpDialog = new HelpImageDialog(imagePath);
            helpDialog.Owner = this;
            helpDialog.ShowDialog();
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
                DhcpClientRadio.IsChecked = true;
                
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

        private void NetworkInterfaceCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // 当网络接口改变时，重新检查网络状态
            if (NetworkInterfaceCombo.SelectedItem != null)
            {
                var selectedInterface = NetworkInterfaceCombo.SelectedItem.ToString();
                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (selectedNic != null)
                {
                    LogMessage($"Selected network interface: {selectedInterface}");
                }
            }
        }

        private async Task<string> GetSmcIp()
        {
            try
            {
                LogMessage("[Network] Starting SMC device discovery...");
                string smcIp = await deviceDiscoveryManager.FindSmcDevice();
                
                if (string.IsNullOrEmpty(smcIp))
                {
                    LogMessage("[Network] No SMC device found");
                    MessageBox.Show("No SMC device found. Please check your connection and try again.", 
                                  "Device Not Found", 
                                  MessageBoxButton.OK, 
                                  MessageBoxImage.Warning);
                    return null;
                }

                LogMessage($"[Network] SMC device found at {smcIp}");
                return smcIp;
            }
            catch (Exception ex)
            {
                LogMessage($"[Network] Error during SMC device discovery: {ex.Message}");
                MessageBox.Show($"Error during device discovery: {ex.Message}", 
                              "Error", 
                              MessageBoxButton.OK, 
                              MessageBoxImage.Error);
                return null;
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
            bool isManualDhcp = ManualIpRadio.IsChecked == true;
            
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
            try
            {
                string bmcIp = await DetermineBmcIp(smcIp);
                if (string.IsNullOrEmpty(bmcIp))
                {
                    LogMessage("[Network] Unable to determine BMC IP address");
                    MessageBox.Show("Unable to determine BMC IP address", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                LogMessage($"[Network] BMC IP address: {bmcIp}");

                // Configure SSH forwarding for HTTP and HTTPS
                await SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTP_PORT, REMOTE_HTTP_PORT);
                await SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTPS_PORT, REMOTE_HTTPS_PORT);

                // Verify connections
                await VerifyConnections(true, true);

                OpenBrowserButton.IsEnabled = true;
                LogMessage("[Network] Configuration completed successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"[Network] Error configuring connection: {ex.Message}");
                MessageBox.Show($"Error configuring connection: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task VerifyConnections(bool checkHttp, bool checkHttps)
        {
            var tasks = new List<Task>();

            if (checkHttp)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using (var client = new TcpClient())
                        {
                            await client.ConnectAsync("127.0.0.1", LOCAL_HTTP_PORT);
                            LogMessage($"[Network] HTTP forwarding verified (Port {LOCAL_HTTP_PORT})");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"[Network] HTTP forwarding verification failed: {ex.Message}");
                        throw;
                    }
                }));
            }

            if (checkHttps)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using (var client = new TcpClient())
                        {
                            await client.ConnectAsync("127.0.0.1", LOCAL_HTTPS_PORT);
                            LogMessage($"[Network] HTTPS forwarding verified (Port {LOCAL_HTTPS_PORT})");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"[Network] HTTPS forwarding verification failed: {ex.Message}");
                        throw;
                    }
                }));
            }

            await Task.WhenAll(tasks);
        }

        private void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = $"https://localhost:{LOCAL_HTTPS_PORT}",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogMessage($"[Browser] Failed to open browser: {ex.Message}");
                MessageBox.Show($"Failed to open browser: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task CleanupExistingConnections()
        {
            try
            {
                // Kill any processes using our ports
                KillPortProcess(LOCAL_HTTP_PORT);
                KillPortProcess(LOCAL_HTTPS_PORT);

                // Wait a bit for processes to be killed
                await Task.Delay(1000);

                LogMessage("[Network] Cleaned up existing connections");
            }
            catch (Exception ex)
            {
                LogMessage($"[Network] Warning during connection cleanup: {ex.Message}");
            }
        }

        private void KillPortProcess(int port)
        {
            try
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = $"-ano | findstr :{port}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(processStartInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    foreach (string line in output.Split('\n'))
                    {
                        if (line.Contains($":{port}"))
                        {
                            string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 4 && int.TryParse(parts[4], out int pid))
                            {
                                Process.GetProcessById(pid).Kill();
                                LogMessage($"[Network] Killed process using port {port} (PID: {pid})");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Network] Warning during port cleanup: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"{DateTime.Now:HH:mm:ss.fff} {message}\n");
                LogTextBox.ScrollToEnd();
            });
        }

        protected override async void OnClosed(EventArgs e)
        {
            await CleanupExistingConnections();
            base.OnClosed(e);
        }

        private async Task SetupSshForwarding(string smcIp, string bmcIp, int localPort, int remotePort)
        {
            try
            {
                await sshConnectionManager.SetupSshForwarding(smcIp, bmcIp, localPort, remotePort);
                LogMessage($"[Network] Port forwarding set up: localhost:{localPort} -> {bmcIp}:{remotePort}");
            }
            catch (Exception ex)
            {
                LogMessage($"[Network] Error setting up port forwarding: {ex.Message}");
                throw;
            }
        }

        private async Task WaitForProcessExit(Process process)
        {
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await Task.Run(() => process.WaitForExit());

            if (!string.IsNullOrEmpty(error))
            {
                LogMessage($"Process error output: {error}");
            }
            if (!string.IsNullOrEmpty(output))
            {
                LogMessage($"Process output: {output}");
            }
        }

        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            if (ClearButton.Content.ToString() == "Abort")
            {
                _cancellationTokenSource?.Cancel();
                return;
            }

            try
            {
                ClearButton.IsEnabled = false;
                StartButton.IsEnabled = false;
                OpenBrowserButton.IsEnabled = false;

                await CleanupExistingConnections();
                LogTextBox.Clear();
                LogMessage("[System] Configuration cleared");
            }
            catch (Exception ex)
            {
                LogMessage($"[System] Error during cleanup: {ex.Message}");
                MessageBox.Show($"Error during cleanup: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ClearButton.IsEnabled = true;
                StartButton.IsEnabled = true;
            }
        }

        private async void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            try
            {
                await CleanupExistingConnections();
            }
            catch (Exception ex)
            {
                LogMessage($"[System] Error during cleanup: {ex.Message}");
            }
        }
    }
}