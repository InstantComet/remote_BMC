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
        private const string SSH_PASSWORD = "remora";
        private const int LOCAL_HTTP_PORT = 8880;
        private const int LOCAL_HTTPS_PORT = 8443;
        private const int REMOTE_HTTP_PORT = 80;
        private const int REMOTE_HTTPS_PORT = 443;
        private const int SSH_PORT = 22;
        private string[] BMC_IPS = new[] { "172.31.250.11", "172.31.240.11" };

        private List<NetworkInterface> networkInterfaces;
        private List<Process> sshProcesses = new List<Process>();
        private List<SshClient> activeSshClients = new List<SshClient>();
        private List<ForwardedPortLocal> activeForwardedPorts = new List<ForwardedPortLocal>();
        
        // 添加保存原始网络配置的变量
        private string originalIpAddress;
        private string originalSubnetMask;
        private string originalGateway;
        private string lastConfiguredInterface;
        private bool originalIsDhcp;

        private DhcpServerManager dhcpManager;

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
            dhcpManager = new DhcpServerManager(LogMessage);
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
                // Store the currently selected interface name
                string previouslySelectedInterface = NetworkInterfaceCombo.SelectedItem?.ToString();
                
                // Clear existing items
                NetworkInterfaceCombo.Items.Clear();
                
                // Refresh the network interfaces list
                networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                           ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();

                foreach (var ni in networkInterfaces)
                {
                    NetworkInterfaceCombo.Items.Add(ni.Name);
                }

                // Try to reselect the previously selected interface
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

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StartButton.IsEnabled = false;
                ClearButton.IsEnabled = false;
                OpenBrowserButton.IsEnabled = false;

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
                ClearButton.IsEnabled = true;
            }
        }

        private void NetworkInterfaceCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (NetworkInterfaceCombo.SelectedItem != null)
            {
                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == NetworkInterfaceCombo.SelectedItem.ToString());
                if (selectedNic != null)
                {
                    bool hasIpFromDhcp;
                    if (dhcpManager.IsInterfaceUsingDhcp(selectedNic, out hasIpFromDhcp))
                    {
                        if (hasIpFromDhcp)
                        {
                            LogMessage($"Warning: Selected interface {selectedNic.Name} is using DHCP and has a valid IP address");
                            ManualDhcpRadio.IsEnabled = false;
                            if (ManualDhcpRadio.IsChecked == true)
                            {
                                AutoDhcpRadio.IsChecked = true;
                            }
                            MessageBox.Show(
                                "The selected network interface is currently using DHCP and has a valid IP address.\n" +
                                "To avoid conflicts, you cannot run as DHCP server on this interface.\n" +
                                "Please either:\n" +
                                "1. Select a different network interface\n" +
                                "2. Change the interface to use static IP\n",
                                "DHCP Configuration Warning",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                        }
                        else
                        {
                            // 检查是否有IP地址
                            var ipAddress = selectedNic.GetIPProperties().UnicastAddresses
                                .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);
                            
                            if (ipAddress != null && ipAddress.Address.ToString().StartsWith("169.254"))
                            {
                                LogMessage($"Note: Selected interface {selectedNic.Name} has an APIPA address, can be used as DHCP server");
                                ManualDhcpRadio.IsEnabled = true;
                            }
                            else
                            {
                                LogMessage($"Note: Selected interface {selectedNic.Name} is set to use DHCP but has no IP address");
                                ManualDhcpRadio.IsEnabled = true;
                            }
                        }
                    }
                    else
                    {
                        ManualDhcpRadio.IsEnabled = true;
                    }
                }
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
                    if (!ipv4Properties.IsDhcpEnabled)
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
                    if (await dhcpManager.CheckExistingDhcpServer(selectedNic))
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
                    await Task.Delay(30000); // Wait 30 seconds

                    // Search for SMC device in subnet
                    var smcIp = await GetDhcpAssignedClientIp();
                    
                    // If first search fails, try stimulating DHCP request again
                    if (string.IsNullOrEmpty(smcIp))
                    {
                        LogMessage("First search found no device, retrying...");
                        await dhcpManager.StimulateSmcDhcpRequest(selectedInterface);
                        await Task.Delay(30000); // Wait another 30 seconds
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
            LogMessage("[DHCP] Starting SMC device search...");
            
            try
            {
                // 1. Get current selected network interface
                string selectedInterface = NetworkInterfaceCombo.SelectedItem.ToString();
                var networkInterface = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (networkInterface == null)
                {
                    LogMessage("[DHCP] Unable to get selected network interface");
                    return null;
                }

                // 2. Determine search range based on mode
                List<string> ipAddressesToScan = new List<string>();
                
                if (ManualDhcpRadio.IsChecked == true)
                {
                    // 如果是DHCP服务器模式，从DHCP池中扫描
                    LogMessage("[DHCP] Scanning DHCP pool range (10.10.20.100-10.10.20.200)");
                    for (int i = 100; i <= 200; i++)
                    {
                        ipAddressesToScan.Add($"10.10.20.{i}");
                    }
                }
                else
                {
                    // 如果是自动检测模式，从当前子网扫描
                    var ipProperties = networkInterface.GetIPProperties();
                    var ipAddress = ipProperties.UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);
                    
                    if (ipAddress == null)
                    {
                        LogMessage("[DHCP] Unable to get network interface IP address");
                        return null;
                    }

                    string localIp = ipAddress.Address.ToString();
                    string subnetMask = ipAddress.IPv4Mask.ToString();
                    LogMessage($"[DHCP] Local IP: {localIp}, Subnet Mask: {subnetMask}");

                    // Calculate subnet range
                    var ipParts = localIp.Split('.');
                    var maskParts = subnetMask.Split('.');
                    var networkParts = new int[4];
                    for (int i = 0; i < 4; i++)
                    {
                        networkParts[i] = int.Parse(ipParts[i]) & int.Parse(maskParts[i]);
                    }

                    // Add all addresses in subnet to scan list
                    for (int i = 1; i < 255; i++)
                    {
                        ipAddressesToScan.Add($"{networkParts[0]}.{networkParts[1]}.{networkParts[2]}.{i}");
                    }
                }

                // 3. Parallel scan of IP addresses
                LogMessage($"[DHCP] Starting scan of {ipAddressesToScan.Count} addresses...");
                var deviceList = new List<(string ip, bool isAlive)>();
                var tasks = new List<Task>();
                var lockObj = new object();

                foreach (string ip in ipAddressesToScan)
                {
                    var task = Task.Run(async () =>
                    {
                        try
                        {
                            using (var tcpClient = new TcpClient())
                            {
                                var connectTask = tcpClient.ConnectAsync(ip, SSH_PORT);
                                if (await Task.WhenAny(connectTask, Task.Delay(200)) == connectTask)
                                {
                                    lock (lockObj)
                                    {
                                        deviceList.Add((ip, true));
                                        LogMessage($"[DHCP] Device found: {ip} (SSH port open)");
                                    }
                                }
                            }
                        }
                        catch
                        {
                            // If SSH port is not open, try ping
                            try
                            {
                                using (var ping = new Ping())
                                {
                                    var reply = await ping.SendPingAsync(ip, 200);
                                    if (reply.Status == IPStatus.Success)
                                    {
                                        lock (lockObj)
                                        {
                                            deviceList.Add((ip, false));
                                            LogMessage($"[DHCP] Device found: {ip} (Ping successful)");
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    });
                    tasks.Add(task);
                }

                await Task.WhenAll(tasks);
                LogMessage($"[DHCP] Scan complete, found {deviceList.Count} devices");

                // 4. Try SSH connection to discovered devices
                LogMessage("[DHCP] Starting device verification...");
                var smcDevices = new List<(string ip, string mac, string info)>();

                // Check devices with open SSH ports first
                foreach (var device in deviceList.OrderByDescending(d => d.isAlive))
                {
                    LogMessage($"[DHCP] Checking {device.ip}...");
                    try
                    {
                        using (var sshClient = new SshClient(device.ip, "root", SSH_PASSWORD))
                        {
                            sshClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(2);
                            try
                            {
                                await Task.Run(() => sshClient.Connect());
                                
                                // Execute commands to verify SMC device
                                var command = sshClient.CreateCommand("uname -a");
                                string result = command.Execute();

                                // Get more device information
                                var hostnameCmd = sshClient.CreateCommand("hostname");
                                string hostname = hostnameCmd.Execute().Trim();

                                var uptimeCmd = sshClient.CreateCommand("uptime");
                                string uptime = uptimeCmd.Execute().Trim();

                                // Try to get MAC address using different methods
                                string mac = "Unknown";
                                try
                                {
                                    // First get all network interfaces
                                    var ifconfigCmd = sshClient.CreateCommand("ifconfig -a");
                                    string ifconfigOutput = ifconfigCmd.Execute().Trim();

                                    if (string.IsNullOrEmpty(ifconfigOutput))
                                    {
                                        // If ifconfig not available, try ip command
                                        var ipCmd = sshClient.CreateCommand("ip link show");
                                        ifconfigOutput = ipCmd.Execute().Trim();
                                    }

                                    if (!string.IsNullOrEmpty(ifconfigOutput))
                                    {
                                        // Try different regex patterns based on command output
                                        var patterns = new[]
                                        {
                                            @"HWaddr\s+([0-9A-Fa-f:]{17})",         // Traditional ifconfig format
                                            @"ether\s+([0-9a-fA-F:]{17})",          // Modern ifconfig format
                                            @"link/ether\s+([0-9a-fA-F:]{17})"      // ip command format
                                        };

                                        foreach (var pattern in patterns)
                                        {
                                            var match = System.Text.RegularExpressions.Regex.Match(ifconfigOutput, pattern);
                                            if (match.Success)
                                            {
                                                mac = match.Groups[1].Value.ToUpper();
                                                break;
                                            }
                                        }

                                        // If still unknown, try another method
                                        if (mac == "Unknown")
                                        {
                                            // Try to find MAC from /sys/class/net
                                            var findMacCmd = sshClient.CreateCommand("cat /sys/class/net/*/address | head -n 1");
                                            string macFromSys = findMacCmd.Execute().Trim();
                                            if (!string.IsNullOrEmpty(macFromSys) && macFromSys.Length == 17)
                                            {
                                                mac = macFromSys.ToUpper();
                                            }
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    LogMessage($"[DHCP] Error getting MAC address: {ex.Message}");
                                }

                                // Check if output contains SMC characteristics
                                if (result.Contains("SMC") || result.Contains("smc"))
                                {
                                    string deviceInfo = $"Hostname: {hostname}\nMAC Address: {mac}\nUptime: {uptime}";
                                    smcDevices.Add((device.ip, mac, deviceInfo));
                                    LogMessage($"[DHCP] SMC device found: {device.ip}");
                                    LogMessage($"[DHCP] Device information:\n{deviceInfo}");
                                }
                                
                                sshClient.Disconnect();
                            }
                            catch
                            {
                                // SSH connection failed, continue to next device
                                continue;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"[DHCP] Error checking device {device.ip}: {ex.Message}");
                        continue;
                    }
                }

                if (smcDevices.Count == 0)
                {
                    LogMessage("[DHCP] No SMC devices found");
                    return null;
                }

                // 5. Let user select device if multiple found
                LogMessage($"[DHCP] Found {smcDevices.Count} SMC devices");
                var options = new List<string>();
                foreach (var device in smcDevices)
                {
                    options.Add($"IP: {device.ip}\nMAC: {device.mac}\n{device.info}");
                }

                var dialog = new SelectDeviceDialog(options);
                if (dialog.ShowDialog() == true)
                {
                    var selectedDevice = smcDevices[dialog.SelectedIndex];
                    LogMessage($"[DHCP] User selected device: {selectedDevice.ip}");
                    // Update IP address input box
                    Dispatcher.Invoke(() => SmcIpTextBox.Text = selectedDevice.ip);
                    return selectedDevice.ip;
                }

                LogMessage("[DHCP] User cancelled device selection");
                return null;
            }
            catch (Exception ex)
            {
                LogMessage($"[DHCP] Error during search process: {ex.Message}");
                return null;
            }
        }

        private async Task<string> DetermineBmcIp(string smcIp)
        {
            LogMessage($"[Debug] Testing management interface connectivity");
            
            try
            {
                // First test if SMC can be pinged
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(smcIp, 500);
                    if (reply.Status != IPStatus.Success)
                    {
                        LogMessage($"Cannot connect to SMC, please verify IP address");
                        return null;
                    }
                }

                // Establish SSH connection
                using (var client = new SshClient(smcIp, "root", SSH_PASSWORD))
                {
                    try
                    {
                        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(5);
                        await Task.Run(() => client.Connect());
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"SSH connection failed: {ex.Message}");
                        return null;
                    }

                    foreach (string ip in BMC_IPS)
                    {
                        LogMessage($"[Debug] Testing {ip}");
                        try
                        {
                            // Use timeout parameter
                            var pingCmd = client.CreateCommand($"ping -c 1 -W 1 {ip}");
                            
                            // Create cancellation token
                            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
                            {
                                try
                                {
                                    var pingTask = Task.Run(() => pingCmd.Execute(), cts.Token);
                                    var result = await pingTask;

                                    if (pingCmd.ExitStatus == 0)
                                    {
                                        LogMessage($"[Debug] Successfully pinged BMC IP: {ip}");
                                        return ip;
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    LogMessage($"[Debug] {ip} test timeout, trying next");
                                    continue;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            LogMessage($"[Debug] Error testing {ip}: {ex.Message}");
                        }
                    }

                    client.Disconnect();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Debug] Connectivity test error: {ex.Message}");
            }

            LogMessage("All management interface IPs are unreachable");
            return null;
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

            // Setup SSH port forwarding
            await Task.Run(() =>
            {
                SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTP_PORT, REMOTE_HTTP_PORT);
                SetupSshForwarding(smcIp, bmcIp, LOCAL_HTTPS_PORT, REMOTE_HTTPS_PORT);
            });

            // Enable browser button and change start button text
            OpenBrowserButton.IsEnabled = true;
            StartButton.Content = "Reconfigure";
            LogMessage("Port forwarding is set up, BMC interface is accessible");
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

            // 1. Stop all port forwarding
            foreach (var port in activeForwardedPorts)
            {
                try
                {
                    if (port.IsStarted)
                    {
                        port.Stop();
                        LogMessage($"Stopped port forwarding on port {port.BoundPort}");
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Error stopping port forward: {ex.Message}");
                }
            }
            activeForwardedPorts.Clear();

            // 2. Disconnect all SSH connections
            foreach (var client in activeSshClients)
            {
                try
                {
                    if (client.IsConnected)
                    {
                        client.Disconnect();
                        LogMessage("Disconnected SSH client");
                    }
                    client.Dispose();
                }
                catch (Exception ex)
                {
                    LogMessage($"Error disconnecting SSH: {ex.Message}");
                }
            }
            activeSshClients.Clear();

            // 3. Kill processes using ports
            KillPortProcess(LOCAL_HTTP_PORT);
            KillPortProcess(LOCAL_HTTPS_PORT);

            // 4. Stop DHCP server if running
            try
            {
                await dhcpManager.StopDhcpServer();
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping DHCP server: {ex.Message}");
            }

            // 5. Restore network configuration if previously configured
            await RestoreNetworkConfiguration();

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
                var forwardedPort = new ForwardedPortLocal("127.0.0.1", (uint)localPort, bmcIp, (uint)remotePort);
                var client = new SshClient(smcIp, "root", SSH_PASSWORD);
                
                client.Connect();
                LogMessage($"SSH connection established");
                
                client.AddForwardedPort(forwardedPort);
                forwardedPort.Start();
                LogMessage($"Port forwarding started: {localPort} -> {remotePort}");

                // Save client and forwardedPort for cleanup
                activeSshClients.Add(client);
                activeForwardedPorts.Add(forwardedPort);

                // Monitor connection status
                Task.Run(() =>
                {
                    try
                    {
                        while (client.IsConnected)
                        {
                            Task.Delay(1000).Wait();
                        }
                        LogMessage($"SSH connection disconnected: {localPort} -> {remotePort}");
                    }
                    catch
                    {
                        // Ignore exceptions
                    }
                });
            }
            catch (Exception ex)
            {
                LogMessage($"Error setting up SSH forwarding: {ex.Message}");
            }
        }

        private void SaveNetworkConfiguration(string interfaceName)
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
                        // Check if DHCP mode
                        originalIsDhcp = networkInterface.GetIPProperties().GetIPv4Properties().IsDhcpEnabled;
                        
                        originalIpAddress = ipAddress.Address.ToString();
                        originalSubnetMask = ipAddress.IPv4Mask.ToString();
                        
                        // Save default gateway
                        var gateway = ipProperties.GatewayAddresses
                            .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                        originalGateway = gateway?.Address.ToString();
                        
                        lastConfiguredInterface = interfaceName;
                        
                        LogMessage("[Network Config] Original configuration saved");
                        LogMessage($"[Network Config] Configuration Mode: {(originalIsDhcp ? "DHCP" : "Static")}");
                        LogMessage($"[Network Config] Original IP: {originalIpAddress}");
                        LogMessage($"[Network Config] Original Subnet Mask: {originalSubnetMask}");
                        LogMessage($"[Network Config] Original Gateway: {originalGateway ?? "None"}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Network Config] Error saving network configuration: {ex.Message}");
            }
        }

        private async Task RestoreNetworkConfiguration()
        {
            if (string.IsNullOrEmpty(lastConfiguredInterface))
            {
                return;
            }

            try
            {
                LogMessage("[Network Config] Restoring original network configuration...");
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = originalIsDhcp ?
                            $"interface ip set address \"{lastConfiguredInterface}\" dhcp" :
                            $"interface ip set address \"{lastConfiguredInterface}\" static {originalIpAddress} {originalSubnetMask}" + 
                            (string.IsNullOrEmpty(originalGateway) ? "" : $" {originalGateway} 1"),
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);
                
                if (process.ExitCode != 0)
                {
                    string error = await process.StandardError.ReadToEndAsync();
                    LogMessage($"[Network Config] Failed to restore network configuration: {error}");
                }
                else
                {
                    if (originalIsDhcp)
                    {
                        // If DHCP mode, wait for IP address assignment
                        LogMessage("[Network Config] Waiting for DHCP to obtain IP address...");
                        await Task.Delay(5000); // Wait 5 seconds for DHCP
                    }
                    
                    LogMessage("[Network Config] Network configuration restored");
                    // Clear saved configuration
                    originalIpAddress = null;
                    originalSubnetMask = null;
                    originalGateway = null;
                    lastConfiguredInterface = null;
                    originalIsDhcp = false;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Network Config] Error restoring network configuration: {ex.Message}");
            }
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
    }
} 