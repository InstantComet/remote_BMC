using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using Renci.SshNet;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Linq;

namespace RemoteBMC
{
    public class DeviceDiscoveryManager
    {
        private readonly Action<string> _logMessage;
        private readonly string[] _bmcIps = new[] { "172.31.250.11", "172.31.240.11" };
        private const string SSH_PASSWORD = "remora";
        private const int SSH_PORT = 22;

        public DeviceDiscoveryManager(Action<string> logMessage)
        {
            _logMessage = logMessage;
        }

        public async Task<string> FindSmcDevice(NetworkInterface networkInterface = null, bool isDhcpMode = false, CancellationToken cancellationToken = default)
        {
            try
            {
                // 在DHCP模式下检查网卡配置
                if (isDhcpMode && networkInterface != null)
                {                    
                    var ipProperties = networkInterface.GetIPProperties();
                    var ipv4Address = ipProperties.UnicastAddresses
                        .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (ipv4Address != null)
                    {
                        string currentIp = ipv4Address.Address.ToString();
                        if (currentIp.StartsWith("169.254."))
                        {
                            _logMessage("[Network] Link-local address detected in DHCP mode");
                            MessageBox.Show(
                                "No valid DHCP server found in current network. \nPlease consider using Direct Connection mode instead.",
                                "Network Configuration Warning",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                            return null;
                        }

                        // 检查是否为静态IP（通过检查DHCP租约时间是否为空）
                        var dhcpLeaseLifetime = ipv4Address.GetType().GetProperty("DhcpLeaseLifetime")?.GetValue(ipv4Address) as TimeSpan?;
                        if (ipv4Address.PrefixLength > 0 && !dhcpLeaseLifetime.HasValue)
                        {
                            _logMessage("[Network] Static IP configuration detected in DHCP mode, attempting to get DHCP IP...");
                            var dhcpIp = await GetDhcpAssignedClientIp(networkInterface.Name, new List<NetworkInterface> { networkInterface }, true);
                            if (string.IsNullOrEmpty(dhcpIp))
                            {
                                _logMessage("[Network] Failed to get DHCP IP");
                                return null;
                            }
                            _logMessage($"[Network] Successfully switched to DHCP mode, assigned IP: {dhcpIp}");
                        }
                    }
                }

                List<string> ipAddressesToScan;
                if (networkInterface != null)
                {
                    _logMessage("[Network] Starting SMC device search in current network segment...");
                    ipAddressesToScan = GetDhcpNetworkAddresses(networkInterface);
                    if (ipAddressesToScan.Count == 0)
                    {
                        _logMessage("[Network] No valid IP range found in current network segment");
                        return null;
                    }
                }
                else
                {
                    _logMessage("[Network] Network interface not provided, searching all active network interfaces...");
                    ipAddressesToScan = new List<string>();
                    
                    // 获取所有活动的网络接口
                    var activeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                        .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                               (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                                ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211));

                    foreach (var nic in activeInterfaces)
                    {
                        var addresses = GetDhcpNetworkAddresses(nic);
                        if (addresses.Count > 0)
                        {
                            _logMessage($"[Network] Adding addresses from interface {nic.Name}");
                            ipAddressesToScan.AddRange(addresses);
                        }
                    }

                    // 如果没有找到任何有效的网络接口，则回退到link-local网络
                    if (ipAddressesToScan.Count == 0)
                    {
                        _logMessage("[Network] No valid network interfaces found, falling back to link-local network...");
                        _logMessage("[Network] Starting SMC device search in 169.254.x.x network...");
                        ipAddressesToScan = GetLinkLocalAddresses();
                    }
                }

                var deviceList = await ScanIpAddresses(ipAddressesToScan, isDhcpMode, cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                {
                    _logMessage("[Network] Device scanning cancelled by user");
                    return null;
                }

                var smcDevices = await VerifySmcDevices(deviceList, cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                {
                    _logMessage("[Network] Device verification cancelled by user");
                    return null;
                }

                if (smcDevices.Count == 0)
                {
                    _logMessage("[Network] No SMC devices found");
                    return null;
                }

                // 在DHCP模式下，如果找到多个设备，让用户选择
                if (isDhcpMode && smcDevices.Count > 1)
                {
                    _logMessage($"[Network] Found {smcDevices.Count} SMC devices, prompting user to select...");
                    return await SelectSmcDevice(smcDevices);
                }
                
                // 在直连模式下或只找到一个设备时，直接返回第一个设备
                var device = smcDevices[0];
                _logMessage($"[Network] Using {(smcDevices.Count == 1 ? "only" : "first")} found SMC device: {device.ip}");
                _logMessage($"[Network] Device information:\n{device.info}");
                return device.ip;
            }
            catch (OperationCanceledException)
            {
                _logMessage("[Network] Operation cancelled by user");
                return null;
            }
            catch (Exception ex)
            {
                _logMessage($"[Network] Error during search process: {ex.Message}");
                return null;
            }
        }

        private List<string> GetLinkLocalAddresses()
        {
            List<string> ipAddressesToScan = new List<string>();
            _logMessage("[Network] Scanning link-local network (169.254.x.x)");
            
            // 优化扫描顺序，先扫描已知的IP地址附近的网段
            var knownIPs = new[] { 
                (169, 254, 24, 162),  // 已知的SMC设备IP
                (169, 254, 5, 235)    // 当前网卡IP
            };

            foreach (var (a, b, c, d) in knownIPs)
            {
                // 先扫描已知IP
                ipAddressesToScan.Add($"{a}.{b}.{c}.{d}");
                
                // 然后扫描同一个C段
                for (int i = 1; i <= 254; i++)
                {
                    if (i != d)
                    {
                        ipAddressesToScan.Add($"{a}.{b}.{c}.{i}");
                    }
                }
            }

            // 最后扫描其他网段
            for (int i = 0; i < 256; i++)
            {
                if (i != 24 && i != 5) // 跳过已扫描的网段
                {
                    for (int j = 1; j < 255; j++)
                    {
                        ipAddressesToScan.Add($"169.254.{i}.{j}");
                    }
                }
            }

            _logMessage($"[Network] Prepared {ipAddressesToScan.Count} addresses to scan");
            return ipAddressesToScan;
        }

        private List<string> GetDhcpNetworkAddresses(NetworkInterface networkInterface)
        {
            List<string> ipAddressesToScan = new List<string>();
            
            var ipProperties = networkInterface.GetIPProperties();
            var ipv4Address = ipProperties.UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

            if (ipv4Address == null)
            {
                _logMessage("[Network] No IPv4 address found on selected interface");
                return ipAddressesToScan;
            }

            // 获取IP地址和子网掩码
            byte[] ipBytes = ipv4Address.Address.GetAddressBytes();
            byte[] maskBytes = ipv4Address.IPv4Mask.GetAddressBytes();

            // 计算网络地址
            byte[] networkBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
            }

            // 获取当前网段
            string baseIp = $"{networkBytes[0]}.{networkBytes[1]}.{networkBytes[2]}";
            int currentIp = ipBytes[3];
            
            _logMessage($"[Network] Current IP: {ipv4Address.Address}");
            _logMessage($"[Network] Scanning network: {baseIp}.0/24");

            // 优先扫描当前IP附近的地址
            int scanRadius = 20; // 扫描半径
            HashSet<int> scannedIps = new HashSet<int>();

            // 先扫描当前IP附近的地址
            for (int offset = 0; offset <= scanRadius; offset++)
            {
                int lowerIp = currentIp - offset;
                int upperIp = currentIp + offset;

                if (lowerIp > 0 && !scannedIps.Contains(lowerIp))
                {
                    ipAddressesToScan.Add($"{baseIp}.{lowerIp}");
                    scannedIps.Add(lowerIp);
                }
                if (upperIp < 255 && !scannedIps.Contains(upperIp))
                {
                    ipAddressesToScan.Add($"{baseIp}.{upperIp}");
                    scannedIps.Add(upperIp);
                }
            }

            // 扫描剩余的地址
            for (int i = 1; i < 255; i++)
            {
                if (!scannedIps.Contains(i))
                {
                    ipAddressesToScan.Add($"{baseIp}.{i}");
                }
            }

            _logMessage($"[Network] Prepared {ipAddressesToScan.Count} addresses to scan in DHCP network");
            return ipAddressesToScan;
        }

        public async Task<string> GetDhcpAssignedClientIp(string selectedInterface, List<NetworkInterface> networkInterfaces, bool isManualDhcp)
        {
            try
            {
                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (selectedNic == null)
                {
                    _logMessage("[Network] Selected network interface not found");
                    return null;
                }

                var ipProperties = await Task.Run(() => selectedNic.GetIPProperties());
                var ipv4Address = ipProperties.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                if (ipv4Address == null)
                {
                    _logMessage("[Network] No IPv4 address found on selected interface");
                    return null;
                }

                string clientIp = ipv4Address.Address.ToString();
                _logMessage($"[Network] DHCP assigned client IP: {clientIp}");
                return clientIp;
            }
            catch (Exception ex)
            {
                _logMessage($"[Network] Error getting DHCP assigned client IP: {ex.Message}");
                return null;
            }
        }

        private async Task<List<(string ip, bool isAlive)>> ScanIpAddresses(List<string> ipAddressesToScan, bool isDhcpMode, CancellationToken cancellationToken)
        {
            _logMessage($"[Network] Starting scan of {ipAddressesToScan.Count} addresses...");
            var deviceList = new List<(string ip, bool isAlive)>();
            var tasks = new List<Task>();
            var lockObj = new object();
            const int sshTimeout = 1000; // SSH连接超时时间1秒
            const int maxConcurrentTasks = 50; // 限制并发任务数量
            var semaphore = new SemaphoreSlim(maxConcurrentTasks);
            var localCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            foreach (string ip in ipAddressesToScan)
            {
                if (localCts.Token.IsCancellationRequested)
                {
                    break;
                }

                await semaphore.WaitAsync(localCts.Token);
                var task = Task.Run(async () =>
                {
                    try
                    {
                        if (localCts.Token.IsCancellationRequested)
                        {
                            return;
                        }

                        try
                        {
                            using (var tcpClient = new TcpClient())
                            {
                                var connectTask = tcpClient.ConnectAsync(ip, SSH_PORT);
                                if (await Task.WhenAny(connectTask, Task.Delay(sshTimeout, localCts.Token)) == connectTask)
                                {
                                    if (connectTask.IsCompleted && !connectTask.IsFaulted)
                                    {
                                        lock (lockObj)
                                        {
                                            if (!deviceList.Any(d => d.ip == ip))
                                            {
                                                deviceList.Add((ip, true));
                                                _logMessage($"[Network] Device found: {ip} (SSH port open)");
                                                
                                                // 在非DHCP模式下，找到设备后取消其他扫描任务
                                                if (!isDhcpMode)
                                                {
                                                    _logMessage("[Network] First device found, stopping further scanning...");
                                                    localCts.Cancel();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            // 忽略取消异常
                        }
                        catch
                        {
                            // 忽略其他连接错误
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, localCts.Token);
                tasks.Add(task);

                // 如果已经找到设备并且不是DHCP模式，立即停止添加新任务
                if (!isDhcpMode && deviceList.Any())
                {
                    break;
                }
            }

            try
            {
                await Task.WhenAll(tasks.Where(t => !t.IsCanceled));
            }
            catch (OperationCanceledException)
            {
                _logMessage("[Network] Scan stopped");
            }
            finally
            {
                localCts.Dispose();
            }

            _logMessage($"[Network] Scan complete, found {deviceList.Count} devices");
            
            // 按照IP地址排序，方便查看
            var sortedList = deviceList.OrderBy(d => {
                var parts = d.ip.Split('.');
                return parts.Length == 4 ? 
                    (int.Parse(parts[0]) << 24) + (int.Parse(parts[1]) << 16) + (int.Parse(parts[2]) << 8) + int.Parse(parts[3]) 
                    : 0;
            }).ToList();
            
            foreach (var device in sortedList)
            {
                _logMessage($"[Network] Found device: {device.ip}");
            }
            
            return sortedList;
        }

        private async Task<List<(string ip, string mac, string info)>> VerifySmcDevices(List<(string ip, bool isAlive)> deviceList, CancellationToken cancellationToken)
        {
            _logMessage("[Network] Starting device verification...");
            var smcDevices = new List<(string ip, string mac, string info)>();
            const int sshTimeout = 3; // SSH连接超时时间3秒

            foreach (var device in deviceList.OrderByDescending(d => d.isAlive))
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    using (var sshClient = new SshClient(device.ip, "root", SSH_PASSWORD))
                    {
                        sshClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(sshTimeout);
                        await Task.Run(() => sshClient.Connect(), cancellationToken);
                        var deviceInfo = await GetDeviceInformation(sshClient, cancellationToken);
                        if (deviceInfo != null)
                        {
                            smcDevices.Add(deviceInfo.Value);
                            _logMessage($"[Network] SMC device found: {device.ip}");
                            _logMessage($"[Network] Device information:\n{deviceInfo.Value.info}");
                        }
                        sshClient.Disconnect();
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logMessage($"[Network] Error checking device {device.ip}: {ex.Message}");
                }
            }

            return smcDevices;
        }

        private async Task<(string ip, string mac, string info)?> GetDeviceInformation(SshClient sshClient, CancellationToken cancellationToken)
        {
            try
            {
                _logMessage($"[Network] Getting device information from {sshClient.ConnectionInfo.Host}...");
                
                // 只执行hostname命令来快速确认是否是SMC设备
                _logMessage($"[Network] Executing hostname command...");
                var hostnameCmd = sshClient.CreateCommand("hostname");
                string hostname = await Task.Run(() => hostnameCmd.Execute().Trim(), cancellationToken);
                _logMessage($"[Network] Hostname command result: {hostname}");

                if (hostname != "smc" && hostname != "remora")
                {
                    _logMessage($"[Network] Device is not an SMC device (hostname: {hostname})");
                    return null;
                }

                // 如果是SMC设备，再获取MAC地址
                _logMessage($"[Network] Device confirmed as SMC, getting MAC address...");
                string mac = await GetMacAddress(sshClient, cancellationToken);
                _logMessage($"[Network] MAC address obtained: {mac}");
                
                string deviceInfo = $"Hostname: {hostname}\nMAC Address: {mac}";
                return (sshClient.ConnectionInfo.Host, mac, deviceInfo);
            }
            catch (Exception ex)
            {
                _logMessage($"[Network] Error getting device information: {ex.Message}");
                return null;
            }
        }

        private async Task<string> GetMacAddress(SshClient sshClient, CancellationToken cancellationToken)
        {
            try
            {
                _logMessage("[Network] Trying to get MAC address using ifconfig...");
                var ifconfigCmd = sshClient.CreateCommand("ifconfig -a");
                string ifconfigOutput = await Task.Run(() => ifconfigCmd.Execute().Trim(), cancellationToken);

                if (string.IsNullOrEmpty(ifconfigOutput))
                {
                    _logMessage("[Network] ifconfig returned no output, trying ip link show...");
                    var ipCmd = sshClient.CreateCommand("ip link show");
                    ifconfigOutput = await Task.Run(() => ipCmd.Execute().Trim(), cancellationToken);
                }

                if (!string.IsNullOrEmpty(ifconfigOutput))
                {
                    var patterns = new[]
                    {
                        @"HWaddr\s+([0-9A-Fa-f:]{17})",
                        @"ether\s+([0-9a-fA-F:]{17})",
                        @"link/ether\s+([0-9a-fA-F:]{17})"
                    };

                    foreach (var pattern in patterns)
                    {
                        _logMessage($"[Network] Trying to match MAC address pattern: {pattern}");
                        var match = System.Text.RegularExpressions.Regex.Match(ifconfigOutput, pattern);
                        if (match.Success)
                        {
                            string mac = match.Groups[1].Value.ToUpper();
                            _logMessage($"[Network] Found MAC address using pattern {pattern}");
                            return mac;
                        }
                    }
                    _logMessage("[Network] No MAC address pattern matched in the output");
                }
                else
                {
                    _logMessage("[Network] Both ifconfig and ip link show commands returned no output");
                }
                return null;
            }
            catch (Exception ex)
            {
                _logMessage($"[Network] Error retrieving MAC address: {ex.Message}");
                return null;
            }
        }

        private Task<string> SelectSmcDevice(List<(string ip, string mac, string info)> smcDevices)
        {
            var tcs = new TaskCompletionSource<string>();
            
            Application.Current.Dispatcher.Invoke(() =>
            {
                try
                {
                    _logMessage($"[Network] Found {smcDevices.Count} SMC devices");
                    var options = smcDevices.Select(d => $"IP: {d.ip}\n{d.info}").ToList();

                    var dialog = new SelectDeviceDialog(options);
                    if (dialog.ShowDialog() == true)
                    {
                        var selectedDevice = smcDevices[dialog.SelectedIndex];
                        _logMessage($"[Network] User selected device: {selectedDevice.ip}");
                        tcs.SetResult(selectedDevice.ip);
                    }
                    else
                    {
                        _logMessage("[Network] User cancelled device selection");
                        tcs.SetResult(null);
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"[Network] Error during device selection: {ex.Message}");
                    tcs.SetException(ex);
                }
            });
            
            return tcs.Task;
        }

        public async Task<string> DetermineBmcIp(string smcIp)
        {
            _logMessage($"[Network] Testing management interface connectivity");
            
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(smcIp, 500);
                    if (reply.Status != IPStatus.Success)
                    {
                        _logMessage($"[Network] Unable to connect to SMC device: Connection timeout");
                        return null;
                    }
                }

                using (var client = new SshClient(smcIp, "root", SSH_PASSWORD))
                {
                    try
                    {
                        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(5);
                        await Task.Run(() => client.Connect());
                    }
                    catch (Exception ex)
                    {
                        _logMessage($"[Network] SSH connection failed: {ex.Message}");
                        return null;
                    }

                    foreach (string ip in _bmcIps)
                    {
                        _logMessage($"[Network] Testing BMC IP: {ip}");
                        try
                        {
                            var pingCmd = client.CreateCommand($"ping -c 1 -W 1 {ip}");
                            
                            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
                            {
                                try
                                {
                                    var pingTask = Task.Run(() => pingCmd.Execute(), cts.Token);
                                    var result = await pingTask;

                                    if (pingCmd.ExitStatus == 0)
                                    {
                                        _logMessage($"[Network] Successfully established connection to BMC IP: {ip}");
                                        return ip;
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    _logMessage($"[Network] Connection timeout for BMC IP {ip}, trying next address");
                                    continue;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logMessage($"[Network] Error testing BMC IP {ip}: {ex.Message}");
                        }
                    }

                    client.Disconnect();
                }
            }
            catch (Exception ex)
            {
                _logMessage($"[Network] Connectivity test failed: {ex.Message}");
            }

            _logMessage("[Network] All BMC management interface IPs are unreachable");
            return null;
        }
    }
}