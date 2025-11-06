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
    public class DeviceDiscoveryManager(Action<string> logMessage)
    {
        private readonly Action<string> _logMessage = logMessage;
        private readonly string[] _bmcIps = ["172.31.250.11", "172.31.240.11"];
        private const string SSH_PASSWORD = "remora";
        private const int SSH_PORT = 22;

        public async Task<string> FindSmcDevice(NetworkInterface networkInterface = null, bool isDhcpMode = false)
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
                            _logMessage("APIPA address detected in DHCP mode");
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
                            _logMessage("Attempting to get DHCP IP...");
                            var dhcpIp = await GetDhcpAssignedClientIp(networkInterface.Name, new List<NetworkInterface> { networkInterface });
                            if (string.IsNullOrEmpty(dhcpIp))
                            {
                                _logMessage("Failed to get DHCP IP");
                                return null;
                            }
                            _logMessage($"Successfully switched to DHCP mode, assigned IP: {dhcpIp}");
                        }
                    }
                }

                List<string> ipAddressesToScan;
                if (networkInterface != null)
                {
                    if (!isDhcpMode)
                    {
                        _logMessage("Direct connect mode - scanning APIPA network");
                        ipAddressesToScan = GetLinkLocalAddresses();
                    }
                    else
                    {
                        _logMessage("Start search for SMC in current network segment...");
                        ipAddressesToScan = GetDhcpNetworkAddresses(networkInterface);
                        if (ipAddressesToScan.Count == 0)
                        {
                            _logMessage("No valid IP range found in current network segment");
                            return null;
                        }
                    }
                }
                else
                {
                    _logMessage("Network interface not provided, searching all active network interfaces...");
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
                            _logMessage($"Adding addresses from interface {nic.Name}");
                            ipAddressesToScan.AddRange(addresses);
                        }
                    }

                    // 如果没有找到任何有效的网络接口，则回退到APIPA网络
                    if (ipAddressesToScan.Count == 0)
                    {
                        _logMessage("No valid network interfaces found, falling back to APIPA network...");
                        _logMessage("Starting SMC device search in 169.254.x.x network...");
                        ipAddressesToScan = GetLinkLocalAddresses();
                    }
                }

                var deviceList = await ScanIpAddresses(ipAddressesToScan, isDhcpMode);
                if (deviceList.Count == 0)
                {
                    _logMessage("No devices found");
                    return null;
                }

                var smcDevices = await VerifySmcDevices(deviceList);
                if (smcDevices.Count == 0)
                {
                    _logMessage("No SMC devices found");
                    return null;
                }

                // 在DHCP模式下，如果找到多个设备，让用户选择
                if (isDhcpMode && smcDevices.Count > 1)
                {
                    _logMessage($"Found {smcDevices.Count} SMC devices, prompting user to select...");
                    return await SelectSmcDevice(smcDevices);
                }
                
                // 在直连模式下或只找到一个设备时，直接返回第一个设备
                var device = smcDevices[0];
                _logMessage($"Using {(smcDevices.Count == 1 ? "only" : "first")} found SMC device: {device.ip}");
                _logMessage($"Device information:\n{device.info}");
                return device.ip;
            }
            catch (Exception ex)
            {
                _logMessage($"Error during search process: {ex.Message}");
                return null;
            }
        }

        private List<string> GetLinkLocalAddresses()
        {
            var ipAddressesToScan = new HashSet<string>();
            _logMessage("Generating full 169.254.0.0/16 addresses");

            // 生成全量169.254.0.0/16地址
            Parallel.For(0, 256, thirdOctet =>
            {
                for (int fourthOctet = 1; fourthOctet < 255; fourthOctet++)
                {
                    lock (ipAddressesToScan)
                    {
                        ipAddressesToScan.Add($"169.254.{thirdOctet}.{fourthOctet}");
                    }
                }
            });

            _logMessage($"Generated {ipAddressesToScan.Count} unique addresses");
            return ipAddressesToScan.OrderBy(ip => ip).ToList();
        }

        private List<string> GetDhcpNetworkAddresses(NetworkInterface networkInterface)
        {
            List<string> ipAddressesToScan = new List<string>();
            
            var ipProperties = networkInterface.GetIPProperties();
            var ipv4Address = ipProperties.UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

            if (ipv4Address == null)
            {
                _logMessage("No IPv4 address found on selected interface");
                return ipAddressesToScan;
            }

            // 根据实际IP地址计算网络地址
            var ipAddress = ipv4Address.Address;
            var subnetMask = GetSubnetMask(ipv4Address.PrefixLength);
            var networkAddress = GetNetworkAddress(ipAddress, subnetMask);
            
            _logMessage($"Searching for SMC in network: {networkAddress}/{ipv4Address.PrefixLength}");

            // 生成当前子网所有地址
            var totalHosts = (int)Math.Pow(2, 32 - ipv4Address.PrefixLength);
            var startIp = IpToInt(networkAddress.ToString());
            var endIp = startIp + totalHosts - 1;

            Parallel.For(startIp, endIp + 1, new ParallelOptions(), ipInt =>
            {
                if (ipInt == startIp || ipInt == endIp) return; // 排除网络地址和广播地址
                var ip = IntToIp(ipInt);
                lock (ipAddressesToScan)
                {
                    ipAddressesToScan.Add(ip);
                }
            });

            // 添加辅助方法
            int IpToInt(string ipAddress)
            {
                var bytes = IPAddress.Parse(ipAddress).GetAddressBytes();
                return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            }

            string IntToIp(int ipAddress)
            {
                return new IPAddress(BitConverter.GetBytes(ipAddress).Reverse().ToArray()).MapToIPv4().ToString();
            }

            IPAddress GetNetworkAddress(IPAddress address, IPAddress subnetMask)
            {
                var ipBytes = address.GetAddressBytes();
                var maskBytes = subnetMask.GetAddressBytes();
                var networkBytes = new byte[ipBytes.Length];
                for (int i = 0; i < ipBytes.Length; i++)
                {
                    networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
                }
                return new IPAddress(networkBytes);
            }

            IPAddress GetSubnetMask(int prefixLength)
            {
                var maskBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    if (prefixLength > 8)
                    {
                        maskBytes[i] = 0xFF;
                        prefixLength -= 8;
                    }
                    else
                    {
                        maskBytes[i] = (byte)(0xFF << (8 - prefixLength));
                        prefixLength = 0;
                    }
                }
                return new IPAddress(maskBytes);
            }

            _logMessage($"Prepared {ipAddressesToScan.Count} addresses to scan");
            return ipAddressesToScan;
        }

        // 修改 GetDhcpAssignedClientIp 方法：
        public async Task<string> GetDhcpAssignedClientIp(string selectedInterface, List<NetworkInterface> networkInterfaces)
        {
            try
            {
                var selectedNic = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (selectedNic == null)
                {
                    _logMessage("Selected network interface not found");
                    return null;
                }

                var ipProperties = await Task.Run(() => selectedNic.GetIPProperties());
                var ipv4Address = ipProperties.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                if (ipv4Address == null)
                {
                    _logMessage("No IPv4 address found on selected interface");
                    return null;
                }

                string clientIp = ipv4Address.Address.ToString();
                _logMessage($"The IP of this PC is: {clientIp}");
                return clientIp;
            }
            catch (Exception ex)
            {
                _logMessage($"Error getting DHCP assigned client IP: {ex.Message}");
                return null;
            }
        }

        private async Task<List<(string ip, bool isAlive)>> ScanIpAddresses(List<string> ipAddressesToScan, bool isDhcpMode)
        {
            _logMessage($"Start scaning of {ipAddressesToScan.Count} addresses...");
            var deviceList = new List<(string ip, bool isAlive)>();
            var tasks = new List<Task>();
            var lockObj = new object();
            const int sshTimeout = 100; // SSH连接超时时间1秒
            const int maxConcurrentTasks = 1000; // 限制并发任务数量
            var semaphore = new SemaphoreSlim(maxConcurrentTasks);

            foreach (string ip in ipAddressesToScan)
            {
                await semaphore.WaitAsync();
                var task = Task.Run(async () =>
                {
                    try
                    {
                        try
                        {
                            using (var tcpClient = new TcpClient())
                            {
                                var connectTask = tcpClient.ConnectAsync(ip, SSH_PORT);
                                if (await Task.WhenAny(connectTask, Task.Delay(sshTimeout)) == connectTask)
                                {
                                    if (connectTask.IsCompleted && !connectTask.IsFaulted)
                                    {
                                        lock (lockObj)
                                        {
                                            if (!deviceList.Any(d => d.ip == ip))
                                            {
                                                deviceList.Add((ip, true));
                                                _logMessage($"Device found: {ip} (SSH port open)");
                                                
                                                // 在非DHCP模式下，找到设备后取消其他扫描任务
                                                if (!isDhcpMode)
                                                {
                                                    _logMessage("First device found, stopping further scanning...");
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            // 忽略连接错误
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                });
                tasks.Add(task);

                // 如果已经找到设备并且不是DHCP模式，立即停止添加新任务
                if (!isDhcpMode && deviceList.Any())
                {
                    break;
                }
            }

            await Task.WhenAll(tasks);
            _logMessage($"Scan complete, {deviceList.Count} devices found");
            
            // 按照IP地址排序，方便查看
            var sortedList = deviceList.OrderBy(d => {
                var parts = d.ip.Split('.');
                return parts.Length == 4 ? 
                    (int.Parse(parts[0]) << 24) + (int.Parse(parts[1]) << 16) + (int.Parse(parts[2]) << 8) + int.Parse(parts[3]) 
                    : 0;
            }).ToList();
            
            return sortedList;
        }

        private async Task<List<(string ip, string mac, string info)>> VerifySmcDevices(List<(string ip, bool isAlive)> deviceList)
        {
            _logMessage("Starting device verification...");
            var smcDevices = new List<(string ip, string mac, string info)>();
            const int sshTimeout = 6; // SSH连接超时时间6秒

            foreach (var device in deviceList.OrderByDescending(d => d.isAlive))
            {
                try
                {
                    using (var sshClient = new SshClient(device.ip, "root", SSH_PASSWORD))
                    {
                        sshClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(sshTimeout);
                        await Task.Run(() => sshClient.Connect());
                        var deviceInfo = await GetDeviceInformation(sshClient);
                        if (deviceInfo != null)
                        {
                            smcDevices.Add(deviceInfo.Value);
                            _logMessage($"SMC device found: {device.ip}");
                            _logMessage($"Device information:\n{deviceInfo.Value.info}");
                        }
                        sshClient.Disconnect();
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"Error checking device {device.ip}: {ex.Message}");
                }
            }

            return smcDevices;
        }

        private async Task<(string ip, string mac, string info)?> GetDeviceInformation(SshClient sshClient)
        {
            try
            {
                _logMessage($"Getting device information from {sshClient.ConnectionInfo.Host}...");
                
                // 只执行hostname命令来快速确认是否是SMC设备
                _logMessage($"Executing hostname command...");
                var hostnameCmd = sshClient.CreateCommand("hostname");
                string hostname = await Task.Run(() => hostnameCmd.Execute().Trim());
                _logMessage($"Hostname command result: {hostname}");

                if (hostname != "smc" && hostname != "remora")
                {
                    _logMessage($"Device is not an SMC device (hostname: {hostname})");
                    return null;
                }

                // 如果是SMC设备，再获取MAC地址
                _logMessage($"Device confirmed as SMC, getting MAC address...");
                string mac = await GetMacAddress(sshClient);
                _logMessage($"MAC address obtained: {mac}");
                
                string deviceInfo = $"Hostname: {hostname}\nMAC Address: {mac}";
                return (sshClient.ConnectionInfo.Host, mac, deviceInfo);
            }
            catch (Exception ex)
            {
                _logMessage($"Error getting device information: {ex.Message}");
                return null;
            }
        }

        private async Task<string> GetMacAddress(SshClient sshClient)
        {
            try
            {
                //_logMessage("Trying to get MAC address using ifconfig...");
                var ifconfigCmd = sshClient.CreateCommand("ifconfig -a");
                string ifconfigOutput = await Task.Run(() => ifconfigCmd.Execute().Trim());

                if (string.IsNullOrEmpty(ifconfigOutput))
                {
                    _logMessage("ifconfig returned no output, trying ip link show...");
                    var ipCmd = sshClient.CreateCommand("ip link show");
                    ifconfigOutput = await Task.Run(() => ipCmd.Execute().Trim());
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
                        //_logMessage($"Trying to match MAC address pattern: {pattern}");
                        var match = System.Text.RegularExpressions.Regex.Match(ifconfigOutput, pattern);
                        if (match.Success)
                        {
                            string mac = match.Groups[1].Value.ToUpper();
                            //_logMessage($"Found MAC address using pattern {pattern}");
                            return mac;
                        }
                    }
                    _logMessage("No MAC address pattern matched in the output");
                }
                else
                {
                    _logMessage("Both ifconfig and ip link show commands returned no output");
                }
                return null;
            }
            catch (Exception ex)
            {
                _logMessage($"Error retrieving MAC address: {ex.Message}");
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
                    _logMessage($"Found {smcDevices.Count} SMC devices");
                    var options = smcDevices.Select(d => $"IP: {d.ip}\n{d.info}").ToList();

                    var dialog = new SelectDeviceDialog(options);
                    if (dialog.ShowDialog() == true)
                    {
                        var selectedDevice = smcDevices[dialog.SelectedIndex];
                        _logMessage($"User selected device: {selectedDevice.ip}");
                        tcs.SetResult(selectedDevice.ip);
                    }
                    else
                    {
                        _logMessage("User cancelled device selection");
                        tcs.SetResult(null);
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"Error during device selection: {ex.Message}");
                    tcs.SetException(ex);
                }
            });
            
            return tcs.Task;
        }

        public async Task<string> DetermineBmcIp(string smcIp)
        {
            _logMessage($"Starting BMC IP determination process");
            
            try
            {
                // 首先确认SMC是否可达
                using (var ping = new Ping())
                {
                    _logMessage($"Checking if SMC is reachable at {smcIp}...");
                    var reply = await ping.SendPingAsync(smcIp, 1000);
                    if (reply.Status != IPStatus.Success)
                    {
                        _logMessage($"Cannot reach SMC at {smcIp}: Connection timeout");
                        return null;
                    }
                    _logMessage($"SMC is reachable at {smcIp}");
                }

                // 修改SSH连接配置
                var connectionInfo = new ConnectionInfo(smcIp, 
                    "root", 
                    new PasswordAuthenticationMethod("root", SSH_PASSWORD),
                    new KeyboardInteractiveAuthenticationMethod("root")
                );
                
                // 设置更详细的连接参数
                connectionInfo.Timeout = TimeSpan.FromSeconds(30);        // 增加总体超时时间
                connectionInfo.RetryAttempts = 3;                        // 添加重试次数
                
                // 建立SSH连接
                _logMessage($"Establishing SSH connection to SMC with extended timeout...");
                using var sshClient = new SshClient(connectionInfo);
                
                try
                {
                    await Task.Run(() => 
                    {
                        sshClient.Connect();
                        _logMessage("SSH connection established successfully");
                    });

                    if (!sshClient.IsConnected)
                    {
                        _logMessage("SSH connection failed to establish");
                        return null;
                    }

                    // 首先尝试ping 172.31.250.11
                    _logMessage("Attempting to ping primary BMC IP (172.31.250.11)...");
                    var primaryPingCmd = sshClient.CreateCommand("ping -c 1 -W 2 172.31.250.11");
                    var primaryResult = await Task.Run(() => primaryPingCmd.Execute());
                    _logMessage($"Primary BMC ping command output:\n{primaryResult}");

                    if (primaryPingCmd.ExitStatus == 0)
                    {
                        _logMessage("Successfully connected to primary BMC IP (172.31.250.11)");
                        return "172.31.250.11";
                    }

                    // 如果第一个IP不通，尝试ping 172.31.240.11
                    _logMessage("Primary BMC IP unreachable, trying secondary BMC IP (172.31.240.11)...");
                    var secondaryPingCmd = sshClient.CreateCommand("ping -c 1 -W 2 172.31.240.11");
                    var secondaryResult = await Task.Run(() => secondaryPingCmd.Execute());
                    _logMessage($"Secondary BMC ping command output:\n{secondaryResult}");

                    if (secondaryPingCmd.ExitStatus == 0)
                    {
                        _logMessage("Successfully connected to secondary BMC IP (172.31.240.11)");
                        return "172.31.240.11";
                    }

                    _logMessage("Both BMC IPs are unreachable from SMC");
                    return null;
                }
                catch (Exception ex)
                {
                    _logMessage($"SSH operation failed: {ex.Message}");
                    _logMessage($"SSH connection details: Host={smcIp}, Username=root");
                    if (sshClient.IsConnected)
                    {
                        try
                        {
                            sshClient.Disconnect();
                        }
                        catch { }
                    }
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logMessage($"BMC IP determination process failed: {ex.Message}");
                return null;
            }
        }
    }
}