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

        public async Task<string> GetDhcpAssignedClientIp(string selectedInterface, List<NetworkInterface> networkInterfaces, bool isManualDhcp)
        {
            _logMessage("[DHCP] Starting SMC device search...");
            
            try
            {
                var networkInterface = networkInterfaces.FirstOrDefault(ni => ni.Name == selectedInterface);
                if (networkInterface == null)
                {
                    _logMessage("[DHCP] Unable to get selected network interface");
                    return null;
                }

                List<string> ipAddressesToScan = GetIpAddressesToScan(networkInterface, isManualDhcp);
                if (ipAddressesToScan == null || ipAddressesToScan.Count == 0)
                {
                    return null;
                }

                var deviceList = await ScanIpAddresses(ipAddressesToScan);
                var smcDevices = await VerifySmcDevices(deviceList);

                if (smcDevices.Count == 0)
                {
                    _logMessage("[DHCP] No SMC devices found");
                    return null;
                }

                return await SelectSmcDevice(smcDevices);
            }
            catch (Exception ex)
            {
                _logMessage($"[DHCP] Error during search process: {ex.Message}");
                return null;
            }
        }

        private List<string> GetIpAddressesToScan(NetworkInterface networkInterface, bool isManualDhcp)
        {
            List<string> ipAddressesToScan = new List<string>();

            if (isManualDhcp)
            {
                _logMessage("[DHCP] Scanning DHCP pool range (10.10.20.100-10.10.20.200)");
                for (int i = 100; i <= 200; i++)
                {
                    ipAddressesToScan.Add($"10.10.20.{i}");
                }
            }
            else
            {
                var ipProperties = networkInterface.GetIPProperties();
                var ipAddress = ipProperties.UnicastAddresses
                    .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);

                if (ipAddress == null)
                {
                    _logMessage("[DHCP] Unable to get network interface IP address");
                    return null;
                }

                string localIp = ipAddress.Address.ToString();
                string subnetMask = ipAddress.IPv4Mask.ToString();
                _logMessage($"[DHCP] Local IP: {localIp}, Subnet Mask: {subnetMask}");

                var ipParts = localIp.Split('.');
                var maskParts = subnetMask.Split('.');
                var networkParts = new int[4];
                for (int i = 0; i < 4; i++)
                {
                    networkParts[i] = int.Parse(ipParts[i]) & int.Parse(maskParts[i]);
                }

                for (int i = 1; i < 255; i++)
                {
                    ipAddressesToScan.Add($"{networkParts[0]}.{networkParts[1]}.{networkParts[2]}.{i}");
                }
            }

            return ipAddressesToScan;
        }

        private async Task<List<(string ip, bool isAlive)>> ScanIpAddresses(List<string> ipAddressesToScan)
        {
            _logMessage($"[DHCP] Starting scan of {ipAddressesToScan.Count} addresses...");
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
                                    _logMessage($"[DHCP] Device found: {ip} (SSH port open)");
                                }
                            }
                        }
                    }
                    catch
                    {
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
                                        _logMessage($"[DHCP] Device found: {ip} (Ping successful)");
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
            _logMessage($"[DHCP] Scan complete, found {deviceList.Count} devices");
            return deviceList;
        }

        private async Task<List<(string ip, string mac, string info)>> VerifySmcDevices(List<(string ip, bool isAlive)> deviceList)
        {
            _logMessage("[DHCP] Starting device verification...");
            var smcDevices = new List<(string ip, string mac, string info)>();

            foreach (var device in deviceList.OrderByDescending(d => d.isAlive))
            {
                _logMessage($"[DHCP] Checking {device.ip}...");
                try
                {
                    using (var sshClient = new SshClient(device.ip, "root", SSH_PASSWORD))
                    {
                        sshClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(2);
                        try
                        {
                            await Task.Run(() => sshClient.Connect());
                            var deviceInfo = await GetDeviceInformation(sshClient);
                            if (deviceInfo != null)
                            {
                                smcDevices.Add(deviceInfo.Value);
                                _logMessage($"[DHCP] SMC device found: {device.ip}");
                                _logMessage($"[DHCP] Device information:\n{deviceInfo.Value.info}");
                            }
                            sshClient.Disconnect();
                        }
                        catch
                        {
                            continue;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"[DHCP] Error checking device {device.ip}: {ex.Message}");
                    continue;
                }
            }

            return smcDevices;
        }

        private async Task<(string ip, string mac, string info)?> GetDeviceInformation(SshClient sshClient)
        {
            var command = sshClient.CreateCommand("uname -a");
            string result = command.Execute();

            if (!result.Contains("SMC") && !result.Contains("smc"))
            {
                return null;
            }

            var hostnameCmd = sshClient.CreateCommand("hostname");
            string hostname = hostnameCmd.Execute().Trim();

            var uptimeCmd = sshClient.CreateCommand("uptime");
            string uptime = uptimeCmd.Execute().Trim();

            string mac = await GetMacAddress(sshClient);
            string deviceInfo = $"Hostname: {hostname}\nMAC Address: {mac}\nUptime: {uptime}";

            return (sshClient.ConnectionInfo.Host, mac, deviceInfo);
        }

        private async Task<string> GetMacAddress(SshClient sshClient)
        {
            try
            {
                var ifconfigCmd = sshClient.CreateCommand("ifconfig -a");
                string ifconfigOutput = await Task.Run(() => ifconfigCmd.Execute().Trim());

                if (string.IsNullOrEmpty(ifconfigOutput))
                {
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
                        var match = System.Text.RegularExpressions.Regex.Match(ifconfigOutput, pattern);
                        if (match.Success)
                        {
                            return match.Groups[1].Value.ToUpper();
                        }
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                _logMessage($"Error getting MAC address: {ex.Message}");
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
                    _logMessage($"[DHCP] Found {smcDevices.Count} SMC devices");
                    var options = smcDevices.Select(d => $"IP: {d.ip}\n{d.info}").ToList();

                    var dialog = new SelectDeviceDialog(options);
                    if (dialog.ShowDialog() == true)
                    {
                        var selectedDevice = smcDevices[dialog.SelectedIndex];
                        _logMessage($"[DHCP] User selected device: {selectedDevice.ip}");
                        tcs.SetResult(selectedDevice.ip);
                    }
                    else
                    {
                        _logMessage("[DHCP] User cancelled device selection");
                        tcs.SetResult(null);
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"[DHCP] Error during device selection: {ex.Message}");
                    tcs.SetException(ex);
                }
            });
            
            return tcs.Task;
        }

        public async Task<string> DetermineBmcIp(string smcIp)
        {
            _logMessage($"[Debug] Testing management interface connectivity");
            
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(smcIp, 500);
                    if (reply.Status != IPStatus.Success)
                    {
                        _logMessage($"Cannot connect to SMC, please verify IP address");
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
                        _logMessage($"SSH connection failed: {ex.Message}");
                        return null;
                    }

                    foreach (string ip in _bmcIps)
                    {
                        _logMessage($"[Debug] Testing {ip}");
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
                                        _logMessage($"[Debug] Successfully pinged BMC IP: {ip}");
                                        return ip;
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    _logMessage($"[Debug] {ip} test timeout, trying next");
                                    continue;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logMessage($"[Debug] Error testing {ip}: {ex.Message}");
                        }
                    }

                    client.Disconnect();
                }
            }
            catch (Exception ex)
            {
                _logMessage($"[Debug] Connectivity test error: {ex.Message}");
            }

            _logMessage("All management interface IPs are unreachable");
            return null;
        }
    }
}