using System;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Linq;
using System.Diagnostics;
using System.Windows;

namespace RemoteBMC
{
    public class DhcpServerManager
    {
        private readonly Action<string> logCallback;
        private const string DHCP_SERVER_IP = "10.10.20.1";
        private const string DHCP_SUBNET_MASK = "255.255.255.0";

        public DhcpServerManager(Action<string> logger)
        {
            logCallback = logger;
        }

        public bool IsInterfaceUsingDhcp(NetworkInterface networkInterface, out bool hasIpFromDhcp)
        {
            hasIpFromDhcp = false;
            try
            {
                if (networkInterface != null)
                {
                    var ipv4Properties = networkInterface.GetIPProperties().GetIPv4Properties();
                    bool isDhcpEnabled = ipv4Properties != null && ipv4Properties.IsDhcpEnabled;

                    // 检查是否是手动配置但IP为空的情况
                    if (!isDhcpEnabled)
                    {                        
                        var ipv4Address = networkInterface.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);
                        if (ipv4Address == null)
                        {
                            LogMessage($"[DHCP] Interface {networkInterface.Name} is using static IP but has no IP configured");
                            return false; // 允许继续使用DHCP服务器模式
                        }
                        
                        // 检查是否已经配置为DHCP服务器IP
                        string ipString = ipv4Address.Address.ToString();
                        if (ipString == DHCP_SERVER_IP)
                        {
                            LogMessage($"[DHCP] Interface {networkInterface.Name} is already configured with DHCP server IP: {ipString}");
                            return false; // 允许继续使用DHCP服务器模式
                        }
                    }

                    if (isDhcpEnabled)
                    {
                        // Check if interface has actually obtained a valid IP from DHCP
                        var ipv4Address = networkInterface.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);
                        
                        if (ipv4Address != null && !IPAddress.IsLoopback(ipv4Address.Address))
                        {
                            // 检查是否是169.254开头的保留IP
                            string ipString = ipv4Address.Address.ToString();
                            if (ipString.StartsWith("169.254"))
                            {
                                LogMessage($"[DHCP] Interface {networkInterface.Name} is using DHCP but has APIPA address: {ipString}");
                                hasIpFromDhcp = false;  // 虽然启用了DHCP，但是获取到的是保留IP，我们认为它没有有效的DHCP分配的IP
                            }
                            else
                            {
                                hasIpFromDhcp = true;  // 有正常的DHCP分配的IP
                                LogMessage($"[DHCP] Interface {networkInterface.Name} DHCP status: Enabled, Has valid IP: {ipString}");
                            }
                        }
                        else
                        {
                            LogMessage($"[DHCP] Interface {networkInterface.Name} is using DHCP but has no IP");
                        }
                    }

                    return isDhcpEnabled;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error checking DHCP status: {ex.Message}");
            }
            return false;
        }

        public async Task<bool> CheckExistingDhcpServer(NetworkInterface selectedNic)
        {
            LogMessage("[DHCP] Checking for existing DHCP servers in subnet...");
            
            try
            {
                // 1. First check if selected interface is using DHCP
                bool hasIpFromDhcp;
                bool isDhcpEnabled = IsInterfaceUsingDhcp(selectedNic, out hasIpFromDhcp);
                if (isDhcpEnabled && hasIpFromDhcp)
                {
                    LogMessage("[DHCP] Selected interface is using DHCP and has a valid IP address, cannot act as DHCP server");
                    await Task.Run(() => 
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            MessageBox.Show(
                                "The selected network interface is using DHCP and has a valid IP address.\n" +
                                "To avoid conflicts, you cannot run as DHCP server on this interface.\n" +
                                "Please either:\n" +
                                "1. Select a different network interface\n" +
                                "2. Change the interface to use static IP\n" +
                                "3. Use the \"As DHCP Client\" mode",
                                "DHCP Configuration Warning",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                        });
                    });
                    return true;
                }
                // 如果网卡未开启DHCP或者开启了但获取到169.254开头的IP，允许继续使用DHCP服务器模式
                return false;
            }
            catch (Exception ex)
            {
                LogMessage($"[DHCP] Error checking for DHCP servers: {ex.Message}");
                return true; // Return true on error to prevent DHCP server start
            }
        }

        private byte[] BuildDhcpDiscoverPacket()
        {
            byte[] packet = new byte[244];
            packet[0] = 0x01; // Boot Request
            packet[1] = 0x01; // Hardware Type: Ethernet
            packet[2] = 0x06; // Hardware Address Length
            packet[3] = 0x00; // Hops
            
            // Transaction ID (random)
            var transactionId = new byte[4];
            new Random().NextBytes(transactionId);
            Array.Copy(transactionId, 0, packet, 4, 4);

            // Client MAC address (random)
            var clientMac = new byte[6];
            new Random().NextBytes(clientMac);
            Array.Copy(clientMac, 0, packet, 28, 6);

            // Magic Cookie
            packet[236] = 99;
            packet[237] = 130;
            packet[238] = 83;
            packet[239] = 99;

            // DHCP Message Type = DISCOVER
            packet[240] = 53;  // Option: DHCP Message Type
            packet[241] = 1;   // Length
            packet[242] = 1;   // DISCOVER
            packet[243] = 255; // End Option

            return packet;
        }

        public async Task<bool> ConfigureInterface(string interfaceName)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"interface ip set address \"{interfaceName}\" static {DHCP_SERVER_IP} {DHCP_SUBNET_MASK}",
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
                    LogMessage($"Failed to configure network interface: {error}");
                    MessageBox.Show(
                        "Failed to configure network interface. Please ensure the program is running with administrator privileges", 
                        "Error", 
                        MessageBoxButton.OK, 
                        MessageBoxImage.Error);
                    return false;
                }

                LogMessage("Network interface configured successfully");
                return true;
            }
            catch (Exception ex)
            {
                LogMessage($"Error configuring network interface: {ex.Message}");
                return false;
            }
        }

        public async Task StartDhcpServer()
        {
            try
            {
                // Install DHCP server service
                var installProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dhcpsrv.exe",
                        Arguments = "-install",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                installProcess.Start();
                await WaitForProcessExit(installProcess);
                LogMessage("DHCP server service installed");

                // Start DHCP server service
                var startProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dhcpsrv.exe",
                        Arguments = "-start",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                startProcess.Start();
                await WaitForProcessExit(startProcess);
                LogMessage("DHCP server service started");
            }
            catch (Exception ex)
            {
                LogMessage($"Error starting DHCP server: {ex.Message}");
                throw;
            }
        }

        public async Task StopDhcpServer()
        {
            try
            {
                // First stop the DHCP server
                var stopProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dhcpsrv.exe",
                        Arguments = "-stop",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                stopProcess.Start();
                await WaitForProcessExit(stopProcess);
                LogMessage("DHCP server service stopped");

                // Then remove the DHCP server
                var removeProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dhcpsrv.exe",
                        Arguments = "-remove",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                removeProcess.Start();
                await WaitForProcessExit(removeProcess);
                LogMessage("DHCP server service removed");
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping/removing DHCP server: {ex.Message}");
                throw;
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

        public async Task StimulateSmcDhcpRequest(string interfaceName)
        {
            LogMessage("Attempting to stimulate SMC DHCP request...");
            
            try
            {
                // 1. 发送广播ping
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ping",
                        Arguments = "-n 3 -w 100 255.255.255.255",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);

                // 2. 发送ARP广播
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-d *",  // 清除ARP缓存
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);

                // 3. 临时禁用和启用网络接口
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"interface set interface \"{interfaceName}\" disable",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);
                
                await Task.Delay(2000); // Wait 2 seconds

                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"interface set interface \"{interfaceName}\" enable",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);

                LogMessage("Network interface reset, waiting for SMC response...");
            }
            catch (Exception ex)
            {
                LogMessage($"Error while stimulating DHCP request: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            logCallback?.Invoke(message);
        }
    }
}