using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using Renci.SshNet;

namespace RemoteBMC
{
    public class SshConnectionManager
    {
        private readonly Action<string> _logMessage;
        private readonly List<SshClient> _activeConnections = new List<SshClient>();
        private const string SSH_PASSWORD = "remora";
        private const int DEFAULT_TIMEOUT = 30000; // 增加到30秒

        public bool IsConnected => _activeConnections.Any(client => client.IsConnected);
        private List<ForwardedPortLocal> _activeForwardedPorts = new List<ForwardedPortLocal>();
        private const int SSH_PORT = 22;

        public SshConnectionManager(Action<string> logMessage)
        {
            _logMessage = logMessage;
        }

        public async Task SetupSshForwarding(string smcIp, string bmcIp, int localPort, int remotePort)
        {
            try
            {
                _logMessage($"Setting up SSH forwarding for {localPort}->{bmcIp}:{remotePort}...");

                // 先检查并清理端口
                await EnsurePortIsFree(localPort);

                // 创建带有详细配置的ConnectionInfo
                var connectionInfo = new ConnectionInfo(smcIp, 
                    "root", 
                    new PasswordAuthenticationMethod("root", SSH_PASSWORD))
                {
                    Timeout = TimeSpan.FromMilliseconds(DEFAULT_TIMEOUT),
                    RetryAttempts = 3
                };

                // 创建SSH客户端
                var sshClient = new SshClient(connectionInfo);
                
                try
                {
                    _logMessage($"Connecting to {smcIp}...");
                    await Task.Run(() => sshClient.Connect());

                    if (!sshClient.IsConnected)
                    {
                        throw new Exception("Failed to establish SSH connection");
                    }

                    _logMessage("SSH connection established successfully");

                    // 在创建端口转发之前再次确保端口空闲
                    await EnsurePortIsFree(localPort);

                    // 创建端口转发
                    var forwarder = new ForwardedPortLocal("127.0.0.1", (uint)localPort, bmcIp, (uint)remotePort);
                    sshClient.AddForwardedPort(forwarder);

                    _logMessage($"Starting port forwarding {localPort}->{bmcIp}:{remotePort}");
                    
                    // 使用超时机制启动端口转发
                    var startTask = Task.Run(() => forwarder.Start());
                    if (await Task.WhenAny(startTask, Task.Delay(5000)) != startTask)
                    {
                        throw new TimeoutException("Port forwarding start timed out");
                    }

                    if (!forwarder.IsStarted)
                    {
                        throw new Exception("Port forwarding failed to start");
                    }

                    _logMessage($"Port forwarding established successfully");
                    
                    // 添加到活动列表中
                    lock (_activeConnections)
                    {
                        _activeConnections.Add(sshClient);
                    }
                    lock (_activeForwardedPorts)
                    {
                        _activeForwardedPorts.Add(forwarder);
                    }
                }
                catch
                {
                    if (sshClient.IsConnected)
                    {
                        sshClient.Disconnect();
                    }
                    sshClient.Dispose();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logMessage($"Failed to set up SSH forwarding: {ex.Message}");
                if (ex.InnerException != null)
                {
                    _logMessage($"Inner exception: {ex.InnerException.Message}");
                }
                throw;
            }
        }

        // 添加新的方法确保端口空闲
        private async Task EnsurePortIsFree(int port)
        {
            try
            {
                _logMessage($"Ensuring port {port} is free...");
                
                // 检查端口是否被使用
                var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpListeners = ipProperties.GetActiveTcpListeners();
                var connections = ipProperties.GetActiveTcpConnections();
                
                bool portInUse = tcpListeners.Any(ep => ep.Port == port) ||
                               connections.Any(conn => conn.LocalEndPoint.Port == port);

                if (portInUse)
                {
                    _logMessage($"Port {port} is in use, attempting to free it...");
                    await KillPortProcess(port);
                    
                    // 等待端口释放
                    for (int i = 0; i < 3; i++)
                    {
                        await Task.Delay(1000);
                        tcpListeners = ipProperties.GetActiveTcpListeners();
                        connections = ipProperties.GetActiveTcpConnections();
                        portInUse = tcpListeners.Any(ep => ep.Port == port) ||
                                  connections.Any(conn => conn.LocalEndPoint.Port == port);
                        
                        if (!portInUse)
                        {
                            _logMessage($"Port {port} is now free");
                            break;
                        }
                        
                        if (i == 2 && portInUse)
                        {
                            throw new Exception($"Unable to free port {port} after multiple attempts");
                        }
                    }
                }
                else
                {
                    _logMessage($"Port {port} is already free");
                }
            }
            catch (Exception ex)
            {
                _logMessage($"Error ensuring port {port} is free: {ex.Message}");
                throw;
            }
        }

        public async Task CleanupConnections()
        {
            _logMessage("Starting cleanup of all connections...");
            
            // 先停止所有端口转发
            foreach (var port in _activeForwardedPorts.ToList())
            {
                try
                {
                    if (port.IsStarted)
                    {
                        _logMessage($"Stopping port forwarding on port {port.BoundPort}");
                        await Task.Run(() => port.Stop());
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"Error stopping port forward: {ex.Message}");
                }
            }
            _activeForwardedPorts.Clear();

            // 断开所有SSH连接
            foreach (var client in _activeConnections.ToList())
            {
                try
                {
                    if (client.IsConnected)
                    {
                        _logMessage("Disconnecting SSH client");
                        client.Disconnect();
                    }
                    client.Dispose();
                }
                catch (Exception ex)
                {
                    _logMessage($"Error disconnecting SSH: {ex.Message}");
                }
            }
            _activeConnections.Clear();
            
            // 确保所有端口都被释放
            await Task.WhenAll(
                EnsurePortIsFree(8880),
                EnsurePortIsFree(8443)
            );
            
            _logMessage("Cleanup completed");
        }

        public async Task KillPortProcess(int port)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = $"-ano | findstr :{port}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await Task.Run(() => process.WaitForExit());

                foreach (string line in output.Split('\n'))
                {
                    if (line.Contains($":{port} "))
                    {
                        string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 4)
                        {
                            string pidStr = parts[4].Trim();
                            if (int.TryParse(pidStr, out int pid))
                            {
                                var killProcess = new Process
                                {
                                    StartInfo = new ProcessStartInfo
                                    {
                                        FileName = "taskkill",
                                        Arguments = $"/F /PID {pid}",
                                        UseShellExecute = false,
                                        CreateNoWindow = true
                                    }
                                };
                                killProcess.Start();
                                await Task.Run(() => killProcess.WaitForExit());
                                _logMessage($"Killed process using port {port}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logMessage($"Error killing process on port {port}: {ex.Message}");
            }
        }

        public void SaveConnection(SshClient client)
        {
            if (client != null && client.IsConnected)
            {
                _activeConnections.Add(client);
                _logMessage($"SSH connection saved");
            }
        }

        public void CloseAllConnections()
        {
            lock (_activeConnections)
            {
                foreach (var client in _activeConnections)
                {
                    try
                    {
                        if (client.IsConnected)
                        {
                            _logMessage("Disconnecting SSH client...");
                            client.Disconnect();
                        }
                        client.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _logMessage($"Error closing SSH connection: {ex.Message}");
                    }
                }
                _activeConnections.Clear();
            }
        }
    }
}