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
        private List<SshClient> _activeSshClients = new List<SshClient>();

        public bool IsConnected => _activeSshClients.Any(client => client.IsConnected);
        private List<ForwardedPortLocal> _activeForwardedPorts = new List<ForwardedPortLocal>();
        private const string SSH_PASSWORD = "remora";
        private const int SSH_PORT = 22;

        public SshConnectionManager(Action<string> logMessage)
        {
            _logMessage = logMessage;
        }

        public async Task SetupSshForwarding(string smcIp, string bmcIp, int localPort, int remotePort)
        {
            try
            {
                var client = new SshClient(smcIp, "root", SSH_PASSWORD);
                client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(5);
                await Task.Run(() => client.Connect());

                var forwardedPort = new ForwardedPortLocal("127.0.0.1", (uint)localPort, bmcIp, (uint)remotePort);
                client.AddForwardedPort(forwardedPort);
                await Task.Run(() => forwardedPort.Start());

                _activeSshClients.Add(client);
                _activeForwardedPorts.Add(forwardedPort);

                _logMessage($"SSH forwarding set up: {localPort} -> {bmcIp}:{remotePort}");
            }
            catch (Exception ex)
            {
                _logMessage($"Failed to set up SSH forwarding: {ex.Message}");
                throw;
            }
        }

        public async Task CleanupConnections()
        {
            // Stop all port forwarding
            foreach (var port in _activeForwardedPorts)
            {
                try
                {
                    if (port.IsStarted)
                    {
                        await Task.Run(() => port.Stop());
                        _logMessage($"Stopped port forwarding on port {port.BoundPort}");
                    }
                }
                catch (Exception ex)
                {
                    _logMessage($"Error stopping port forward: {ex.Message}");
                }
            }
            _activeForwardedPorts.Clear();

            // Disconnect all SSH connections
            foreach (var client in _activeSshClients)
            {
                try
                {
                    if (client.IsConnected)
                    {
                        await Task.Run(() => client.Disconnect());
                        _logMessage("Disconnected SSH client");
                    }
                    client.Dispose();
                }
                catch (Exception ex)
                {
                    _logMessage($"Error disconnecting SSH: {ex.Message}");
                }
            }
            _activeSshClients.Clear();
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
                _activeSshClients.Add(client);
                _logMessage($"SSH connection saved");
            }
        }

        public void CloseAllConnections()
        {
            foreach (var port in _activeForwardedPorts.Where(p => p.IsStarted))
            {
                port.Stop();
                port.Dispose();
            }
            _activeForwardedPorts.Clear();

            foreach (var client in _activeSshClients.Where(c => c.IsConnected))
            {
                client.Disconnect();
                client.Dispose(); 
            }
            _activeSshClients.Clear();
        }
    }
}