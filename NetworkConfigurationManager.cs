using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using System.Net.Sockets;
using System.Linq;
using System.Collections.Generic;
using System.Net;

namespace RemoteBMC
{
    public class NetworkConfigurationManager
    {
        private readonly Action<string> _logMessage;
        private string _originalIpAddress;
        private string _originalSubnetMask;
        private string _originalGateway;
        private string _lastConfiguredInterface;
        private bool _originalIsDhcp;

        public NetworkConfigurationManager(Action<string> logMessage)
        {
            _logMessage = logMessage;
        }

        public List<NetworkInterface> GetNetworkInterfaces()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                       ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToList();
        }

        public string GetLocalIpAddress(string interfaceName, List<NetworkInterface> networkInterfaces)
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
                _logMessage($"Failed to get local IP address: {ex.Message}");
            }
            return null;
        }

        public void SaveNetworkConfiguration(string interfaceName)
        {
            try
            {
                var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.Name == interfaceName);

                if (networkInterface != null)
                {
                    var ipProperties = networkInterface.GetIPProperties();
                    var ipv4Properties = ipProperties.GetIPv4Properties();
                    var ipAddress = ipProperties.UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);

                    _originalIsDhcp = ipv4Properties.IsDhcpEnabled;
                    _lastConfiguredInterface = interfaceName;

                    if (ipAddress != null)
                    {
                        _originalIpAddress = ipAddress.Address.ToString();
                        _originalSubnetMask = ipAddress.IPv4Mask.ToString();

                        var gateway = ipProperties.GatewayAddresses
                            .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                        _originalGateway = gateway?.Address.ToString();
                    }

                    _logMessage($"Saved network configuration for interface {interfaceName}");
                }
            }
            catch (Exception ex)
            {
                _logMessage($"Failed to save network configuration: {ex.Message}");
            }
        }

        public async Task RestoreNetworkConfiguration()
        {
            if (string.IsNullOrEmpty(_lastConfiguredInterface))
            {
                return;
            }

            try
            {
                _logMessage("[Network Config] Restoring original network configuration...");
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = _originalIsDhcp ?
                            $"interface ip set address \"{_lastConfiguredInterface}\" dhcp" :
                            $"interface ip set address \"{_lastConfiguredInterface}\" static {_originalIpAddress} {_originalSubnetMask}" + 
                            (string.IsNullOrEmpty(_originalGateway) ? "" : $" {_originalGateway} 1"),
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };
                
                process.Start();
                await WaitForProcessExit(process);
                
                _logMessage("[Network Config] Network configuration restored");
            }
            catch (Exception ex)
            {
                _logMessage($"[Network Config] Failed to restore network configuration: {ex.Message}");
                MessageBox.Show($"Failed to restore network configuration: {ex.Message}", 
                              "Error", 
                              MessageBoxButton.OK, 
                              MessageBoxImage.Error);
            }
        }

        private async Task WaitForProcessExit(Process process)
        {
            await Task.Run(() =>
            {
                process.WaitForExit();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                
                if (!string.IsNullOrEmpty(error))
                {
                    _logMessage($"Process error output: {error}");
                }
                if (!string.IsNullOrEmpty(output))
                {
                    _logMessage($"Process output: {output}");
                }
            });
        }
    }
}