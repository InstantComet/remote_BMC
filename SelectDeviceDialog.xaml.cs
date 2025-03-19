using System.Collections.Generic;
using System.Windows;
using System.Linq;
using System.Net;

namespace RemoteBMC
{
    public partial class SelectDeviceDialog : Window
    {
        private List<(string deviceInfo, int originalIndex)> sortedDevices;
        public int SelectedIndex { get; private set; }

        public SelectDeviceDialog(List<string> devices)
        {
            InitializeComponent();
            
            // Create list with original indices
            var devicesWithIndices = devices.Select((device, index) => (device, index)).ToList();
            
            // Sort devices by IP address while keeping track of original indices
            sortedDevices = devicesWithIndices.OrderBy(item =>
            {
                // Extract IP address from the device info string
                var ipLine = item.device.Split('\n').First();
                var ip = ipLine.Split(':')[1].Trim();
                
                // Convert IP address to numeric value for proper sorting
                var parts = ip.Split('.');
                if (parts.Length == 4)
                {
                    uint numericIp = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        if (byte.TryParse(parts[i], out byte part))
                        {
                            numericIp = (numericIp << 8) | part;
                        }
                    }
                    return numericIp;
                }
                return uint.MaxValue; // Invalid IPs will be sorted to the end
            }).ToList();

            // Display only the device info in the ListBox
            DeviceListBox.ItemsSource = sortedDevices.Select(x => x.deviceInfo);
            DeviceListBox.SelectedIndex = 0;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (DeviceListBox.SelectedIndex >= 0)
            {
                // Return the original index of the selected device
                SelectedIndex = sortedDevices[DeviceListBox.SelectedIndex].originalIndex;
                DialogResult = true;
            }
            else
            {
                MessageBox.Show("Please select a device", "Notice", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
} 