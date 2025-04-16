using System.Windows;

namespace RemoteBMC
{
    public partial class HelpImageDialog : Window
    {
        public HelpImageDialog(string imagePath)
        {
            InitializeComponent();
            HelpImage.Source = new System.Windows.Media.Imaging.BitmapImage(new System.Uri(imagePath, System.UriKind.Relative));
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}