using System;
using System.Drawing;
using System.Windows.Forms;

namespace HydraDragonClient.UI
{
    /// <summary>
    /// Connection dialog with keyboard-focused design
    /// </summary>
    public class ConnectDialog : Form
    {
        private readonly TextBox _hostTextBox;
        private readonly TextBox _portTextBox;
        private readonly TextBox _passwordTextBox;
        private readonly Button _connectButton;
        private readonly Button _cancelButton;

        public string Host => _hostTextBox.Text.Trim();
        public int Port => int.TryParse(_portTextBox.Text, out var p) ? p : 9876;
        public string Password => _passwordTextBox.Text;
        public bool Confirmed { get; private set; }

        public ConnectDialog(string defaultHost = "", int defaultPort = 9876)
        {
            // Form setup
            Text = "Connect to Remote";
            Size = new Size(400, 280);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            BackColor = Color.FromArgb(45, 45, 48);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 11);
            KeyPreview = true;
            AcceptButton = null; // We'll handle Enter manually

            var y = 20;

            // Host
            Controls.Add(new Label
            {
                Text = "IP Address:",
                Location = new Point(20, y),
                AutoSize = true
            });
            y += 25;

            _hostTextBox = new TextBox
            {
                Location = new Point(20, y),
                Size = new Size(340, 30),
                BackColor = Color.FromArgb(60, 60, 65),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Text = defaultHost,
                TabIndex = 0
            };
            Controls.Add(_hostTextBox);
            y += 45;

            // Port
            Controls.Add(new Label
            {
                Text = "Port:",
                Location = new Point(20, y),
                AutoSize = true
            });
            y += 25;

            _portTextBox = new TextBox
            {
                Location = new Point(20, y),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(60, 60, 65),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Text = defaultPort.ToString(),
                TabIndex = 1
            };
            Controls.Add(_portTextBox);
            y += 45;

            // Password
            Controls.Add(new Label
            {
                Text = "Password:",
                Location = new Point(20, y),
                AutoSize = true
            });
            y += 25;

            _passwordTextBox = new TextBox
            {
                Location = new Point(20, y),
                Size = new Size(200, 30),
                BackColor = Color.FromArgb(60, 60, 65),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                TabIndex = 2,
                MaxLength = 6
            };
            Controls.Add(_passwordTextBox);

            // Buttons
            _connectButton = new Button
            {
                Text = "Connect",
                Size = new Size(100, 35),
                Location = new Point(160, y + 45),
                BackColor = Color.FromArgb(0, 122, 204),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                TabIndex = 3
            };
            _connectButton.FlatAppearance.BorderSize = 0;
            _connectButton.Click += (s, e) => 
            {
                if (ValidateInput())
                {
                    Confirmed = true;
                    Close();
                }
            };
            Controls.Add(_connectButton);

            _cancelButton = new Button
            {
                Text = "Cancel",
                Size = new Size(100, 35),
                Location = new Point(270, y + 45),
                BackColor = Color.FromArgb(80, 80, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                TabIndex = 4
            };
            _cancelButton.FlatAppearance.BorderSize = 0;
            _cancelButton.Click += (s, e) => Close();
            Controls.Add(_cancelButton);

            // Keyboard handling
            KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Escape)
                    Close();
                else if (e.KeyCode == Keys.Enter)
                {
                    if (ValidateInput())
                    {
                        Confirmed = true;
                        Close();
                    }
                }
            };
        }

        private bool ValidateInput()
        {
            if (string.IsNullOrWhiteSpace(_hostTextBox.Text))
            {
                MessageBox.Show("Please enter an IP address", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _hostTextBox.Focus();
                return false;
            }

            if (!int.TryParse(_portTextBox.Text, out var port) || port < 1 || port > 65535)
            {
                MessageBox.Show("Please enter a valid port (1-65535)", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _portTextBox.Focus();
                return false;
            }

            if (string.IsNullOrWhiteSpace(_passwordTextBox.Text))
            {
                MessageBox.Show("Please enter the session password", "Validation Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _passwordTextBox.Focus();
                return false;
            }

            return true;
        }
    }
}
