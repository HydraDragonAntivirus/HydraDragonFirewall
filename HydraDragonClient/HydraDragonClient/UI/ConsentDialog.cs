using System;
using System.Drawing;
using System.Windows.Forms;

namespace HydraDragonClient.UI
{
    /// <summary>
    /// Dialog for user consent when someone tries to connect
    /// </summary>
    public class ConsentDialog : Form
    {
        private readonly Label _messageLabel;
        private readonly Button _acceptButton;
        private readonly Button _denyButton;
        private readonly System.Windows.Forms.Timer _timeoutTimer;
        private int _remainingSeconds = 30;

        public bool Accepted { get; private set; }

        public ConsentDialog(string remoteAddress, string clientName)
        {
            // Form setup
            Text = "Connection Request";
            Size = new Size(400, 200);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            TopMost = true;
            BackColor = Color.FromArgb(45, 45, 48);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10);
            KeyPreview = true;

            // Message label
            _messageLabel = new Label
            {
                Text = $"Connection request from:\n\n{clientName}\n({remoteAddress})\n\nAccept connection? ({_remainingSeconds}s)",
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Top,
                Height = 100
            };

            // Button panel
            var buttonPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Bottom,
                Height = 50,
                Padding = new Padding(10)
            };

            _acceptButton = new Button
            {
                Text = "Accept (Enter)",
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(0, 122, 204),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                TabIndex = 0
            };
            _acceptButton.FlatAppearance.BorderSize = 0;
            _acceptButton.Click += (s, e) => { Accepted = true; Close(); };

            _denyButton = new Button
            {
                Text = "Deny (Esc)",
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(200, 60, 60),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                TabIndex = 1
            };
            _denyButton.FlatAppearance.BorderSize = 0;
            _denyButton.Click += (s, e) => { Accepted = false; Close(); };

            buttonPanel.Controls.Add(_acceptButton);
            buttonPanel.Controls.Add(_denyButton);

            Controls.Add(_messageLabel);
            Controls.Add(buttonPanel);

            // Timeout timer
            _timeoutTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _timeoutTimer.Tick += (s, e) =>
            {
                _remainingSeconds--;
                if (_remainingSeconds <= 0)
                {
                    Accepted = false;
                    Close();
                }
                else
                {
                    _messageLabel.Text = $"Connection request from:\n\n{clientName}\n({remoteAddress})\n\nAccept connection? ({_remainingSeconds}s)";
                }
            };
            _timeoutTimer.Start();

            // Keyboard handling
            KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    Accepted = true;
                    Close();
                }
                else if (e.KeyCode == Keys.Escape)
                {
                    Accepted = false;
                    Close();
                }
            };

            // Focus the accept button
            Shown += (s, e) => _acceptButton.Focus();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _timeoutTimer.Stop();
            _timeoutTimer.Dispose();
            base.OnFormClosing(e);
        }
    }
}
