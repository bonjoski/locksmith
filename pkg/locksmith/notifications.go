package locksmith

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Notifier handles expiration notifications
type Notifier struct {
	config *Config
}

// NewNotifier creates a new notifier with the given config
func NewNotifier(config *Config) *Notifier {
	return &Notifier{config: config}
}

// NotifyExpiration sends expiration notification based on config
func (n *Notifier) NotifyExpiration(key string, secret *Secret) {
	// Check if notifications are enabled
	if n.config.Notifications.Method == "silent" {
		return
	}

	// Check if secret is expiring or expired
	threshold, _ := n.config.GetExpiringThreshold()
	status := secret.GetExpirationStatus(threshold)

	if status == StatusValid {
		return
	}

	message := n.formatMessage(key, secret, status)

	switch n.config.Notifications.Method {
	case "stderr":
		n.notifyStderr(message)
	case "macos":
		n.notifyMacOS(message)
	}
}

func (n *Notifier) formatMessage(key string, secret *Secret, status ExpirationStatus) string {
	timeLeft := secret.TimeUntilExpiration()

	if status == StatusExpired {
		return fmt.Sprintf("Warning: Secret '%s' expired %s ago", key, formatDuration(-timeLeft))
	}

	return fmt.Sprintf("Warning: Secret '%s' expires in %s", key, formatDuration(timeLeft))
}

func (n *Notifier) notifyStderr(message string) {
	fmt.Fprintln(os.Stderr, message)
}

func (n *Notifier) notifyMacOS(message string) {
	// Use %q to safely escape the message for AppleScript, preventing injection
	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification %q with title "Locksmith"`, message))
	_ = cmd.Run() // Ignore errors
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%d days", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}
