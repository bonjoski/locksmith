package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var (
	daemonSocketPath    string
	daemonDefaultTTL    time.Duration
	daemonWatchInterval time.Duration
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the resident Locksmith Ephemeral Lease Manager daemon",
	Long: `Starts the Locksmith background IPC daemon on a local UNIX socket.
The daemon manages ephemeral credential leases for Airlock and agentic runtimes,
performing biometric authentication, process liveness monitoring, and memory sanitization.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		if daemonSocketPath == "" {
			daemonSocketPath = locksmith.DefaultSocketPath()
		}

		lmOpts := locksmith.LeaseManagerOptions{
			DefaultTTL:    daemonDefaultTTL,
			MaxTTL:        1 * time.Hour,
			WatchInterval: daemonWatchInterval,
		}

		lm := locksmith.NewLeaseManager(ls, lmOpts)
		server := locksmith.NewDaemonServer(lm, daemonSocketPath)

		fmt.Printf("Locksmith Ephemeral Lease Daemon listening on UNIX socket: %s\n", daemonSocketPath)
		fmt.Printf("Default Lease TTL: %v | Process Watch Interval: %v\n", daemonDefaultTTL, daemonWatchInterval)

		return server.ListenAndServe(ctx)
	},
}

func init() {
	daemonCmd.Flags().StringVar(&daemonSocketPath, "socket", "", "Path to UNIX domain socket (defaults to ~/.locksmith/locksmith.sock)")
	daemonCmd.Flags().DurationVar(&daemonDefaultTTL, "ttl", 5*time.Minute, "Default ephemeral lease TTL")
	daemonCmd.Flags().DurationVar(&daemonWatchInterval, "watch-interval", 500*time.Millisecond, "Process liveness polling interval")
	rootCmd.AddCommand(daemonCmd)
}
