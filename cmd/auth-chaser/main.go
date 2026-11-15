package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Romstar/auth-chaser/internal/checks/packs"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/report"
	"github.com/Romstar/auth-chaser/internal/runner"
	"github.com/Romstar/auth-chaser/internal/server"
	"github.com/spf13/cobra"
)

var (
	version = "0.2.0"
	commit  = "dev"
)

func main() {
	runner.Version = version
	root := &cobra.Command{
		Use:   "auth-chaser",
		Short: "Defensive authentication and authorization verification tool",
		Long: `auth-chaser verifies authentication and authorization on applications
you own or are authorized to test. Checks are non-destructive, scoped,
rate-limited, and require an explicit authorization confirmation.`,
	}

	root.AddCommand(newCheckCmd(), newServeCmd(), newVersionCmd(), newListChecksCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("auth-chaser %s (%s)\n", version, commit)
		},
	}
}

func newListChecksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-checks",
		Short: "List built-in check packs and check IDs",
		Run: func(_ *cobra.Command, _ []string) {
			for _, p := range packs.List() {
				fmt.Printf("%s — %s\n", p.ID, p.Title)
				for _, c := range p.Checks {
					fmt.Printf("  - %s: %s\n", c.ID, c.Title)
				}
				fmt.Println()
			}
		},
	}
}

func newCheckCmd() *cobra.Command {
	var (
		cfgPath           string
		target            string
		confirmAuthorized bool
		format            string
		enableAuth        bool
		enableMisconfig   bool
		enableRBAC        bool
		maxRequests       int
		rps               float64
		browser           bool
		packList          string
		failOnCritical    bool
	)

	cmd := &cobra.Command{
		Use:           "check",
		Short:         "Run non-destructive auth/authz checks against a target",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			if target != "" {
				cfg.Target.BaseURL = target
			}
			if confirmAuthorized {
				cfg.Safety.ConfirmAuthorized = true
			}
			if cmd.Flags().Changed("auth") {
				cfg.Checks.Auth = enableAuth
			}
			if cmd.Flags().Changed("misconfig") {
				cfg.Checks.Misconfig = enableMisconfig
			}
			if cmd.Flags().Changed("rbac") {
				cfg.Checks.RBAC = enableRBAC
			}
			if cmd.Flags().Changed("max-requests") {
				cfg.Safety.MaxRequests = maxRequests
			}
			if cmd.Flags().Changed("rps") {
				cfg.Safety.RequestsPerSecond = rps
			}
			if browser {
				cfg.Browser.Enabled = true
				cfg.Safety.AllowBrowser = true
			}
			if packList != "" {
				parts := strings.Split(packList, ",")
				cleaned := make([]string, 0, len(parts))
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						cleaned = append(cleaned, p)
					}
				}
				cfg.Checks.Packs = cleaned
			}
			cfg.Normalize()

			if !cfg.Safety.ConfirmAuthorized {
				return fmt.Errorf("authorization not confirmed: set safety.confirm_authorized=true or pass --confirm-authorized")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()

			r := runner.New(cfg)
			fmt.Fprintf(os.Stderr, "auth-chaser: %s\n", r.Describe())
			rep, err := r.Run(ctx)
			if err != nil {
				return err
			}

			switch format {
			case "json":
				if err := report.WriteJSON(os.Stdout, rep); err != nil {
					return err
				}
			case "sarif":
				if err := report.WriteSARIF(os.Stdout, rep); err != nil {
					return err
				}
			default:
				if err := report.WriteText(os.Stdout, rep); err != nil {
					return err
				}
			}
			if failOnCritical && rep.HasCriticalFail() {
				return fmt.Errorf("critical findings failed")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "Path to chase YAML config")
	cmd.Flags().StringVarP(&target, "target", "t", "", "Target base URL (overrides config)")
	cmd.Flags().BoolVar(&confirmAuthorized, "confirm-authorized", false, "Confirm you own or are authorized to test the target")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text|json|sarif")
	cmd.Flags().BoolVar(&enableAuth, "auth", true, "Include auth-related packs when packs unset")
	cmd.Flags().BoolVar(&enableMisconfig, "misconfig", true, "Include misconfig pack when packs unset")
	cmd.Flags().BoolVar(&enableRBAC, "rbac", false, "Include RBAC pack when packs unset")
	cmd.Flags().IntVar(&maxRequests, "max-requests", 80, "Maximum outbound HTTP requests")
	cmd.Flags().Float64Var(&rps, "rps", 2, "Requests per second rate limit")
	cmd.Flags().BoolVar(&browser, "browser", false, "Enable Chrome browser automation for JS/MFA/passkey gaps")
	cmd.Flags().StringVar(&packList, "packs", "", "Comma-separated pack IDs (overrides defaults)")
	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", false, "Exit non-zero when any critical finding fails")
	return cmd
}

func newServeCmd() *cobra.Command {
	var (
		addr     string
		dataDir  string
		apiToken string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the self-hostable SaaS HTTP API and UI",
		RunE: func(_ *cobra.Command, _ []string) error {
			return server.New(server.Options{
				Addr:     addr,
				DataDir:  dataDir,
				APIToken: apiToken,
			}).ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "Listen address")
	cmd.Flags().StringVar(&dataDir, "data-dir", ".auth-chaser-data", "Directory for SQLite job store")
	cmd.Flags().StringVar(&apiToken, "api-token", "", "Optional API bearer token (or AUTH_CHASER_API_TOKEN)")
	return cmd
}
