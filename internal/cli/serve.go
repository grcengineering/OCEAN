package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/api"
	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/module"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	awscollector "github.com/grcengineering/ocean/modules/collectors/aws"
	githubcollector "github.com/grcengineering/ocean/modules/collectors/github"
	mockcollector "github.com/grcengineering/ocean/modules/collectors/mock"
	oktacollector "github.com/grcengineering/ocean/modules/collectors/okta"
)

var (
	servePort      int
	serveAuthToken string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the OCEAN HTTP server for dashboard and API access",
	Long: `Start the OCEAN REST API server, providing HTTP endpoints for querying
evidence, control status, attestations, and module metadata.

The server requires a Bearer token for authentication on all endpoints
except the health check. Set the token via --auth-token flag or the
OCEAN_AUTH_TOKEN environment variable.

Example:
  ocean serve --port 8080 --auth-token my-secret-token`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 0, "port to listen on (default from config or 8080)")
	serveCmd.Flags().StringVar(&serveAuthToken, "auth-token", "", "Bearer token for API authentication (or OCEAN_AUTH_TOKEN env)")
}

func runServe(cmd *cobra.Command, args []string) error {
	// Load configuration.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	config.SetupLogging(cfg)

	// Determine port: flag > config > default.
	port := cfg.Server.Port
	if servePort != 0 {
		port = servePort
	}
	if port == 0 {
		port = 8080
	}

	// Determine auth token: flag > env > config.
	authToken := cfg.Server.AuthToken
	if envToken := os.Getenv("OCEAN_AUTH_TOKEN"); envToken != "" {
		authToken = envToken
	}
	if serveAuthToken != "" {
		authToken = serveAuthToken
	}

	if authToken == "" {
		return fmt.Errorf("authentication token is required: use --auth-token flag or OCEAN_AUTH_TOKEN environment variable")
	}

	// Open storage.
	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Build module registry.
	reg := module.NewRegistry()
	mockcollector.RegisterAll(reg)
	oktacollector.RegisterAll(reg)
	awscollector.RegisterAll(reg)
	githubcollector.RegisterAll(reg)

	// Load control definitions if controls directory exists.
	controlsDir := expandPath(cfg.ControlsDir)
	var controls []*control.Control
	if info, statErr := os.Stat(controlsDir); statErr == nil && info.IsDir() {
		controls, err = control.LoadAllControls(controlsDir)
		if err != nil {
			log.Warn().Err(err).Str("dir", controlsDir).Msg("failed to load some controls")
		}
	}

	// Create and configure the API server.
	srv := api.NewServer(store, reg, authToken, port)
	srv.Version = version
	srv.SetControls(controls)

	// Set up graceful shutdown on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
		cancel()
	}()

	log.Info().Int("port", port).Msg("starting OCEAN API server")
	return srv.ListenAndServe(ctx)
}
