package seedsetup

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const Usage = "keyvault-seed --nostr-identity NAME --namecoin-identity NAME [--version N --nostr-version N --namecoin-version N] [--qualification-nostr-identity NAME --qualification-namecoin-identity NAME] [--artifact-dir DIRECTORY]"

// Run runs the attended release workflow. Every argument and output is public.
// Missing build pins refuse before custody; no unsigned dev mode is provided.
func Run(args []string, release Release, out, diag io.Writer) int {
	// A broken output pipe must return an error so a post-mutation receipt
	// failure can still emit a diagnostic on stderr.
	if !signal.Ignored(syscall.SIGPIPE) {
		broken := make(chan os.Signal, 1)
		signal.Notify(broken, syscall.SIGPIPE)
		defer signal.Stop(broken)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		if writePublic(out, Usage+"\n") != nil {
			return 1
		}
		return 0
	}
	config, err := Parse(args)
	if err != nil {
		_ = writePublic(diag, Usage+"\n")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
	defer cancel()
	if err := runAttended(ctx, config, release, out); err != nil {
		_ = writePublic(diag, "keyvault-seed: "+err.Error()+"\n")
		return 1
	}
	return 0
}

func runAttended(ctx context.Context, c Config, release Release, out io.Writer) error {
	if err := release.validate(); err != nil {
		return err
	}
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() {
		return refused("current_unprivileged_user_required")
	}
	current, accountErr := user.Current()
	home, homeErr := os.UserHomeDir()
	if accountErr != nil || homeErr != nil || current.Uid != strconv.Itoa(os.Getuid()) || current.HomeDir != home {
		return refused("current_os_home_required")
	}
	self, err := os.Executable()
	if err != nil {
		return refused("self_executable_unavailable")
	}
	resolvedSelf, err := filepath.EvalSymlinks(self)
	if err != nil || resolvedSelf != self {
		return refused("self_path_unsafe")
	}
	paths, err := UserPaths(home, self, c.ArtifactDirectory, release.Version, release.Source)
	if err != nil {
		return err
	}
	ids, err := SelectIdentities(c, rand.Reader)
	if err != nil {
		return err
	}
	lock, err := keyvault.DefaultFileLock()
	if err != nil || lock.Path != paths.Lock || lock.BootstrapDir != home {
		return refused("vault_plan_lock_unavailable")
	}
	p := installation{paths: paths, release: release, uid: uint32(os.Getuid())}
	w := workflow{
		planner: keyvault.NewRecoveryPlanner(keyvault.NewRecoveryInventory(), lock),
		out:     out,
		run:     func(binary string, argv ...string) invocation { return command(ctx, home, binary, argv...) },
		restore: func(binary string, t publicTarget) invocation { return publicFixtureRestore(ctx, home, binary, t) },
		prompt:  func(message string, limit int) (string, error) { return publicPrompt(ctx, message, limit) },
	}
	return execute(ctx, p, w, c, ids)
}

func makeCommand(ctx context.Context, home, binary string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = childEnv(home)
	cmd.WaitDelay = 8 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	return cmd
}

func childExit(ctx context.Context, err error) int {
	if ctx.Err() != nil {
		return -1
	}
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return -1
	}
	return exit.ExitCode()
}

func command(parent context.Context, home, binary string, args ...string) invocation {
	budget := 30 * time.Second
	if len(args) > 2 && args[0] == "--json" && args[1] == "recovery" && args[2] == "generate" {
		budget = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	cmd := makeCommand(ctx, home, binary, args)
	// The actual vault inherits the process group, and independently opens its
	// controlling terminal. We capture only its closed public JSON pipe.
	stdout, stderr := &capped{limit: 32768}, &capped{limit: 8192}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return invocation{}
	}
	exit := childExit(ctx, cmd.Wait())
	return checkCappedOutput(stdout, stderr, exit, binary == "/usr/bin/codesign")
}
