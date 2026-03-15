package clitoken

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

type Opener interface {
	// Open opens the provided URL in the user's browser
	Open(ctx context.Context, url string) error
}

// OpenerReturner is an extended Opener that can also return the user back to
// the calling application on completion of the auth flow.
type OpenerReturner interface {
	Opener
	// CanReturn returns true if the opener can return the user back to the
	// calling application on completion of the auth flow.
	CanReturn() bool
	// Return returns the user back to the calling application on completion of
	// the auth flow. If an error is returned, this will abort the auth flow and
	// return an error to the caller.
	Return(context.Context) error
}

// DetectOpener attempts to find the best opener for a user's system. If there
// is no best opener for the system, it defaults to an opener that prints the
// URL to the console so the user can click on it.
func DetectOpener() Opener {
	switch runtime.GOOS {
	case "darwin":
		return &MacOSOpenerReturner{}
	case "linux":
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return &CommandOpener{CommandName: path}
		}
	}
	return &EchoOpener{}
}

var _ Opener = (*CommandOpener)(nil)

// CommandOpener implements the [Opener] interface and opens a URL by executing
// a command with the URL. CommandOpener works well with MacOS's `open` command.
type CommandOpener struct {
	// CommandName is the name of the command to execute.
	CommandName string
	// CommandArgs are the arguments to pass to the command. The special
	// argument `$$url$$` will be replaced with the URL to open. If no args are
	// provided, the CommandName will be executed with the URL as the first
	// argument.
	CommandArgs []string
	// PromptFn is a function that will be called before executing the open
	// command. If this returns an error the auth flow will be aborted and an
	// error will be returned to the caller. If not set, the auth will continue
	// automatically.
	PromptFn func(ctx context.Context, url string) error
}

func (o *CommandOpener) Open(ctx context.Context, url string) error {
	if o.CommandName == "" {
		return fmt.Errorf("CommandName is not set")
	}
	var args []string
	if len(o.CommandArgs) == 0 {
		args = []string{url}
	} else {
		args = make([]string, 0, len(o.CommandArgs))
		for _, arg := range o.CommandArgs {
			if arg == "$$url$$" {
				args = append(args, url)
				continue
			}
			args = append(args, arg)
		}
	}

	if o.PromptFn != nil {
		if err := o.PromptFn(ctx, url); err != nil {
			return err
		}
	}

	cmd := exec.CommandContext(ctx, o.CommandName, args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var _ OpenerReturner = (*MacOSOpenerReturner)(nil)

// DefaultMacOSTerminalNames is a default map of TERM_PROGRAM to the Mac App name
// is corresponds to.
var DefaultMacOSTerminalNames = map[string]string{
	"Apple_Terminal": "Terminal",
	"ghostty":        "Ghostty",
	"iTerm.app":      "iTerm2",
}

// MacOSOpenerReturner implements the [OpenerReturner] interface and opens a URL
// by executing a command with the URL. It will use osascript/AppleScript to
// return to the calling terminal after auth is complete, if the terminal is in
// the configured list.
type MacOSOpenerReturner struct {
	// CommandName is the name of the command to execute. Defaults to `open`.
	CommandName string
	// CommandArgs are the arguments to pass to the command. The special
	// argument `$$url$$` will be replaced with the URL to open. If no args are
	// provided, the CommandName will be executed with the URL as the first
	// argument.
	CommandArgs []string
	// PromptFn is a function that will be called before executing the open
	// command. If this returns an error the auth flow will be aborted and an
	// error will be returned to the caller. If not set, the auth will continue
	// automatically.
	PromptFn func(ctx context.Context, url string) error
	// TerminalNames is a map of TERM_PROGRAM to the Mac App name is corresponds
	// to. If not set, [DefaultMacOSTerminalNames] will be used. This will be
	// used to look up the calling terminal, and return to it using osascript.
	TerminalNames map[string]string
}

func (o *MacOSOpenerReturner) Open(ctx context.Context, url string) error {
	co := &CommandOpener{
		CommandName: o.CommandName,
		CommandArgs: o.CommandArgs,
		PromptFn:    o.PromptFn,
	}
	if o.CommandName == "" {
		co.CommandName = "open"
	}

	return co.Open(ctx, url)
}

func (o *MacOSOpenerReturner) CanReturn() bool {
	_, ok := o.terminalNames()[os.Getenv("TERM_PROGRAM")]
	return ok
}

func (o *MacOSOpenerReturner) Return(ctx context.Context) error {
	openScript := `on run argv
	tell application (item 1 of argv) to activate
end run`

	appName, ok := o.terminalNames()[os.Getenv("TERM_PROGRAM")]
	if !ok {
		return fmt.Errorf("TERM_PROGRAM is not set or not in the configured map")
	}

	cmd := exec.CommandContext(ctx, "osascript", "-e", openScript, appName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (o *MacOSOpenerReturner) terminalNames() map[string]string {
	if o.TerminalNames != nil {
		return o.TerminalNames
	}
	return DefaultMacOSTerminalNames
}

// EchoOpener opens a URL by printing it to the console for the user to
// manually click on. It is used as a last resort.
type EchoOpener struct{}

func (o *EchoOpener) Open(ctx context.Context, url string) error {
	_, err := fmt.Fprintf(os.Stderr, "To continue, open this URL in a browser: %s\n", url)
	return err
}
