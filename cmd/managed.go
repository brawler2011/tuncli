package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/AlecAivazis/survey/v2"
	"github.com/brawler2011/tuncli/pkg/service"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var daemonProcess bool

func managedSelect(cmd *cobra.Command) error {
	response, err := service.Call(cmd.Context(), service.Request{Operation: "choices"})
	if err != nil {
		return err
	}
	if len(response.Choices) == 0 {
		return fmt.Errorf("no nodes; use tuncli add")
	}
	labels := make([]string, len(response.Choices))
	for i, c := range response.Choices {
		labels[i] = fmt.Sprintf("[%s] %s", c.Subscription, c.Name)
	}
	var index int
	if err = survey.AskOne(&survey.Select{Message: "Select VPN node:", Options: labels, PageSize: 15}, &index); err != nil {
		return err
	}
	var mode string
	if err = survey.AskOne(&survey.Select{Message: "Select mode:", Options: []string{"tun", "proxy"}}, &mode); err != nil {
		return err
	}
	choice := response.Choices[index]
	_, err = service.Call(cmd.Context(), service.Request{Operation: "select", Mode: mode, Node: choice.Name, Subscription: choice.Subscription})
	return err
}
func serviceCommand(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("missing command")
	}
	switch args[0] {
	case "add", "remove", "update", "list", "routing":
	default:
		return "", fmt.Errorf("command not allowed")
	}
	command, remaining, err := rootCmd.Find(args)
	if err != nil {
		return "", err
	}
	if command == rootCmd || command.RunE == nil {
		return "", fmt.Errorf("unknown command")
	}
	// Each request gets fresh flag values; command handlers are serialized.
	command.Flags().VisitAll(func(f *pflag.Flag) { _ = f.Value.Set(f.DefValue); f.Changed = false })
	if err = command.ParseFlags(remaining); err != nil {
		return "", err
	}
	if err = command.ValidateArgs(command.Flags().Args()); err != nil {
		return "", err
	}
	if err = command.ValidateRequiredFlags(); err != nil {
		return "", err
	}
	output := new(bytes.Buffer)
	command.SetOut(output)
	command.SetErr(output)
	defer func() { command.SetOut(nil); command.SetErr(nil) }()
	err = command.RunE(command, command.Flags().Args())
	return output.String(), err
}

// Installed services own all settings. Wrapping handlers also covers commands
// constructed directly by the command tests, without a second execution path.
func routeManaged(command *cobra.Command) {
	for _, child := range command.Commands() {
		routeManaged(child)
	}
	if command.RunE == nil {
		return
	}
	path := strings.Fields(strings.TrimPrefix(command.CommandPath(), "tuncli "))
	if len(path) == 0 {
		return
	}
	switch path[0] {
	case "add", "remove", "update", "list", "routing":
	default:
		return
	}
	local := command.RunE
	command.RunE = func(cmd *cobra.Command, args []string) error {
		if daemonProcess || !service.Installed() {
			return local(cmd, args)
		}
		// Reconstruct only known flags, excluding persistent framework flags.
		requestArgs := append(append([]string{}, path...), args...)
		cmd.Flags().Visit(func(f *pflag.Flag) { requestArgs = append(requestArgs, "--"+f.Name+"="+f.Value.String()) })
		response, err := service.Call(cmd.Context(), service.Request{Operation: "command", Args: requestArgs})
		if response.Output != "" {
			cmd.Print(response.Output)
		}
		return err
	}
}
func init() {
	serviceCmd := &cobra.Command{Use: "service", Short: "Install, remove or recover the systemd VPN service"}
	for name, fn := range map[string]func() error{"install": service.Install, "uninstall": service.Uninstall, "recover": service.Recover, "guard": service.Guard} {
		serviceCmd.AddCommand(&cobra.Command{Use: name, Hidden: name == "guard", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return fn() }})
	}
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(&cobra.Command{Use: "daemon", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		daemonProcess = true
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return service.Daemon(ctx, serviceCommand)
	}})
	rootCmd.AddCommand(&cobra.Command{Use: "restart", Short: "Reconnect a running VPN", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := service.Call(cmd.Context(), service.Request{Operation: "restart"})
		return err
	}})
	status := &cobra.Command{Use: "status", Short: "Show desired and actual VPN state", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		response, err := service.Call(cmd.Context(), service.Request{Operation: "status"})
		if err != nil {
			return err
		}
		s := response.Status
		if s == nil {
			return fmt.Errorf("service returned no status")
		}
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(s)
		}
		cmd.Printf("State: %s\nDesired: %t\nNode: %s\nMode: %s\nProtection: %t\n", s.State, s.Desired, s.Node, s.Mode, s.Protection)
		switch s.Mode {
		case "proxy":
			cmd.Println("Proxy: 127.0.0.1:2080; system internet is not blocked")
		case "tun":
			cmd.Println("Proxy: 127.0.0.1:2080 (HTTP/SOCKS5, available while connected)")
		}
		if s.LastError != "" {
			cmd.Println("Last error:", s.LastError)
		}
		return nil
	}}
	status.Flags().Bool("json", false, "Print JSON")
	rootCmd.AddCommand(status)
	logs := &cobra.Command{Use: "logs", Short: "Read service journal without sudo", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		follow, _ := cmd.Flags().GetBool("follow")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return service.Logs(ctx, follow, cmd.OutOrStdout())
	}}
	logs.Flags().BoolP("follow", "f", false, "Follow journal output")
	rootCmd.AddCommand(logs)
}
