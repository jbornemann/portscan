package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jbornemann/portscan/internal/server"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "pscan",
	Short: "pscan is a server for scanning ports",
	RunE: func(cmd *cobra.Command, args []string) error {
		if config, err := cmdLineArgs.ValidateAndPrepare(); err != nil {
			return err
		} else if server := server.NewServer(*config); server != nil {
			sigCh := make(chan os.Signal)
			killCh := make(chan bool)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go server.Run(killCh)
			<-sigCh
			killCh <- true
		}
		return nil
	},
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err.Error())
	}
}

var (
	cmdLineArgs = server.CommandLineArgs{}
)

func init() {
	cmd.Flags().StringVar(&cmdLineArgs.ListenPort, "port", "8080", "port to listen for requests")
}
