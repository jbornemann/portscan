package main

import (
	"fmt"

	"github.com/jbornemann/portscan/internal/cli"
	"github.com/jbornemann/portscan/internal/net"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pscli",
	Short: "pscli is a client for issuing port scanning requests to a pscan server",
}

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "submit a new scan request",
	RunE: func(cmd *cobra.Command, args []string) error {
		if request, err := cmdLineArgs.PrepareSubmitRequest(); err != nil {
			return err
		} else if err := cli.Submit(*request, net.DefaultHttpClient()); err != nil {
			return err
		}
		return nil
	},
}

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "query a scan request",
	RunE: func(cmd *cobra.Command, args []string) error {
		if query, err := cmdLineArgs.PrepareQuery(); err != nil {
			return err
		} else if err := cli.DoQuery(*query, net.DefaultHttpClient()); err != nil {
			return err
		}
		return nil
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err.Error())
	}
}

var (
	cmdLineArgs = cli.CommandLineArgs{}
)

func init() {
	//display usage only on explicit -h or --help
	rootCmd.SilenceUsage = true
	//handle displaying error output through main(), avoid duplicate output
	rootCmd.SilenceErrors = true

	rootCmd.PersistentFlags().StringVar(&cmdLineArgs.Host, "host", "", "host of the pscan server")

	submitCmd.Flags().StringSliceVar(&cmdLineArgs.ScanIPs, "ips", nil, "list of ips to scan from pscan server")
	submitCmd.Flags().StringVar(&cmdLineArgs.ScanPort, "port", "", "port to scan from pscan server")

	queryCmd.Flags().StringVar(&cmdLineArgs.ScanID, "id", "", "id of port scan to query")

	rootCmd.AddCommand(submitCmd)
	rootCmd.AddCommand(queryCmd)
}
