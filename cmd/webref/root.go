package main

import "github.com/spf13/cobra"

func NewRoot() *cobra.Command {
	return &cobra.Command{
		Use: "webref",
	}
}
