package main

import (
	"github.com/yugabyte/yb-tools/yb-getlogs/cmd"
)

func main() {
	// TODO: Add flags to control node list source(s) (platform postgres, YB masters, or manual)
	// TODO: Add flags for specifying individual nodes by number or name
	// TODO: Add flags for controlling time window (before / after)
	// TODO: Add flags for controlling which logs to collect (info/error/fatal)
	// TODO: Add a flag for specifying the SSH port for the nodes
	// TODO: Add flags for specifying SSH keys
	// TODO: Make it possible to set SSH ports on a node-by-node basis?
	// TODO: Add flag to list universes and node counts?

	cmd.Execute()

}
