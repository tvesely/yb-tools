package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4"
	"os"
)

func main() {
	// TODO: Command line flags
	// TODO: Add debug flag
	// TODO: Add flags for specifying universe name or UUID
	// TODO: Add flags to control node list source(s) (platform postgres, YB masters, or manual)
	// TODO: Add flags for specifying individual nodes by number and by name
	// TODO: Add flags for controlling time window (before / after)
	// TODO: Add flags for controlling which logs to collect (info/error/fatal)

	Euid := os.Geteuid()
	if Euid != 0 {
		// fmt.Println("Effective user id: ", Euid)

		_, _ = fmt.Fprintln(os.Stderr, "The getlogs utility must be run with root privileges.")
		os.Exit(1)
	}

	// TODO: Replace hard-coded URL
	// DbUrl := os.Getenv("DATABASE_URL")
	DbUrl := "postgres://postgres:GwxSSDZcyUHVY8g8@localhost:5432/yugaware"

	fmt.Println("Connecting to Yugaware database to retrieve node info")
	conn, err := pgx.Connect(context.Background(), DbUrl)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
	fmt.Println("Connected to Yugaware database successfully")
	// fmt.Println("Connection info:", conn)

	// TODO: Retrieve universe JSON from postgres
}
