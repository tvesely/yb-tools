package main

import (
	"context"
	"fmt"
	"os/user"

	"github.com/jackc/pgx/v4"
)

func main() {
	fmt.Println("Hello Go!")
	CurrentUser, _ := user.Current()
	fmt.Println("Current user is", CurrentUser.Name)
	// TODO: Replace hard-coded URL
	// DbUrl := os.Getenv("DATABASE_URL")
	DbUrl := "postgres://postgres:GwxSSDZcyUHVY8g8@localhost:5432/yugaware"
	conn, _ := pgx.Connect(context.Background(), DbUrl)
	fmt.Println("Connection info:", conn)
}
