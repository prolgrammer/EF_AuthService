package main

import (
	"context"
	"fmt"
	"os"

	"github.com/eventflow/auth-service/internal/app"
)

func main() {
	if err := app.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
