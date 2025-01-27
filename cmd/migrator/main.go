package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"os"
	"time"
)

func main() {
	var storagePath, migrationsPath, migrationsTable string = "postgres:postgres@localhost:5433/sso_db", "./migrations", ""

	flag.StringVar(&storagePath, "storage-path", "", "Path to a directory containing migration files")
	flag.StringVar(&migrationsPath, "migrations-path", "", "Path to a directory containing migration files")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of migrations table")
	flag.Parse()
	time.Sleep(2 * time.Second)
	if storagePath == "" {
		storagePath = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?x-migrations-table=%s&sslmode=disable", os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"), migrationsTable)
	} else {
		storagePath = fmt.Sprintf("postgres://%s?x-migrations-table=%s&sslmode=disable", storagePath, migrationsTable)
	}

	if migrationsPath == "" {
		panic("migrations-path is required")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		storagePath)
	if err != nil {
		panic(err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("No migrations found")
			return
		}
		/*if err = m.Down(); err != nil {
			panic(err)
		}*/
		fmt.Println("migrations are probably cracked, check it")
	}
	fmt.Println("migrations completed successfully")
}
