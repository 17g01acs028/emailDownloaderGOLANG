package DB

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// DBConfig holds the configuration for both PostgreSQL and MySQL
type DBConfig struct {
	DBType         string
	User           string
	Table          string
	Password       string
	DBName         string
	Host           string
	Port           int
	MaxConnections int
}

// DBConnection manages the database connection
var DB *sql.DB

func TestConnection(config DBConfig) (*sql.DB, error) {
	var err error
	var connStr string

	switch config.DBType {
	case "postgres":
		connStr = fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d sslmode=disable",
			config.User, config.Password, config.DBName, config.Host, config.Port)
		DB, err = sql.Open("postgres", connStr)
	case "mysql":
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.User, config.Password, config.Host, config.Port, config.DBName)
		DB, err = sql.Open("mysql", connStr)
	default:
		err = fmt.Errorf("unsupported database type: %s", config.DBType)
	}

	if err != nil {
		return nil, err
	}

	err = DB.Ping()

	if err != nil {
		return nil, err
	}
	return DB, nil
}

func InitDB(config DBConfig) error {
	var err error
	var connStr string

	switch config.DBType {
	case "postgres":
		connStr = fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d sslmode=disable",
			config.User, config.Password, config.DBName, config.Host, config.Port)
		DB, err = sql.Open("postgres", connStr)
	case "mysql":
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.User, config.Password, config.Host, config.Port, config.DBName)
		DB, err = sql.Open("mysql", connStr)
	default:
		err = fmt.Errorf("unsupported database type: %s", config.DBType)
	}

	if err != nil {
		return err
	}

	//db, err = sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/testdb")
	//if err != nil {
	//	return fmt.Errorf("error opening database: %v", err)
	//}

	// Connection pool settings
	DB.SetMaxOpenConns(config.MaxConnections)
	DB.SetMaxIdleConns(5)
	//DB.SetConnMaxLifetime(time.Hour)

	return DB.Ping()
}
