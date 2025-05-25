

# ============================================
# examples/vulnerable_go.go - Test file  
# ============================================
"""
package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    _ "github.com/go-sql-driver/mysql"
)

// SQL Injection vulnerability
func getUser(db *sql.DB, username string) error {
    query := "SELECT * FROM users WHERE username = '" + username + "'"
    rows, err := db.Query(query)
    if err != nil {
        return err
    }
    defer rows.Close()
    return nil
}

// Command Injection vulnerability  
func executeCommand(userInput string) error {
    cmd := exec.Command("sh", "-c", "ls "+userInput)
    return cmd.Run()
}

// Hardcoded credentials
const (
    APIKey = "sk-1234567890abcdef"
    DBPassword = "admin123"
)

// Path Traversal vulnerability
func readFile(filename string) ([]byte, error) {
    return os.ReadFile("/var/www/uploads/" + filename)
}

func main() {
    fmt.Println("Vulnerable Go application")
}
"""