"""
Example vulnerable Python code for testing
"""
import sqlite3
import os
import pickle

def login(username, password):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    # Command Injection vulnerability
    os.system("ls " + user_input)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)
