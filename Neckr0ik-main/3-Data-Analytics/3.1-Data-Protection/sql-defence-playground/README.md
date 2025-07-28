# SQL Defence Playground

Interactive laboratory environment for learning SQL injection vulnerabilities and implementing secure database practices. This playground provides both vulnerable and secure versions of a web application for hands-on security testing.

## Overview

This project demonstrates common SQL injection vulnerabilities and their prevention techniques through a practical web application. It's designed for security professionals, developers, and students to understand SQL injection attacks and learn secure coding practices.

## Features

- **Vulnerable Application** - Intentionally insecure for testing
- **Secure Implementation** - Best practices demonstration
- **Multiple Attack Vectors** - Various SQL injection techniques
- **Interactive Testing** - Web-based vulnerability exploration
- **Educational Content** - Detailed explanations and examples
- **Security Tools** - Automated testing and validation

## Installation

### Prerequisites
```bash
# Python 3.8+
python3 --version

# Required packages
pip install flask sqlite3 hashlib bcrypt
```

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/3-Data-Analytics/3.1-Data-Protection/sql-defence-playground

# Install dependencies
pip install -r requirements.txt

# Initialize database
python setup_database.py

# Start vulnerable application
python vulnerable_app.py

# Start secure application (in another terminal)
python secure_app.py
```

## Usage

### Accessing Applications

#### Vulnerable Application
- **URL**: http://localhost:5000
- **Purpose**: Testing SQL injection vulnerabilities
- **Warning**: ⚠️ Intentionally insecure - do not use in production

#### Secure Application
- **URL**: http://localhost:5001
- **Purpose**: Demonstrating secure implementation
- **Features**: Input validation, parameterized queries, error handling

### Testing Scenarios

#### 1. Authentication Bypass
```sql
-- Test in login form
Username: admin' OR '1'='1' --
Password: anything

-- Expected: Bypass authentication in vulnerable app
-- Expected: Login failure in secure app
```

#### 2. Data Extraction
```sql
-- Test in search field
Search: ' UNION SELECT username, password FROM users --

-- Expected: Expose user data in vulnerable app
-- Expected: No data exposure in secure app
```

## Vulnerability Examples

### 1. Classic SQL Injection

#### Vulnerable Code
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login successful!"
    else:
        return "Login failed!"
```

#### Secure Code
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Input validation
    if not validate_input(username) or not validate_input(password):
        return "Invalid input", 400
    
    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    cursor.execute(query, (username, hash_password(password)))
    user = cursor.fetchone()
    
    if user:
        return "Login successful!"
    else:
        return "Login failed!"
```

## Security Best Practices

### Input Validation
```python
def validate_sql_input(input_string, max_length=100):
    """Comprehensive input validation for SQL injection prevention"""
    
    # Check for null or empty input
    if not input_string:
        return False, "Input cannot be empty"
    
    # Check length
    if len(input_string) > max_length:
        return False, f"Input too long (max {max_length} characters)"
    
    # Check for SQL injection patterns
    dangerous_patterns = [
        # SQL keywords
        r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b',
        # SQL operators
        r'(\-\-|\/\*|\*\/)',
        # SQL functions
        r'\b(concat|substring|ascii|char|waitfor|delay)\b',
        # SQL metacharacters
        r"[';\"\\]"
    ]
    
    import re
    for pattern in dangerous_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False, f"Potentially malicious input detected"
    
    return True, "Input is valid"
```

### Parameterized Queries
```python
# Different database implementations

# SQLite
def get_user_sqlite(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# PostgreSQL
def get_user_postgresql(user_id):
    import psycopg2
    conn = psycopg2.connect(database="mydb", user="user", password="pass")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

# MySQL
def get_user_mysql(user_id):
    import mysql.connector
    conn = mysql.connector.connect(host="localhost", user="user", password="pass", database="mydb")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
```

## Disclaimer

⚠️ **Educational Use Only**: This playground contains intentionally vulnerable code for educational purposes. Do not use vulnerable components in production environments. Always follow secure coding practices in real applications.

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.