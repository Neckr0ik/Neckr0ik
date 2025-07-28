# Data Protection Projects

Labs and tools for preventing SQL injection attacks and implementing secure data handling practices in database applications.

## Projects

### 🛡️ sql-defence-playground
Interactive laboratory environment for testing SQL injection vulnerabilities and implementing secure coding practices.

**Key Features:**
- Vulnerable web application for testing
- Secure implementation examples
- SQL injection prevention techniques
- Input validation and parameterized queries
- Security testing tools and methodologies

**Skills:** SQL Security, Python, Flask, Input Validation, Secure Coding

## Getting Started

Each project contains:
- `README.md` with detailed setup and usage instructions
- Vulnerable and secure application versions
- Testing tools and exploit examples
- Security best practices and remediation guides

## Prerequisites

- **Python 3.8+** for web application development
- **SQL Database** (SQLite, PostgreSQL, or MySQL)
- **Web Browser** for testing applications
- **Basic SQL Knowledge** for understanding vulnerabilities

## SQL Security Fundamentals

### Common Vulnerabilities

#### SQL Injection
- **Classic SQL Injection**: Direct query manipulation
- **Blind SQL Injection**: Inference-based data extraction
- **Time-based SQL Injection**: Timing attack techniques
- **Union-based SQL Injection**: Data extraction via UNION queries

#### Prevention Techniques
- **Parameterized Queries**: Using prepared statements
- **Input Validation**: Sanitizing user input
- **Least Privilege**: Minimal database permissions
- **Error Handling**: Preventing information disclosure

### Secure Coding Practices

#### Input Validation
```python
# Bad: Direct string concatenation
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good: Parameterized query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

#### Output Encoding
```python
# Escape special characters for display
import html
safe_output = html.escape(user_input)
```

#### Access Controls
```python
# Implement role-based access
def check_permissions(user, action, resource):
    return user.has_permission(action, resource)
```

## Learning Objectives

### Understanding Vulnerabilities
- Identify common SQL injection patterns
- Understand attack vectors and exploitation techniques
- Recognize vulnerable code patterns
- Assess impact and risk levels

### Implementing Security
- Apply secure coding practices
- Implement input validation and sanitization
- Use parameterized queries and prepared statements
- Configure proper error handling

### Testing and Validation
- Perform security testing and code review
- Use automated security testing tools
- Validate security controls and implementations
- Document findings and remediation steps