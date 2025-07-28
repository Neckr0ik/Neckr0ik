# SQL Reference Guide

## Introduction

This reference guide provides essential SQL commands and techniques for database operations, with a focus on security best practices. It covers basic queries, filtering, joins, and secure implementation methods.

## Basic SQL Commands

### SELECT Statement
Retrieves data from a database table.

```sql
-- Basic SELECT statement
SELECT column1, column2 FROM table_name;

-- Select all columns
SELECT * FROM table_name;

-- Select with column alias
SELECT column1 AS alias1, column2 AS alias2 FROM table_name;
```

### Filtering with WHERE
Filters records based on specified conditions.

```sql
-- Basic WHERE clause
SELECT * FROM employees WHERE department = 'IT';

-- Multiple conditions with AND
SELECT * FROM employees WHERE department = 'IT' AND salary > 50000;

-- Multiple conditions with OR
SELECT * FROM employees WHERE department = 'IT' OR department = 'HR';

-- Combining AND and OR with parentheses
SELECT * FROM employees WHERE (department = 'IT' OR department = 'HR') AND salary > 50000;
```

### Sorting with ORDER BY
Sorts the result set by one or more columns.

```sql
-- Ascending order (default)
SELECT * FROM employees ORDER BY last_name;

-- Descending order
SELECT * FROM employees ORDER BY salary DESC;

-- Multiple columns
SELECT * FROM employees ORDER BY department, last_name;
```

### Limiting Results
Restricts the number of rows returned.

```sql
-- MySQL/SQLite syntax
SELECT * FROM employees LIMIT 10;

-- SQL Server syntax
SELECT TOP 10 * FROM employees;

-- PostgreSQL syntax
SELECT * FROM employees LIMIT 10;
```

## Advanced Filtering

### LIKE Operator
Searches for patterns in string columns.

```sql
-- Names starting with 'J'
SELECT * FROM employees WHERE first_name LIKE 'J%';

-- Names ending with 'son'
SELECT * FROM employees WHERE last_name LIKE '%son';

-- Names containing 'an'
SELECT * FROM employees WHERE last_name LIKE '%an%';

-- Single character wildcard
SELECT * FROM employees WHERE first_name LIKE 'J_n';
```

### IN Operator
Matches values in a list.

```sql
-- Match multiple values
SELECT * FROM employees WHERE department IN ('IT', 'HR', 'Finance');

-- Combine with subquery
SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE location = 'New York');
```

### BETWEEN Operator
Selects values within a range.

```sql
-- Numeric range
SELECT * FROM employees WHERE salary BETWEEN 50000 AND 75000;

-- Date range
SELECT * FROM orders WHERE order_date BETWEEN '2023-01-01' AND '2023-12-31';
```

### NULL Values
Handles missing data.

```sql
-- Find NULL values
SELECT * FROM employees WHERE manager_id IS NULL;

-- Find non-NULL values
SELECT * FROM employees WHERE phone_number IS NOT NULL;
```

## Joins

### INNER JOIN
Returns records with matching values in both tables.

```sql
SELECT employees.name, departments.name
FROM employees
INNER JOIN departments ON employees.department_id = departments.id;
```

### LEFT JOIN
Returns all records from the left table and matching records from the right table.

```sql
SELECT employees.name, departments.name
FROM employees
LEFT JOIN departments ON employees.department_id = departments.id;
```

### RIGHT JOIN
Returns all records from the right table and matching records from the left table.

```sql
SELECT employees.name, departments.name
FROM employees
RIGHT JOIN departments ON employees.department_id = departments.id;
```

### FULL JOIN
Returns all records when there is a match in either table.

```sql
SELECT employees.name, departments.name
FROM employees
FULL JOIN departments ON employees.department_id = departments.id;
```

## Aggregate Functions

### COUNT
Counts the number of rows.

```sql
-- Count all rows
SELECT COUNT(*) FROM employees;

-- Count non-NULL values
SELECT COUNT(phone_number) FROM employees;

-- Count with grouping
SELECT department, COUNT(*) FROM employees GROUP BY department;
```

### SUM, AVG, MIN, MAX
Perform calculations on numeric columns.

```sql
-- Calculate total salary
SELECT SUM(salary) FROM employees;

-- Calculate average salary
SELECT AVG(salary) FROM employees;

-- Find minimum and maximum salary
SELECT MIN(salary), MAX(salary) FROM employees;

-- Group by department
SELECT department, AVG(salary) FROM employees GROUP BY department;
```

### GROUP BY and HAVING
Groups rows and filters groups.

```sql
-- Group by department
SELECT department, COUNT(*) FROM employees GROUP BY department;

-- Filter groups with HAVING
SELECT department, COUNT(*) FROM employees 
GROUP BY department 
HAVING COUNT(*) > 5;
```

## Data Modification

### INSERT
Adds new records to a table.

```sql
-- Insert a single row
INSERT INTO employees (first_name, last_name, department, salary)
VALUES ('John', 'Smith', 'IT', 60000);

-- Insert multiple rows
INSERT INTO employees (first_name, last_name, department, salary)
VALUES 
  ('Jane', 'Doe', 'HR', 55000),
  ('Bob', 'Johnson', 'Finance', 65000);
```

### UPDATE
Modifies existing records.

```sql
-- Update a single column
UPDATE employees SET salary = 65000 WHERE employee_id = 101;

-- Update multiple columns
UPDATE employees 
SET department = 'Marketing', salary = salary * 1.1
WHERE department = 'Sales';
```

### DELETE
Removes records from a table.

```sql
-- Delete specific records
DELETE FROM employees WHERE department = 'Temporary';

-- Delete all records (use with caution)
DELETE FROM audit_logs_archive;
```

## Security Best Practices

### Parameterized Queries
Prevents SQL injection by separating SQL code from data.

```sql
-- VULNERABLE (DO NOT USE):
-- string query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

-- SECURE (Python example):
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))

-- SECURE (PHP example):
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

-- SECURE (Java example):
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
stmt.setString(2, password);
```

### Least Privilege
Restricts database user permissions to only what's necessary.

```sql
-- Create restricted user with minimal permissions
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON app_database.customers TO 'app_user'@'localhost';
GRANT SELECT ON app_database.products TO 'app_user'@'localhost';

-- Revoke dangerous permissions
REVOKE DROP, ALTER, CREATE ON app_database.* FROM 'app_user'@'localhost';
```

### Input Validation
Validates user input before using it in queries.

```sql
-- Example of input validation in application code (pseudocode)
function isValidInput(input) {
  // Check if input is empty
  if (input == null || input.trim() == "") {
    return false;
  }
  
  // Check for SQL injection patterns
  if (input.match(/[';\\]/) || input.match(/\b(union|select|insert|update|delete|drop)\b/i)) {
    return false;
  }
  
  // Check length
  if (input.length > 100) {
    return false;
  }
  
  return true;
}
```

### Error Handling
Prevents information disclosure through error messages.

```sql
-- Example of error handling in application code (pseudocode)
try {
  // Execute database query
  result = executeQuery(query, parameters);
  return result;
} catch (DatabaseException e) {
  // Log the detailed error for administrators
  logError("Database error: " + e.getMessage());
  
  // Return generic error to user
  return "An error occurred while processing your request.";
}
```

## Common SQL Injection Techniques

### Authentication Bypass
Attackers attempt to bypass login forms.

```sql
-- VULNERABLE QUERY:
-- SELECT * FROM users WHERE username = '[INPUT]' AND password = '[INPUT]'

-- ATTACK EXAMPLES:
-- username: admin' --
-- password: anything

-- RESULTING QUERY:
-- SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

### UNION-Based Attacks
Attackers use UNION to extract data from other tables.

```sql
-- VULNERABLE QUERY:
-- SELECT name, description FROM products WHERE category = '[INPUT]'

-- ATTACK EXAMPLE:
-- category: x' UNION SELECT username, password FROM users --

-- RESULTING QUERY:
-- SELECT name, description FROM products WHERE category = 'x' UNION SELECT username, password FROM users --
```

### Blind SQL Injection
Attackers infer information when no direct output is visible.

```sql
-- VULNERABLE QUERY:
-- SELECT * FROM products WHERE id = [INPUT]

-- BOOLEAN-BASED ATTACK:
-- id: 1 AND 1=1  (returns results)
-- id: 1 AND 1=2  (returns no results)

-- TIME-BASED ATTACK:
-- id: 1; WAITFOR DELAY '0:0:5' --  (causes 5-second delay if successful)
```

## Performance Optimization

### Indexing
Improves query performance by creating indexes on frequently queried columns.

```sql
-- Create index on a single column
CREATE INDEX idx_employee_department ON employees(department);

-- Create index on multiple columns
CREATE INDEX idx_employee_dept_name ON employees(department, last_name);

-- Create unique index
CREATE UNIQUE INDEX idx_employee_email ON employees(email);
```

### Query Optimization
Improves query efficiency.

```sql
-- Use specific columns instead of SELECT *
SELECT employee_id, first_name, last_name FROM employees;

-- Use appropriate JOINs
SELECT e.name, d.name
FROM employees e
INNER JOIN departments d ON e.department_id = d.id;

-- Use WHERE before GROUP BY
SELECT department, COUNT(*) 
FROM employees 
WHERE hire_date > '2020-01-01'
GROUP BY department;
```

## Conclusion

This reference guide covers essential SQL commands and security best practices. Always use parameterized queries, implement proper input validation, and follow the principle of least privilege to protect your database applications from SQL injection attacks.

## Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Bobby Tables: A guide to preventing SQL injection](https://bobby-tables.com/)