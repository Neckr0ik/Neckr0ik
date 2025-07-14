# Linux File Permissions Lab Manual

## Overview

This lab manual provides hands-on exercises for understanding and managing Linux file permissions. You'll learn to examine, modify, and secure file access using command-line tools.

## Learning Objectives

- Understand Linux file permission concepts
- Use `ls -la` to examine file permissions
- Modify permissions using `chmod` command
- Apply security principles to file access control

---

## Exercise 1: Examining File Permissions

### Understanding Permission Display

When you use `ls -la`, you'll see output like this:

```bash
$ ls -la
total 32
drwxr-xr-x 2 user user 4096 Dec 15 10:30 .
drwxr-xr-x 3 user user 4096 Dec 15 10:25 ..
-rw-r--r-- 1 user user  156 Dec 15 10:30 document.txt
-rwxr-xr-x 1 user user 8760 Dec 15 10:28 script.sh
-rw------- 1 user user   42 Dec 15 10:29 secret.txt
```

### Permission Structure Breakdown

Each file entry shows:
- **File type**: First character (`-` = file, `d` = directory)
- **Owner permissions**: Characters 2-4 (rwx)
- **Group permissions**: Characters 5-7 (rwx)
- **Other permissions**: Characters 8-10 (rwx)

### Permission Meanings

- **r (read)**: View file contents or list directory contents
- **w (write)**: Modify file contents or create/delete files in directory
- **x (execute)**: Run file as program or access directory

### Practical Exercise

1. **Create a test directory and files:**
```bash
mkdir ~/permissions_lab
cd ~/permissions_lab
echo "This is a public document" > public.txt
echo "This is a private document" > private.txt
echo "#!/bin/bash\necho 'Hello World'" > hello.sh
```

2. **Examine the default permissions:**
```bash
ls -la
```

3. **Analyze the output:**
   - What permissions do the files have?
   - Who can read, write, or execute each file?
   - What do you notice about the script file?

---

## Exercise 2: Modifying File Permissions

### Using chmod with Symbolic Notation

The `chmod` command changes file permissions using symbolic or numeric notation.

#### Symbolic Notation Examples

```bash
# Make a file executable for the owner
chmod u+x hello.sh

# Remove write permission for group and others
chmod go-w private.txt

# Give read and write permissions to group
chmod g+rw public.txt

# Set specific permissions for all categories
chmod u=rwx,g=rx,o=r hello.sh
```

#### Symbolic Notation Components

- **Who**: `u` (user/owner), `g` (group), `o` (others), `a` (all)
- **Operation**: `+` (add), `-` (remove), `=` (set exactly)
- **Permission**: `r` (read), `w` (write), `x` (execute)

### Practical Exercise

1. **Make the script executable:**
```bash
chmod u+x hello.sh
ls -la hello.sh
```

2. **Secure the private file:**
```bash
chmod go-r private.txt
ls -la private.txt
```

3. **Test the permissions:**
```bash
# Try to run the script
./hello.sh

# Try to read the private file as the owner
cat private.txt

# Create another user account (if possible) and test access
```

---

## Exercise 3: Numeric Permission Notation

### Understanding Numeric Permissions

Permissions can be represented as three-digit numbers:
- **4** = read (r)
- **2** = write (w)
- **1** = execute (x)

Add the numbers to combine permissions:
- **7** = rwx (4+2+1)
- **6** = rw- (4+2)
- **5** = r-x (4+1)
- **4** = r-- (4)
- **0** = --- (no permissions)

### Common Permission Combinations

| Numeric | Symbolic | Meaning |
|---------|----------|---------|
| 755 | rwxr-xr-x | Owner: full access, Group/Others: read and execute |
| 644 | rw-r--r-- | Owner: read/write, Group/Others: read only |
| 600 | rw------- | Owner: read/write, Group/Others: no access |
| 777 | rwxrwxrwx | Everyone: full access (rarely recommended) |

### Practical Exercise

1. **Set permissions using numeric notation:**
```bash
# Make a file readable and writable by owner only
chmod 600 private.txt

# Make a script executable by owner, readable by others
chmod 755 hello.sh

# Make a document readable by everyone, writable by owner
chmod 644 public.txt
```

2. **Verify the changes:**
```bash
ls -la
```

3. **Test different permission scenarios:**
```bash
# Create files with different permission sets
echo "Test file 1" > test1.txt
echo "Test file 2" > test2.txt
echo "Test file 3" > test3.txt

chmod 700 test1.txt  # Owner only
chmod 750 test2.txt  # Owner full, group read/execute
chmod 644 test3.txt  # Owner read/write, others read

ls -la test*.txt
```

---

## Exercise 4: Directory Permissions

### Understanding Directory Permissions

Directory permissions work differently:
- **r (read)**: List directory contents
- **w (write)**: Create, delete, or rename files in directory
- **x (execute)**: Access the directory (cd into it)

### Practical Exercise

1. **Create directories with different permissions:**
```bash
mkdir public_dir private_dir restricted_dir

# Set different permission levels
chmod 755 public_dir      # Everyone can access and list
chmod 700 private_dir     # Owner only
chmod 644 restricted_dir  # Read-only (problematic for directories)
```

2. **Test directory access:**
```bash
# Try to access each directory
cd public_dir
cd ../private_dir
cd ../restricted_dir  # This should fail

# Try to list contents
ls public_dir
ls private_dir
ls restricted_dir
```

3. **Create files in directories:**
```bash
# Create files in accessible directories
echo "Public file" > public_dir/file1.txt
echo "Private file" > private_dir/file2.txt

# Try to create file in restricted directory
echo "Restricted file" > restricted_dir/file3.txt  # This should fail
```

---

## Exercise 5: Security Scenarios

### Scenario 1: Shared Project Directory

**Requirement**: Create a directory where team members can collaborate, but others cannot access.

```bash
# Create the project directory
mkdir ~/team_project
cd ~/team_project

# Set appropriate permissions
chmod 770 .  # Owner and group can access, others cannot

# Create some project files
echo "Project documentation" > README.md
echo "Configuration settings" > config.txt
echo "#!/bin/bash\necho 'Build script'" > build.sh

# Set file permissions
chmod 664 README.md config.txt  # Read/write for owner and group
chmod 775 build.sh              # Executable for owner and group
```

### Scenario 2: Secure Log Files

**Requirement**: Create log files that only the owner can read and write, but the system can append to.

```bash
# Create log directory
mkdir ~/secure_logs
cd ~/secure_logs

# Create log files
touch application.log error.log access.log

# Set secure permissions
chmod 600 *.log  # Owner read/write only

# Verify permissions
ls -la
```

### Scenario 3: Public Web Content

**Requirement**: Set up files for a web server where content is readable by everyone but only editable by the owner.

```bash
# Create web content directory
mkdir ~/web_content
cd ~/web_content

# Create web files
echo "<html><body>Welcome</body></html>" > index.html
echo "body { color: blue; }" > style.css
echo "console.log('Hello');" > script.js

# Set web-appropriate permissions
chmod 644 *  # Owner read/write, others read-only

# Verify permissions
ls -la
```

---

## Assessment Questions

1. **What command would you use to:**
   - Make a file readable by everyone but writable only by the owner?
   - Remove execute permission for group and others from a script?
   - Give full permissions to owner and read-only to group?

2. **Explain the difference between these permission sets:**
   - `rwxr-xr-x` vs `rwxrwxrwx`
   - `644` vs `755`
   - `700` vs `600`

3. **Security Analysis:**
   - Why is `777` permission generally not recommended?
   - What's the minimum permission needed for a directory to be accessible?
   - How would you secure a file containing passwords?

## Best Practices Summary

1. **Principle of Least Privilege**: Give only the minimum permissions necessary
2. **Regular Audits**: Periodically review file permissions
3. **Secure Defaults**: Start with restrictive permissions and add as needed
4. **Directory Security**: Remember that directory permissions affect file access
5. **Script Security**: Be careful with executable permissions on scripts

## Troubleshooting Common Issues

### Permission Denied Errors
```bash
# If you get "Permission denied" when trying to execute a file:
chmod +x filename

# If you can't access a directory:
chmod +x directory_name

# If you can't read a file:
chmod +r filename
```

### Fixing Overly Permissive Files
```bash
# Secure files that are too open:
chmod 644 document.txt    # For regular files
chmod 755 script.sh       # For executable files
chmod 700 private_dir     # For private directories
```

---

## Conclusion

This lab has covered the fundamentals of Linux file permissions, including:
- Understanding permission notation (symbolic and numeric)
- Using `ls -la` to examine permissions
- Modifying permissions with `chmod`
- Applying security principles to real-world scenarios

Practice these concepts regularly to build proficiency in Linux system security. Remember that proper file permissions are a critical component of system security and should be carefully managed in any production environment.

## Next Steps

- Explore advanced topics like ACLs (Access Control Lists)
- Learn about special permissions (setuid, setgid, sticky bit)
- Study user and group management commands
- Practice with more complex security scenarios