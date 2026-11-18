import subprocess

# Hardcoded password
password = "test_password123"

# Hardcoded API key
api_key = "test_api_key_12345"

# Dangerous eval usage
user_input = "2 + 2"
result = eval(user_input)

# Dangerous exec usage
exec("print('Hello')")

# Dangerous shell execution
subprocess.run("echo hello", shell=True)

# Potential SQL injection
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")