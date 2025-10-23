"""
Example Vulnerable Code for Security Testing
=============================================

⚠️  WARNING: This file contains INTENTIONALLY VULNERABLE CODE
These examples are for educational purposes only.
DO NOT use these patterns in production!

Use these to test the security analysis tools.
"""

# VULNERABILITY 1: Code Injection via eval()
def calculate_user_expression(expression):
    """CRITICAL: eval() allows arbitrary code execution"""
    result = eval(expression)  # DANGEROUS!
    return result


# VULNERABILITY 2: Unsafe Deserialization
import pickle

def load_user_data(data_bytes):
    """CRITICAL: pickle.loads can execute arbitrary code during deserialization"""
    user_data = pickle.loads(data_bytes)  # DANGEROUS!
    return user_data


# VULNERABILITY 3: Command Injection
import os

def run_user_command(filename):
    """HIGH: os.system with user input allows command injection"""
    os.system(f"cat {filename}")  # DANGEROUS!


# VULNERABILITY 4: SQL Injection
def authenticate_user(username, password):
    """HIGH: String formatting in SQL queries"""
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # SQL injection vulnerability!
    return execute_query(query)


# VULNERABILITY 5: Hardcoded Secrets
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"  # DANGEROUS!
DATABASE_PASSWORD = "SuperSecret123"  # DANGEROUS!


# Test Snippet 1: Multiple Critical Issues
SNIPPET_1 = """
import pickle
import os

def process_user_input(user_data, user_command):
    # Multiple vulnerabilities in one function
    obj = pickle.loads(user_data)  # Unsafe deserialization
    result = eval(user_command)     # Code injection
    os.system(obj['cmd'])           # Command injection
    return result
"""

# Test Snippet 2: SQL Injection
SNIPPET_2 = """
def get_user_profile(user_id):
    query = f"SELECT * FROM profiles WHERE id = {user_id}"
    return db.execute(query)
"""

# Test Snippet 3: Hardcoded Credentials
SNIPPET_3 = """
# Configuration
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_CONNECTION = "postgresql://admin:password123@localhost/mydb"
"""

if __name__ == "__main__":
    print("""
    ⚠️  This file contains INTENTIONALLY VULNERABLE CODE
    
    Use these snippets to test the security analysis tools:
    
    1. SNIPPET_1: Multiple critical issues (pickle, eval, os.system)
    2. SNIPPET_2: SQL injection
    3. SNIPPET_3: Hardcoded secrets
    
    Run:
        > use snyk_security_server.analyze_code_security to check SNIPPET_1
    """)

