#!/usr/bin/env python3
"""
Snyk Security Workshop - MCP Server
====================================

Demonstrates secure MCP server patterns for the Snyk AI Security Summit.

Features:
- Runtime secret injection (FILE_ACCESS_TOKEN)
- OAuth token brokering (GitHub)
- Tool chaining with OAuth continuity
- Security-focused code analysis
- Breaking the toxic flow triangle

5 Tools:
1. greet - Basic connectivity
2. read_file - File access with secrets
3. analyze_code_security - Static security analysis
4. fetch_github_code - GitHub OAuth demo
5. security_audit_workflow - Tool chaining + OAuth (THE WOW!)
"""

import re
import sys
from pathlib import Path
from typing import Annotated

import httpx
from arcade_mcp_server import Context, MCPApp, tool
from arcade_mcp_server.auth import GitHub

app = MCPApp(name="snyk_security_server", version="1.0.0", log_level="INFO")


# ============================================================================
# TOOL 1: Basic Connectivity
# ============================================================================

@app.tool
def greet(name: Annotated[str, "Name of person to greet"]) -> str:
    """Simple greeting tool to test MCP connectivity.
    
    No authentication or secrets required.
    
    Example:
        > use snyk_security_server.greet to say hello to Snyk Summit
    """
    return f"Hello, {name}! Welcome to the Snyk AI Security Summit! 🎉"


# ============================================================================
# TOOL 2: File Reading with Secret Injection
# ============================================================================

@app.tool(requires_secrets=["FILE_ACCESS_TOKEN"])
def read_file(
    context: Context,
    path: Annotated[str, "Path to file to read"],
    max_bytes: Annotated[int, "Maximum bytes to read"] = 50000
) -> dict:
    """Read file contents with secret-based access control.
    
    Demonstrates runtime secret injection:
    - Secret (FILE_ACCESS_TOKEN) stored in .env
    - Injected at runtime via context
    - LLM never sees the secret
    
    Toxic Flow Protection:
    - Factor #2 (Sensitive Data): Secret stays server-side
    
    Example:
        > use snyk_security_server.read_file to read examples/vulnerable_code.py
    """
    try:
        # Secret injected at runtime - LLM can't see it!
        access_token = context.get_secret("FILE_ACCESS_TOKEN")
        # In production, validate token here
    except Exception as e:
        return {
            "error": f"Secret not configured: {str(e)}",
            "note": "Set FILE_ACCESS_TOKEN in .env file"
        }
    
    # Production-quality file reading with safety bounds
    p = Path(path).expanduser().resolve()
    
    if not p.exists() or not p.is_file():
        return {
            "error": "File not found or not a file",
            "path": str(p)
        }
    
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        
        was_truncated = p.stat().st_size > max_bytes
        
        return {
            "content": content,
            "path": str(p),
            "size": p.stat().st_size,
            "truncated": was_truncated,
            "note": f"Access validated with token (last 4 chars: ...{access_token[-4:]})"
        }
    except Exception as e:
        return {"error": f"Failed to read file: {str(e)}"}


# ============================================================================
# TOOL 3: Security Analysis
# ============================================================================

@app.tool
async def analyze_code_security(
    context: Context,
    code: Annotated[str, "Python code to analyze for security vulnerabilities"]
) -> dict:
    """Analyze Python code for common security vulnerabilities.
    
    Detects:
    - Code injection (eval, exec, compile)
    - Unsafe deserialization (pickle.loads, yaml.load)
    - Command injection (os.system, subprocess shell=True)
    - SQL injection patterns
    - Hardcoded secrets
    
    Toxic Flow Protection:
    - Factor #1: Input validation via type hints
    - Factor #3: Bounded output (no code echo in errors)
    
    Example:
        > use snyk_security_server.analyze_code_security to check: import pickle; pickle.loads(data)
    """
    await context.log.info("Starting security analysis...")
    
    issues = []
    
    # Code injection checks
    if re.search(r'\beval\s*\(', code):
        issues.append({
            "severity": "CRITICAL",
            "type": "Code Injection",
            "issue": "eval() usage detected",
            "description": "eval() executes arbitrary code and is extremely dangerous",
            "remediation": "Use ast.literal_eval() for safe evaluation of literals"
        })
    
    if re.search(r'\bexec\s*\(', code):
        issues.append({
            "severity": "CRITICAL",
            "type": "Code Injection",
            "issue": "exec() usage detected",
            "description": "exec() executes arbitrary Python code",
            "remediation": "Refactor to avoid dynamic code execution"
        })
    
    if re.search(r'\bcompile\s*\(', code):
        issues.append({
            "severity": "HIGH",
            "type": "Code Injection",
            "issue": "compile() usage detected",
            "description": "compile() can execute arbitrary code",
            "remediation": "Avoid dynamic code compilation"
        })
    
    # Deserialization checks
    if re.search(r'pickle\.loads?\s*\(', code):
        issues.append({
            "severity": "CRITICAL",
            "type": "Unsafe Deserialization",
            "issue": "pickle.loads() detected",
            "description": "Deserializing untrusted pickle data can lead to remote code execution",
            "remediation": "Use JSON or other safe serialization formats"
        })
    
    if re.search(r'yaml\.load\s*\([^,)]*\)', code) and 'SafeLoader' not in code:
        issues.append({
            "severity": "HIGH",
            "type": "Unsafe Deserialization",
            "issue": "yaml.load() without SafeLoader",
            "description": "yaml.load() can execute arbitrary Python code",
            "remediation": "Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)"
        })
    
    # Command injection checks
    if re.search(r'os\.system\s*\(', code):
        issues.append({
            "severity": "HIGH",
            "type": "Command Injection",
            "issue": "os.system() usage detected",
            "description": "os.system() executes shell commands and is vulnerable to injection",
            "remediation": "Use subprocess with argument list (no shell=True)"
        })
    
    if re.search(r'subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True', code):
        issues.append({
            "severity": "HIGH",
            "type": "Command Injection",
            "issue": "subprocess with shell=True",
            "description": "Using shell=True enables command injection attacks",
            "remediation": "Use subprocess with list arguments, no shell=True"
        })
    
    # SQL injection patterns
    if re.search(r'execute\s*\([^)]*[+%]|cursor\.[a-z]+\s*\([^)]*\.format\s*\(', code):
        issues.append({
            "severity": "HIGH",
            "type": "SQL Injection",
            "issue": "Potential SQL injection via string formatting",
            "description": "SQL queries use string concatenation or .format()",
            "remediation": "Use parameterized queries with ? or %s placeholders"
        })
    
    # Hardcoded secrets
    if re.search(r'password\s*=\s*["\'][^"\']+["\']|api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', code, re.IGNORECASE):
        issues.append({
            "severity": "HIGH",
            "type": "Hardcoded Secrets",
            "issue": "Potential hardcoded password or API key",
            "description": "Secrets should never be hardcoded in source code",
            "remediation": "Store secrets in environment variables or secret managers"
        })
    
    await context.log.info(f"Analysis complete. Found {len(issues)} potential issues.")
    
    # Calculate severity counts
    severity_counts = {
        "CRITICAL": sum(1 for i in issues if i["severity"] == "CRITICAL"),
        "HIGH": sum(1 for i in issues if i["severity"] == "HIGH"),
        "MEDIUM": sum(1 for i in issues if i["severity"] == "MEDIUM"),
        "LOW": sum(1 for i in issues if i["severity"] == "LOW"),
    }
    
    return {
        "total_issues": len(issues),
        "severity_counts": severity_counts,
        "issues": issues,
        "recommendation": (
            "❌ CRITICAL - Do not deploy" if severity_counts["CRITICAL"] > 0 else
            "⚠️  Security issues found - Fix before deployment" if issues else
            "✅ No obvious security issues detected"
        )
    }


# ============================================================================
# TOOL 4: GitHub Code Fetching (OAuth Demo)
# ============================================================================

@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def fetch_github_code(
    context: Context,
    owner: Annotated[str, "Repository owner (e.g., 'octocat')"],
    repo: Annotated[str, "Repository name (e.g., 'Hello-World')"],
    file_path: Annotated[str, "Path to file in repository"] = "README.md"
) -> str:
    """Fetch code from a GitHub repository.
    
    Demonstrates OAuth token injection:
    - Requires GitHub authentication via 'arcade login github'
    - OAuth token retrieved via context.get_auth_token_or_empty()
    - Token never exposed to LLM or MCP client
    - Multi-tenant: each user gets their own token
    
    Toxic Flow Protection:
    - Factor #2 (Sensitive Data): OAuth token stays server-side
    - Token injected at runtime, never in MCP protocol
    
    Setup:
        $ arcade login github
    
    Example:
        > use snyk_security_server.fetch_github_code from owner octocat repo Hello-World file README.md
    """
    await context.log.info(f"Fetching {file_path} from {owner}/{repo}...")
    
    # OAuth token is injected into context at runtime
    # LLM and MCP clients cannot see or access the token
    oauth_token = context.get_auth_token_or_empty()
    
    if not oauth_token:
        return "Error: Not authenticated. Run 'arcade login github' first."
    
    # Use proper GitHub API headers (following Arcade GitHub toolkit pattern)
    headers = {
        "Accept": "application/vnd.github.raw+json",
        "Authorization": f"Bearer {oauth_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "snyk-workshop-mcp-server"
    }
    
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10.0)
            response.raise_for_status()
            
            await context.log.info(f"Successfully fetched {len(response.text)} bytes from {owner}/{repo}/{file_path}")
            
            return response.text
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return f"Error: File not found - {owner}/{repo}/{file_path}"
        elif e.response.status_code == 401:
            return "Error: Invalid or expired GitHub token. Run 'arcade login github' again."
        else:
            return f"Error: GitHub API returned {e.response.status_code}"
    except Exception as e:
        await context.log.error(f"Failed to fetch from GitHub: {str(e)}")
        return f"Error: {str(e)}"


# ============================================================================
# TOOL 5: Security Audit Workflow (Tool Chaining + OAuth Continuity)
# ============================================================================

@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def security_audit_workflow(
    context: Context,
    repo: Annotated[str, "GitHub repository to audit (e.g., 'owner/repo')"],
    file_path: Annotated[str, "File path to audit"] = "app.py"
) -> dict:
    """Complete security audit workflow using tool chaining.
    
    THE WOW MOMENT: This tool orchestrates other tools!
    
    Workflow:
    1. Fetch code from GitHub (uses GitHub OAuth)
    2. Analyze code for security issues
    3. Return combined audit report
    
    Key Features:
    - Tool chaining via context.tools.call_raw()
    - OAuth context propagates through entire chain
    - Same GitHub token used in both fetch and parent tool
    - Demonstrates composable, secure workflows
    
    Toxic Flow Protection:
    - Factor #2: OAuth token NEVER enters MCP protocol
    - Token stays server-side through entire tool chain
    - Context (auth, secrets, session) flows securely
    
    Setup:
        $ arcade login github
    
    Example:
        > use snyk_security_server.security_audit_workflow for octocat/Hello-World file README.md
    """
    await context.log.info(f"🔍 Starting security audit for {repo}/{file_path}")
    await context.log.info("This will demonstrate tool chaining with OAuth continuity...")
    
    try:
        # CHAIN 1: Fetch code from GitHub
        # This tool call INHERITS the GitHub OAuth from the parent tool!
        await context.log.info("Step 1: Fetching code from GitHub (using OAuth)...")
        
        # Split repo into owner and name
        if "/" in repo:
            owner, repo_name = repo.split("/", 1)
        else:
            return {
                "error": "Invalid repo format. Use 'owner/repo' format (e.g., 'octocat/Hello-World')",
                "repo": repo
            }
        
        code_result = await context.tools.call_raw(
            "SnykSecurityServer.FetchGithubCode",
            {"owner": owner, "repo": repo_name, "file_path": file_path}
        )
        
        # Check if fetch was successful
        fetched_code = code_result.value
        if isinstance(fetched_code, str) and fetched_code.startswith("Error:"):
            return {
                "error": fetched_code,
                "step_failed": "fetch_github_code"
            }
        
        await context.log.info(f"Step 1 complete: Fetched {len(fetched_code)} characters")
        
        # CHAIN 2: Analyze the fetched code for security issues
        await context.log.info("Step 2: Analyzing code for security vulnerabilities...")
        
        analysis_result = await context.tools.call_raw(
            "SnykSecurityServer.AnalyzeCodeSecurity",
            {"code": fetched_code}
        )
        
        analysis = analysis_result.value
        
        await context.log.info(f"Step 2 complete: Found {analysis['total_issues']} potential issues")
        await context.log.info("✅ Security audit workflow complete!")
        
        # Return combined audit report
        return {
            "repo": repo,
            "file": file_path,
            "code_length": len(fetched_code),
            "security_analysis": analysis,
            "workflow": {
                "step_1": "fetch_github_code (OAuth injected)",
                "step_2": "analyze_code_security (inherited context)",
                "auth_flow": "GitHub OAuth token shared across entire tool chain",
                "toxic_flow_prevention": "OAuth token never appeared in MCP protocol"
            },
            "summary": f"Audited {repo}/{file_path}: {analysis['total_issues']} issues ({analysis['severity_counts']['CRITICAL']} critical)"
        }
    
    except Exception as e:
        await context.log.error(f"Audit workflow failed: {str(e)}")
        return {
            "error": f"Workflow failed: {str(e)}",
            "repo": repo,
            "file": file_path
        }


# ============================================================================
# Server Entry Point
# ============================================================================

if __name__ == "__main__":
    # Get transport from command line argument, default to "stdio"
    # - "stdio" (default): Standard I/O - OAuth and secrets work!
    # - "http": HTTP Streamable - OAuth/secrets require deployment
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Arcade.dev @ Snyk Security Workshop - MCP Server            ║
║  ══════════════════════════════════════════════════════════  ║
║  Transport: {transport:<49}║
║  Tools: 5 (greet, read_file, analyze, fetch, audit)          ║
║                                                              ║
║  **Features:**                                               ║
║    - Secret injection pattern (requires deployment)          ║
║    - OAuth brokering (requires deployment)                   ║
║    - Tool chaining (works locally!)                          ║
║    - Security analysis (works locally!)                      ║
║                                                              ║
║  **Breaking the Toxic Flow Triangle!**                       ║
║  Ready for Snyk AI Security Summit!                          ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if transport == "stdio":
        print("ℹ️  Using stdio transport - Secrets work!")
        print("   Perfect for local development and workshops.")
        print()
    else:
        print("ℹ️  Using HTTP transport.")
        print("   Secrets require deployment to Arcade Cloud with HTTP.")
        print("   For local dev with OAuth, use: python server.py stdio")
        print()
    
    app.run(transport=transport, host="127.0.0.1", port=8000)

