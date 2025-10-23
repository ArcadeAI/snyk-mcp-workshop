<h3 align="center">
  <img
    src="https://docs.arcade.dev/images/logo/arcade-logo.png"
    style="width: 400px;"
  >
</h3>

<h1 align="center">Building Secure MCP Servers</h1>

<p align="center">
  <strong>Snyk AI Security Summit Workshop</strong><br>
  Breaking the Toxic Flow Triangle with Arcade MCP
</p>

<div align="center">
  <a href="https://github.com/arcadeai/arcade-mcp"><img src="https://img.shields.io/badge/Arcade-MCP-blue" alt="Arcade MCP"></a>
  <a href="https://snyk.io"><img src="https://img.shields.io/badge/Snyk-Security-purple" alt="Snyk"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Protocol-green" alt="MCP"></a>
</div>

---

## 🎯 What You'll Build in 30 Minutes

**Part 1: Secure MCP Server Framework**
- 5 production-quality tools
- GitHub OAuth integration
- Tool chaining with OAuth continuity
- Security-first architecture

**Part 2: Arcade Gateway**
- Access 20+ production toolkits instantly
- Google Calendar, Slack, Gmail, GitHub
- Zero code, managed OAuth

**Outcome**: Production-ready MCP servers that eliminate factor #2 of the toxic flow triangle

---


## ⚠️ The Toxic Flow Triangle

<div align="center">

```
         1️⃣ Untrusted Instructions
          (Prompt injection, jailbreaks)
                    │
          ┌─────────┴─────────┐
          │                   │
    2️⃣ Sensitive Data   3️⃣ Exfil Path
     (API keys, OAuth)    (Logs, Caches,
                           LLM Memory)

     When all three combine → TOXIC FLOW ☠️
```

</div>

### Traditional MCP Tools: All 3 Factors Present ❌

```python
# ❌ BAD: Traditional approach
def my_tool(api_key: str, repo: str) -> dict:
    # API key passed as parameter
    headers = {"Authorization": f"Bearer {api_key}"}
    # Token visible in protocol, logged, cached
```

**Client calls**:
```json
{
  "tool": "my_tool",
  "args": {
    "api_key": "ghp_xxxxxxxxxxxx",  ← EXPOSED!
    "repo": "my-org/my-repo"
  }
}
```

**Problems**:
- ✘ Factor #2: API key in protocol
- ✘ Factor #3: Gets logged, cached, visible to LLM
- ✘ Prompt injection can extract credentials
- ✘ Not multi-tenant (same key for all users)

### Arcade MCP: Factor #2 Eliminated ✅

```python
# ✅ GOOD: Arcade MCP approach
@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def my_tool(context: Context, repo: str) -> dict:
    # OAuth token injected at runtime
    token = context.get_auth_token_or_empty()
    headers = {"Authorization": f"Bearer {token}"}
    # Token NEVER in protocol!
```

**Client calls**:
```json
{
  "tool": "my_tool",
  "args": {
    "repo": "my-org/my-repo"  ← No API key!
  }
}
```

**Benefits**:
- ✓ Factor #2: Token stays server-side
- ✓ Factor #3: **BROKEN** - no sensitive data in protocol
- ✓ Can't exfiltrate what isn't there
- ✓ Multi-tenant: Each user gets their own token

---

## 🏗️ Architecture: How Arcade MCP Eliminates Toxic Flows

<div align="center">

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                    MCP Client (Gemini CLI)                       ┃
┃                  "Fetch code from my-repo"                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
│
MCP Protocol (HTTP/stdio)
JSON-RPC messages
✅ NO CREDENTIALS HERE! ✅
│
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃         Arcade MCP Server (Your Tools)                        ┃
┃                                                               ┃
┃  ┌──────────────────────────────────────────────────────────┐ ┃
┃  │           MCP Protocol Handler                           │ ┃
┃  │  • Receives tool call request                            │ ┃
┃  │  • NO credentials in request!                            │ ┃
┃  └────────────────────────┬─────────────────────────────────┘ ┃
┃                           │                                   ┃
┃  ┏━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓  ┃
┃  ┃  Context Injection Layer (THE MAGIC!)                   ┃  ┃
┃  ┃                                                         ┃  ┃
┃  ┃   ┌──────────────┐          ┌──────────────┐            ┃  ┃
┃  ┃   │   Secrets    │          │ OAuth Tokens │            ┃  ┃
┃  ┃   │   (.env)     │          │   (Arcade    │            ┃  ┃
┃  ┃   │              │          │   Platform)  │            ┃  ┃
┃  ┃   └──────┬───────┘          └──────┬───────┘            ┃  ┃
┃  ┃          │                         │                    ┃  ┃
┃  ┃          └──────────┬──────────────┘                    ┃  ┃
┃  ┃                     │                                   ┃  ┃
┃  ┃             ┌───────▼────────┐                          ┃  ┃
┃  ┃             │ Context Object │                          ┃  ┃
┃  ┃             │  • user_id     │                          ┃  ┃
┃  ┃             │  • session_id  │                          ┃  ┃
┃  ┃             │  • secrets     │ ◀─ Injected at runtime   ┃  ┃
┃  ┃             │  • auth tokens │ ◀─ Injected at runtime   ┃  ┃
┃  ┃             └───────┬────────┘                          ┃  ┃
┃  ┗━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛  ┃
┃                          │                                    ┃
┃  ┌───────────────────────▼──────────────────────────────────┐ ┃
┃  │  Tool Execution (with injected context)                  │ ┃
┃  │  tool.execute(context) ◀─ Has secrets & OAuth!           │ ┃
┃  └──────────────────────────────────────────────────────────┘ ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

╔═══════════════════════════════════════════════════════════════╗
║  💡 Credentials injected AFTER the protocol layer             ║
║      → LLM never sees them, can't leak them!                  ║
╚═══════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════════╗
║  🔑 THE KEY POINT: The only way to solve this is with an              ║
║                    Agnostic Third Party Layer                         ║
║                                                                       ║
║  Credentials MUST be injected between the protocol and execution,     ║
║  never passed through the MCP protocol itself.                        ║
╚═══════════════════════════════════════════════════════════════════════╝
```

</div>

---

## 🛠️ Action Based Tools!

### Why These Tools Are Different

**Traditional API wrappers**: Match REST endpoints 1:1, require LLMs to understand HTTP semantics

**Arcade MCP tools**: Intent-specific, LLM-friendly, secure by design

> "LLMs care about **INTENT** ('get my calendar'), not API parameters (`GET /calendar/v3/events?timeMin=...`). Arcade tools are built for how LLMs think."


### The Problem with Traditional Wrappers

```python
# Traditional: Mirrors REST API
def github_get_file(owner, repo, path, ref, access_token):
    """
    GET /repos/{owner}/{repo}/contents/{path}
    Query params: ref (optional)
    Headers: Authorization: Bearer {access_token}
    """
    # LLM must:
    # - Know HTTP semantics
    # - Manage OAuth tokens
    # - Handle error codes
    # - Parse JSON responses
```

**LLM usage**:
```
> Get the README from octocat/Hello-World

LLM thinks: "I need owner='octocat', repo='Hello-World', path='README.md', and... wait, where's my access_token? User, can you provide your GitHub token?"
```

**Problems**:
- LLM manages credentials (factor #2!)
- LLM understands HTTP (cognitive overhead)
- Error messages are HTTP codes
- Not intent-specific

### Arcade MCP: Intent-Specific Tools

```python
# Arcade MCP: Intent-based
@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def fetch_github_code(
    context: Context,
    repo: Annotated[str, "Repository name (owner/repo)"],
    file_path: Annotated[str, "File to fetch"]
) -> str:
    """Fetch code from a GitHub repository.
    
    OAuth token is injected automatically.
    LLM never sees or manages credentials.
    """
    token = context.get_auth_token_or_empty()
    # Platform handles OAuth, tool uses it
```

**LLM usage**:
```
> Get the README from octocat/Hello-World

LLM thinks: "I have a tool `fetch_github_code`. Intent matches. Args: repo='octocat/Hello-World', file_path='README.md'. Call it."
```

**Benefits**:
- ✓ LLM focuses on INTENT, not HTTP
- ✓ Platform manages credentials (factor #2 eliminated!)
- ✓ Type hints guide LLM (Annotated types)
- ✓ Structured errors (JSON, not HTTP codes)

**This is the paradigm shift: Tools built for LLMs, not for humans calling REST APIs.**

---

## 🚀 Workshop Setup (5 Minutes)

### Step 1: Clone This Repository

```bash
git clone https://github.com/ArcadeAI/snyk-mcp-workshop
cd snyk-mcp-workshop
uv venv
source .venv/bin/activate
```

### Step 2: Install Arcade Secure MCP Framework

```bash
# Install the Arcade Secure MCP Framework
uv tool install arcade-mcp
```

This gives you everything to build MCP servers with Arcade:
- `arcade new` command for scaffolding
- `arcade login` for OAuth management

### Step 3: Install Dependencies

```bash
uv pip install httpx
```

### Step 4: Authenticate

```bash
# Create Arcade account (one-time)
arcade login
```

### Step 5: Create a new Secure MCP Server
```bash
arcade new server-name 
## i.e. arcade new snyk_workshop
```
---

## Meet The 5 Tools

### Special #1: Run the Server

```bash
# Set environment variable
export FILE_ACCESS_TOKEN="demo-file-access-token-2025"

# Start server with HTTP transport
python3 server.py http
```

You should see:

```
╔══════════════════════════════════════════════════════════════╗
║  Snyk Security Workshop - MCP Server                         ║
║  Transport: HTTP                                             ║
║  Tools: 5 (greet, read_file, analyze, fetch, audit)          ║
║  **Breaking the Toxic Flow Triangle!**                       ║
╚══════════════════════════════════════════════════════════════╝
```

### Special #2: Connect Gemini CLI

```bash
# Add Using The CLI
 gemini mcp add snykhttp -t http http://127.0.0.1:8000/mcp
```

OR edit file ```~/.gemini/settings.json``` 

```json
{
  "mcpServers": {
    "snykhttp": {
      "httpUrl": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

Then test in gemini-cli:
```bash
gemini
ctrl + t #lists tools 
```

### Tool 1: `greet` - Connectivity Test

**Intent**: Test basic MCP connectivity

**Code**:
```python
@app.tool
def greet(name: Annotated[str, "Name to greet"]) -> str:
    return f"Hello, {name}! Welcome to Snyk AI Security Summit!"
```

**Test**:
```
> use snykhttp.greet to say hello to Workshop Attendees
```

**Why it matters**: Simple, no auth, proves MCP protocol is working.

---

### Tool 2: `read_file` - Secret Injection Pattern

**Intent**: Read a file with access control

**Code**:
```python
@app.tool(requires_secrets=["FILE_ACCESS_TOKEN"])
def read_file(context: Context, path: str, max_bytes: int = 50000) -> dict:
    # Secret injected at runtime from .env
    token = context.get_secret("FILE_ACCESS_TOKEN")
    
    # Validate access (in production, check token against DB)
    # Read file with safety bounds
    
    return {
        "content": file_content,
        "note": f"Access validated with token (...{token[-4:]})"
    }
```

**Test**:
```
> use snykhttp.read_file to read examples/vulnerable_code.py
```

**What happens** (and why it's GOOD security):

```
Error: Tool 'snykhttp_ReadFile' cannot be executed over 
unauthenticated HTTP transport for security reasons. This tool requires 
end-user authorization or access to sensitive secrets.

See: https://docs.arcade.dev/en/home/compare-server-types
```

**STOP. This is not a bug. This is EXCELLENT security!** 🎯

**Talk Track** (during workshop):

> "Look at that error. Arcade is refusing to run a tool with secrets over unauthenticated HTTP. This is security by design.
>
> Why? Because HTTP without authentication is unprotected. If your server is running on localhost and someone else on your network knows the port, they could call tools that use secrets. Arcade prevents this.
>
> This error is PROOF that Arcade takes security seriously. It won't let you accidentally expose secrets over insecure transport.
>
> To use tools with secrets or OAuth locally, you have two options:
> 1. Use **stdio transport** (process-isolated, secure)
> 2. Deploy to **Arcade Cloud** (authenticated HTTPS)
>
> Let me show you stdio..."

**Demo with stdio**:

```bash
# Stop HTTP server
# Start with stdio transport
python3 server.py stdio
```
```bash
# Configure Gemini CLI for stdio:
# Edit file ~/.gemini/settings.json
{
  "mcpServers": {
    "snykstdio": {
      "command": "/absolute/path/to/snyk-mcp-workshop/.venv/bin/python",
      "args": ["server.py", "stdio"],
      "cwd": "/absolute/path/to/snyk-mcp-workshop/",
      "env": {
        "FILE_ACCESS_TOKEN": "demo-token-2025"
      }
    }
  }
}
```
```bash
# Check Tools
gemini mcp list
#Restart after MCP check
gemini

# Now test again:
> use snykstdio.read_file to read examples/vulnerable_code.py
```

**Now it works!** Returns file content with `"note": "Access validated with token (...2025)"`

**Toxic Flow Prevention**:
- **Factor #2**: Secret in `.env`, injected at runtime
- LLM sees: `"...2025"` (last 4 chars only)
- Full secret NEVER in MCP protocol
- **BONUS**: Arcade enforces transport security (won't run over unprotected HTTP)

**The Security Model**:
1. Secret stored in `.env`: `FILE_ACCESS_TOKEN=demo-file-access-token-2025`
2. Tool decorated: `@app.tool(requires_secrets=["FILE_ACCESS_TOKEN"])`
3. **Arcade checks transport**: HTTP unauth? → Reject! stdio or HTTPS? → Allow!
4. At runtime: `context.get_secret("FILE_ACCESS_TOKEN")` retrieves it
5. MCP protocol: `{"tool": "read_file", "args": {"path": "..."}}` ← **No secret!**

**This is defense in depth**: Not just runtime injection, but also transport validation!

---

### Tool 3: `analyze_code_security` - Security Analysis
Let's Revert Back to HTTP-Streamable First:
```bash
#STOP RUNNING STDIO SERVER
#START HTTP SERVER 
python3 server.py http
#REMOVE STDIO FIELDS FROM ~/.gemini/settings.json
gemini mcp list #should see one HTTP Server
```
**Intent**: Find security vulnerabilities in code

**Code**:
```python
@app.tool
async def analyze_code_security(context: Context, code: str) -> dict:
    await context.log.info("Analyzing code...")
    
    issues = []
    
    # Check for code injection
    if "eval(" in code:
        issues.append({
            "severity": "CRITICAL",
            "type": "Code Injection",
            "issue": "eval() usage detected"
        })
    
    # Check for unsafe deserialization
    if "pickle.loads(" in code:
        issues.append({
            "severity": "CRITICAL",
            "type": "Unsafe Deserialization",
            "issue": "pickle.loads() detected"
        })
    
    # + checks for os.system, SQL injection, hardcoded secrets, etc.
    
    return {
        "total_issues": len(issues),
        "severity_counts": {...},
        "issues": issues
    }
```

**Test**:
```
> use snykhttp.analyze_code_security to check:
import pickle
def process(data):
    obj = pickle.loads(data)
    eval(obj['cmd'])
```

**Result**:
```json
{
  "total_issues": 2,
  "severity_counts": {"CRITICAL": 2},
  "issues": [
    {"severity": "CRITICAL", "type": "Unsafe Deserialization", "issue": "pickle.loads()"},
    {"severity": "CRITICAL", "type": "Code Injection", "issue": "eval()"}
  ],
  "recommendation": "❌ CRITICAL - Do not deploy"
}
```

**Why it's LLM-friendly**:
- **Intent-based**: "analyze this code for security issues"
- Not: "POST /api/v1/security/scan with headers X-API-Key..."
- **Structured output**: JSON the LLM can reason about
- **Actionable**: Includes remediation guidance

---

### Tool 4: `fetch_github_code` - OAuth Injection

**Intent**: Get code from a GitHub repository

**Code**:
```python
@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def fetch_github_code(
    context: Context,
    owner: Annotated[str, "Repository owner"],
    repo: Annotated[str, "Repository name"],
    file_path: Annotated[str, "File path"]
) -> str:
    # OAuth token injected by Arcade platform
    token = context.get_auth_token_or_empty()
    
    # Proper GitHub API headers (following Arcade pattern)
    headers = {
        "Accept": "application/vnd.github.raw+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text
```


**Test**:
```
> use snykhttp.fetch_github_code for the repo arcadeai/snyk-mcp-workshop/examples/hello_world.py
```

**Toxic Flow Prevention**:
- **Factor #2**: GitHub OAuth token managed by Arcade
- User `Authorize With OAuth URL` → Arcade stores token
- At runtime: Token injected via `context.get_auth_token_or_empty()`
- MCP protocol: `{"tool": "fetch_github_code", "args": {"repo": "..."}` ← **No token!**

**Multi-Tenant**:
- Alice calls tool → Gets **her** GitHub token
- Bob calls tool → Gets **his** GitHub token
- Same server, isolated credentials


### Tool 5: `security_audit_workflow` - 🔥 THE WOW MOMENT

**Intent**: Complete security audit (fetch code + analyze)

**Code**:
```python
@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def security_audit_workflow(
    context: Context,
    repo: Annotated[str, "GitHub repository"],
    file_path: Annotated[str, "File to audit"]
) -> dict:
    await context.log.info(f"🔍 Starting audit for {repo}/{file_path}")
    
    # CHAIN 1: Fetch code from GitHub
    # Child tool INHERITS parent's GitHub OAuth!
    code_result = await context.tools.call_raw(
        "SnykSecurityServer.FetchGithubCode",
        {"repo": repo, "file_path": file_path}
    )
    
    # CHAIN 2: Analyze the fetched code
    analysis_result = await context.tools.call_raw(
        "SnykSecurityServer.AnalyzeCodeSecurity",
        {"code": code_result.value}
    )
    
    return {
        "repo": repo,
        "file": file_path,
        "security_analysis": analysis_result.value,
        "workflow": {
            "auth_flow": "GitHub OAuth shared across tool chain",
            "toxic_flow_prevention": "OAuth never in MCP protocol"
        }
    }
```

**Test**:
```
> use snykhttp.security_audit_workflow for repo arcadeai/snyk-mcp-workshop/examples/hello_world.py
```

**Watch the server logs**:
```
INFO | 🔍 Starting security audit for octocat/Hello-World/README.md
INFO | Step 1: Fetching code from GitHub (using OAuth)...
INFO | Step 1 complete: Fetched 1234 characters
INFO | Step 2: Analyzing code for security vulnerabilities...
INFO | Step 2 complete: Found 0 potential issues
INFO | ✅ Security audit workflow complete!
```

**OAuth Continuity - THE MAGIC**:

```
┌─────────────────────────────────────────────────────────┐
│  Parent Tool: security_audit_workflow                   │
│  Has GitHub OAuth from @app.tool(requires_auth=GitHub())│
└──────────────────────┬──────────────────────────────────┘
                       │
         context.tools.call_raw("FetchGithubCode", ...)
                       │
┌──────────────────────▼──────────────────────────────────┐
│  Child Tool: fetch_github_code                          │
│  INHERITS parent's GitHub OAuth token!                  │
│  Same token, no re-auth, secure propagation             │
└──────────────────────┬──────────────────────────────────┘
                       │ Returns code
┌──────────────────────▼──────────────────────────────────┐
│  Child Tool: analyze_code_security                      │
│  Analyzes the fetched code (no auth needed)             │
└──────────────────────┬──────────────────────────────────┘
                       │ Returns analysis
┌──────────────────────▼───────────────────────────────────┐
│  Parent Tool: Combines results                           │
│  Returns comprehensive audit report                      │
└──────────────────────────────────────────────────────────┘

SAME GitHub token through 3 tools!
LLM never saw it in ANY MCP call!
```

**Toxic Flow Prevention at Scale**:
- One OAuth token
- Three tools (parent + 2 children)
- Two GitHub API calls
- **ZERO appearances in MCP protocol**

**This is architectural security.**

**Why this is revolutionary**:
- **Composable**: Build complex workflows from simple tools
- **Secure**: OAuth propagates, never exposes
- **LLM-friendly**: "Audit this file from GitHub" (one intent, multi-step execution)
- **Not traditional APIs**: LLM doesn't see OAuth flows, HTTP verbs, header management

---

## 🔗 Tool Chaining: Composable Security

### Why Tool Chaining Matters

**Without chaining**: Each tool is isolated, LLM coordinates
```
LLM: Call fetch_code → Get result → Call analyze → Get result → Combine
     ↑ LLM has to manage state and coordinate
```

**With chaining**: Tools orchestrate, LLM gives intent
```
LLM: Call security_audit_workflow
Tool: Fetches code → Analyzes → Returns combined report
      ↑ Tool manages workflow, LLM just states intent
```

**Benefits**:
- **Simpler for LLM**: One intent ("audit this file") vs multi-step coordination
- **Secure**: OAuth flows through chain, LLM never sees it
- **Composable**: Build complex workflows from simple building blocks
- **Atomic**: Workflow succeeds or fails as a unit

### How `context.tools.call_raw()` Works

```python
# Parent tool
@app.tool(requires_auth=GitHub(scopes=["repo"]))
async def parent_tool(context: Context) -> dict:
    # Context has:
    # - context.user_id: "alice"
    # - context.session_id: "sess_123"
    # - context.authorization: {github_token}
    
    # Call child tool
    result = await context.tools.call_raw(
        "SnykSecurityServer.ChildTool",
        {"param": "value"}
    )
    
    # Child tool executed with SAME context:
    # - Same user_id: "alice"
    # - Same session_id: "sess_123"
    # - Same authorization: {github_token}
    
    return result.value
```

**Key Insight**: `context` propagates automatically. Child inherits parent's credentials, session, everything.

---

## 🌐 Part 2: Arcade Gateway - Instant Production Tools

### What is Arcade Gateway?

A unified Secure MCP server exposing 1000+ production toolkits without writing code.
The Gateway is your Centralized Zone for Security and Governance Management.

<div align="center">

```
┌───────────────────────────────────────────────────────────┐
│              Arcade Gateway Architecture                  │
│                                                           │
│  Gemini CLI ────► Arcade Gateway ────► Toolkits           │
│                   (One endpoint)        │                 │
│                                         ├─► Google        │
│                                         ├─► Slack         │
│                                         ├─► Gmail         │
│                                         ├─► GitHub        │
│                                         ├─► Notion        │
│                                         └─► 1k+ more      │
│                                                           │
│  Benefits:                                                │
│  ✓ No code to write                                       │
│  ✓ OAuth managed by Arcade                                │
│  ✓ One security boundary                                  │
│  ✓ Centralized governance                                 │
└───────────────────────────────────────────────────────────┘
```

</div>

### Setup Steps

#### 1. Create Gateway (5 minutes)

Visit [dashboard.arcade.dev](https://dashboard.arcade.dev):

1. Click **"MCP Gateways"** → **"Create Gateway"**
2. Name: `Snyk Workshop Gateway`
3. **Select Toolkits**:
   - ✅ Google (Calendar, Gmail, Drive)
   - ✅ Slack (Channels, Messages)
   - ✅ 1000+ more available
4. **Save** and copy:
   - Gateway slug (e.g., `snyk-workshop-abc123`)
4. Create API Key
   - Click [Get API Key](https://api.arcade.dev/dashboard/api-keys)
   - Create an API Key

#### 2. Configure Gemini CLI

Use Gemini CLI Commands:
```bash
gemini mcp add arcade -t http https://api.arcade.dev/mcp/YOUR-SLUG -H "Authorization: Bearer arc_YOUR_PROJECT_API_KEY" -H "Arcade-User-ID: your@email.com"
```

OR edit `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "snykhttp": {
      "httpUrl": "http://127.0.0.1:8000/mcp"
    },
    "arcade": {
      "httpUrl": "https://api.arcade.dev/mcp/YOUR-SLUG",
      "headers": {
        "Authorization": "Bearer <YOUR_PROJECT_API_KEY>",
        "Arcade-User-ID": "<YOUR_EMAIL>"
      }
    }
  }
}
```

Replace:
- `YOUR-SLUG` → Your gateway slug
- `YOUR_PROJECT_API_KEY` → Your project API key
- `YOUR_EMAIL` → Your Arcade account email

#### 3. Test Both Servers

```bash
gemini mcp list #You Should See 2 Servers
```

**You'll see TWO servers**:
```
MCP Servers:
1. snyk_security (5 tools)
   - greet
   - read_file
   - analyze_code_security
   - fetch_github_code
   - security_audit_workflow

2. arcade_gateway (Many+ tools)
   - Google.Calendar.ListEvents
   - Google.Calendar.CreateEvent
   - Slack.PostMessage
   - Gmail.SendEmail
   - GitHub.CreateIssue
   - ... and more
```

**Test custom server**:
```
> use snykhttp.analyze_code_security to check: import pickle; pickle.loads(data)
```

**Test gateway**:
```
> What emails did I get this morning? And what is on my calendar right now?
```

### Why Use Both?

**Custom Server (what you built)**:
- ✓ Custom business logic
- ✓ Security-specific tools
- ✓ Full control over implementation
- ✓ Your intellectual property

**Arcade Gateway**:
- ✓ Production toolkits instantly
- ✓ No code to maintain
- ✓ OAuth already handled
- ✓ Updates managed by Arcade

**Together**: Custom + Commodity = Complete Solution

---

## 🔐 Escaped the Toxic Flow Triangle: Complete Analysis

### Factor #1: Untrusted Instructions

**What it is**: Prompt injection, jailbreaks, malicious user input

**How we mitigate**:
- ✅ **Type validation**: `Annotated[str, "description"]` guides LLM
- ✅ **Input bounds**: `max_bytes` limits prevent DoS
- ✅ **Structured errors**: Return JSON, not stack traces
- ✅ **Intent-based design**: Tools match LLM reasoning patterns

**Can we eliminate it?** No. Users must interact with AI. But we validate.

---

### Factor #2: Sensitive Data

**What it is**: API keys, OAuth tokens, database credentials

**How we ELIMINATE it**:
- ✅ **Secrets in `.env`**: `FILE_ACCESS_TOKEN` stored outside code
- ✅ **OAuth via platform**: `@app.tool(requires_auth=GitHub)` → Arcade manages tokens
- ✅ **Runtime injection**: `context.get_secret()`, `context.get_auth_token_or_empty()`
- ✅ **Never in protocol**: MCP messages contain NO credentials

**Can we eliminate it?** **YES!** Credentials stay server-side. Protocol is clean.

**This is the breakthrough**: Factor #2 eliminated = Triangle broken.

---

### Factor #3: Exfil Path

**What it is**: Logs, caches, LLM conversation memory, debug output

**How we BREAK it**:
- ✅ **No data to exfil**: If factor #2 is eliminated, nothing sensitive in protocol
- ✅ **Logs are clean**: Server logs don't echo secrets (we show last 4 chars only)
- ✅ **LLM memory clean**: Conversation history has no credentials
- ✅ **Caches safe**: MCP clients cache protocol messages, which are credential-free

**Can we eliminate it?** We don't need to! Without factor #2, there's nothing sensitive to exfiltrate.

---

### Result: Architecture Prevents Toxic Flows

Traditional MCP:
```
1️⃣ Untrusted input + 2️⃣ Credentials in protocol + 3️⃣ Logs/caches = ☠️ TOXIC FLOW
```

Arcade MCP:
```
1️⃣ Untrusted input + ❌ (Factor #2 eliminated) + 3️⃣ Exfil path = ✅ SAFE
                        ↑
              No sensitive data in protocol
              = Nothing to exfiltrate
```

**You can't exfiltrate what isn't in the protocol.**


## 💡 Key Takeaways

### What You Learned

1. **Toxic Flow Triangle**: 3 factors that combine to create AI security risks
2. **Architectural Security**: Design to prevent, not just detect
3. **Runtime Injection**: Secrets/OAuth injected at execution, never in protocol
4. **Tool Chaining**: Composable workflows with secure context propagation
5. **Intent-Specific Tools**: Built for LLMs, not traditional REST APIs
6. **Gateway Pattern**: Custom tools + commodity integrations

### Why This Matters

**Before Arcade MCP**:
- Credentials hardcoded or passed as parameters
- OAuth tokens visible to LLMs
- Tools isolated, LLM coordinates
- Factor #2 and #3 present → Toxic flow risk

**With Arcade MCP**:
- Credentials server-side only
- Runtime injection via context
- Tools chain with shared secure context
- **Factor #2 eliminated → Triangle broken**

**Result**: You can govern what you can observe, and you can't exfiltrate what isn't there.


---

<div align="center">

**Simple. Secure. Production-Ready.**

[🚀 Get Started](https://docs.arcade.dev/en/home/custom-mcp-server-quickstart) | [📖 Read the Docs](https://docs.arcade.dev) | [💬 Join Discord](https://discord.com/invite/GUZEMpEZ9p)

</div>

---

<p align="center">
  <sub>Built with ❤️ @Arcade.dev for AI devs who care about security</sub>
</p>
