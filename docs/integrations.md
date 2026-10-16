# TaintGate Integrations Guide

## 1. Overview

TaintGate supports two primary integration patterns:
1. **MCP Proxy**: A network and stdio proxy speaking the Model Context Protocol (MCP) on both sides. Works transparently with tools in Claude Desktop, Claude Code, Cursor, and custom MCP clients.
2. **Framework Wrappers**: Direct Python hooks and tool decorators for LangChain, OpenAI Agents SDK, and AgentDojo benchmark pipelines.

Both patterns share the identical core policy decision engine (`taintgate.core`).

---

## 2. MCP Proxy Mode

The MCP Proxy sits between the agent host and the target MCP server(s):

```bash
# Running TaintGate proxy in front of an MCP filesystem server
taintgate proxy --config policy.yaml -- npx @modelcontextprotocol/server-filesystem ~/work
```

### Interception Points
- `tools/list`: Intercepts advertised tools, hashes their schemas and descriptions to detect silent tampering (tool-description poisoning), and attaches policy annotations.
- `tools/call`: Evaluates arguments against the session context and tool effect annotations. Triggers `ALLOW`, `DENY`, `APPROVE`, or `REDACT`.
- `resources/read`: Intercepts file/resource accesses and applies path-specific confidentiality/integrity labels.
- `prompts/get`: Labels prompt templates by declared trust level.

---

## 3. Framework Wrappers

### 3.1 LangChain
Wrap LangChain tools with `TaintGateToolWrapper`:

```python
from langchain_core.tools import tool
from taintgate.integrations.langchain import wrap_tool
from taintgate.core import Engine

engine = Engine.from_config("policy.yaml")

@tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient."""
    return "Email sent."

protected_tool = wrap_tool(send_email, engine=engine, effect="external")
```

### 3.2 OpenAI Agents SDK / ReAct
Intercept tool calling loops using the session context manager:

```python
from taintgate.session import SessionTracker
from taintgate.core import DecisionType

session = SessionTracker(engine=engine)

# In tool execution dispatch:
decision = session.evaluate_tool_call(tool_name="email.send", arguments={"to": recipient, "body": content})
if decision.type == DecisionType.DENY:
    raise SecurityException(f"Call blocked by TaintGate: {decision.explanation}")
```

### 3.3 AgentDojo Pipeline Element
TaintGate integrates directly as an AgentDojo pipeline filter, running across the 97 user tasks and 629 security test cases without modifying model evaluation code.
