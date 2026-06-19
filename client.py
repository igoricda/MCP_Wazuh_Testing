"""
client.py — LangGraph ReAct agent backed by the Wazuh Indexer MCP server.

Usage:
    python client.py
    python client.py "alertas críticos nas últimas 2 horas"

The MCP server (wazuh_indexer_mcp/server.py) is launched automatically as a
subprocess via stdio transport — no separate process needed.

Dependencies:
    pip install langchain-mcp-adapters langchain-ollama langgraph python-dotenv
    pip install -e ./wazuh-indexer-mcp          # the server package
"""

from __future__ import annotations

import asyncio
import sys
import os
import logging
import json
from pathlib import Path
from typing import List
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient

# 1. Use the dedicated partner package instead of the legacy community package
from langchain_ollama import ChatOllama

# 2. Use LangGraph's prebuilt ReAct agent instead of the legacy AgentExecutor
from langchain.agents import create_agent

from langchain_mcp_adapters.tools import load_mcp_tools

load_dotenv()

# ─── Verbose agent logger ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,       # suppress noisy lib logs
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
agent_log = logging.getLogger("agent")
agent_log.setLevel(logging.DEBUG)

def _log_event(event: dict) -> None:
    """Print a human-readable trace of every agent step."""
    messages = event.get("messages", [])
    if not messages:
        return
    last = messages[-1]
    role    = getattr(last, "type", None) or getattr(last, "role", "unknown")
    content = getattr(last, "content", "")

    if role == "ai":
        # Check for tool_calls embedded in the message
        tool_calls = getattr(last, "tool_calls", []) or []
        if tool_calls:
            for tc in tool_calls:
                name = tc.get("name", "?")
                args = tc.get("args", {})
                print(f"\n  🔧 [TOOL CALL] {name}")
                print(f"     args: {json.dumps(args, ensure_ascii=False, indent=6)}")
        elif content:
            # Reasoning / thinking step
            print(f"\n  🤔 [THINKING]\n{_indent(content)}")

    elif role == "tool":
        name    = getattr(last, "name", "?")
        result  = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        # Truncate very long results for readability
        if len(result) > 1000:
            result = result[:1000] + "\n     ... [truncated]"
        print(f"\n  📥 [TOOL RESULT] {name}\n{_indent(result)}")

    elif role in ("assistant",):
        if content:
            print(f"\n  🤔 [THINKING]\n{_indent(content)}")


def _indent(text: str, prefix: str = "     ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())



# ─── Resolve server.py path relative to this file ────────────────────────────
# Works regardless of whether client.py is in src/ or project root.
_HERE       = Path(__file__).resolve().parent
# Try sibling wazuh_indexer_mcp/server.py (flat layout) then src/ sub-layout
_SERVER_PY  = _HERE /  "server.py"
if not _SERVER_PY.exists():
    _SERVER_PY = _HERE.parent / "src"  / "server.py"
if not _SERVER_PY.exists():
    raise FileNotFoundError(
        f"Cannot find server.py. Looked in:\n"
        f"  {_HERE  / 'server.py'}\n"
        f"  {_HERE.parent / 'src'  / 'server.py'}"
    )

# Use the same python interpreter that is running this script
_PYTHON = sys.executable



# ─── Configuration ────────────────────────────────────────────────────────────
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

INDEXER_HOST = os.getenv("INDEXER_HOST", "localhost")
INDEXER_PORT = os.getenv("INDEXER_PORT", "9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "admin")

WAZUH_HOST = os.getenv("WAZUH_HOST", "")
WAZUH_USER = os.getenv("WAZUH_USER", "")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")

# ─── MCP server config ────────────────────────────────────────────────────────
# Server is launched as a child process via stdio.
# We call server.py directly by file path — no pip install needed.
MCP_CONFIG: dict = {
    "wazuh-indexer": {
        "transport": "stdio",
        "command": _PYTHON,
        "args": [str(_SERVER_PY)],
        # Merge with the current environment so PATH, VIRTUAL_ENV, and other
        # uv/venv variables are inherited by the server subprocess.
        "env": {
            **os.environ,
            "INDEXER_HOST":        INDEXER_HOST,
            "INDEXER_PORT":        INDEXER_PORT,
            "INDEXER_USER":        INDEXER_USER,
            "INDEXER_PASS":        INDEXER_PASS,
            "WAZUH_VERIFY_SSL":    os.getenv("WAZUH_VERIFY_SSL", "false"),
            "DEFAULT_RESULT_SIZE": os.getenv("DEFAULT_RESULT_SIZE", "10"),
            "MAX_RESULT_SIZE":     os.getenv("MAX_RESULT_SIZE", "100"),
            "LOG_LEVEL":           os.getenv("LOG_LEVEL", "WARNING"),
        },
    },

    # ── Optional: Wazuh Manager MCP alongside ───────────────────────────────
    # Uncomment if you want manager tools (agents, rules, etc.)
    #
    # "wazuh-manager": {
    #     "command": "/home/igor/wazuh-ollama/mcp-server-wazuh",
    #     "transport": "stdio",
    #     "args": [],
    #     "env": {
    #         "WAZUH_API_HOST":         WAZUH_HOST,
    #         "WAZUH_API_PORT":         "55000",
    #         "WAZUH_API_USERNAME":     WAZUH_USER,
    #         "WAZUH_API_PASSWORD":     WAZUH_PASS,
    #         "WAZUH_INDEXER_HOST":     INDEXER_HOST,
    #         "WAZUH_INDEXER_PORT":     INDEXER_PORT,
    #         "WAZUH_INDEXER_USERNAME": INDEXER_USER,
    #         "WAZUH_INDEXER_PASSWORD": INDEXER_PASS,
    #         "WAZUH_VERIFY_SSL":       "false",
    #         "RUST_LOG":               "info",
    #     },
    # },
}

# ─── System prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """# Role and Identity
You are an expert, elite Tier-3 Security Operations Center (SOC) Analyst and Incident Responder. Your primary objective is to monitor, analyze, investigate, and remediate security events, vulnerabilities, and misconfigurations within the infrastructure utilizing live telemetry provided via the Wazuh Model Context Protocol (MCP) server.

# Analytical Approach & Core Competencies
1. **Thorough Threat Evaluation:** Treat every anomaly with strict professional skepticism. Cross-reference active endpoints, running processes, and network exposure to locate hidden vectors.
2. **Proactive Investigation:** Do not simply answer the user's explicit question. When queried about a metric, automatically hunt for underlying anomalies, dependencies, log anomalies, or potential blind spots.
3. **Risk Prioritization:** Rank your findings using standardized severity levels (Critical, High, Medium, Low). Focus immediate mitigation efforts on vulnerabilities and exploits that present severe architectural exposure.
4. **Framework Mapping:** Align all discovered risks, vulnerabilities, and security gaps directly with industry-standard compliance and attack matrices:
   - MITRE ATT&CK (Tactics, Techniques, and Procedures)
   - NIST Cyber Security Framework (CSF)
   - SOC 2 Type II
   - PCI-DSS
   - CIS Benchmarks

# Behavioral Workflow & Response Structure
When executing security assessments or analyzing logs, you must consistently structure your findings into highly structured, actionable intelligence dashboards using the following sections:

## 1. Executive Summary
- Provide a high-level operational overview of the active environment (e.g., total active endpoints, overall risk level, immediate posture status).

## 2. Deep-Dive Log & Threat Analysis
- Breakdown live telemetry data (vulnerabilities, open ports, error logs, or network exposure).
- Highlight explicit indicators of compromise (IoCs), critical CVEs, or critical system warnings.

## 3. Compliance & Coverage Gaps
- Clearly map the findings to outstanding compliance violations or critical network blind spots. Provide explicit status metrics (e.g., "SOC 2 Compliance: Failing").

## 4. Emergency Response Playbook & Immediate Remediation
- Deliver a definitive, phased, step-by-step remediation plan (e.g., Phase 1: Isolation/Patching, Phase 2: Configuration hardening).
- Provide precise Wazuh rule sets, configurations, or shell commands necessary to enforce mitigation.

## 5. Success Metrics & Continuous Monitoring KPIs
- Define clear criteria to evaluate if the remediation succeeded and list key metrics for ongoing continuous monitoring.

# Communication Style
- **Professional & Technical:** Speak as an experienced, authoritative cybersecurity specialist. Use accurate domain terminology (e.g., *log collection coverage*, *external exposure*, *remediation workflow*).
- **Direct & Actionable:** Be concise and lead with the most critical security findings. Cut out unnecessary pleasantries; prioritize high-signal data.
- **Proactive Interrogator:** Conclude your analysis by suggesting specific next-step deep dives, dashboard implementations, or further active network threat hunts."""
# ─── Agent ────────────────────────────────────────────────────────────────────

async def run_agent(question: str, agent, conversation_history: List[dict]) -> None:
    # Append the new user message to the running history
    conversation_history.append({"role": "user", "content": question})

    print(f"\n[User] {question}")
    print("─" * 60)

    final_answer = ""

    async for event in agent.astream(
        {"messages": conversation_history},
        stream_mode="values",
    ):
        _log_event(event)

        # Capture the last AI message as the final answer
        messages = event.get("messages", [])
        if messages:
            last = messages[-1]
            role    = getattr(last, "type", None) or getattr(last, "role", "")
            content = getattr(last, "content", "")
            tool_calls = getattr(last, "tool_calls", []) or []
            if role == "ai" and content and not tool_calls:
                final_answer = content

    print(f"\n{'='*60}")
    print(f"  [Final Answer]\n")
    print(final_answer)
    print(f"{'='*60}\n")

    # Persist the assistant reply so follow-ups have full context
    if final_answer:
        conversation_history.append({"role": "assistant", "content": final_answer})


async def _session() -> None:
    """Build the agent once and loop over user questions."""
    llm = ChatOllama(model=OLLAMA_MODEL, temperature=0)

    client = MultiServerMCPClient(MCP_CONFIG)
    # 2. Busque as ferramentas diretamente do cliente

    mcp_tools = await client.get_tools()

    agent = create_agent(llm, tools=mcp_tools, system_prompt=SYSTEM_PROMPT, debug=True)

    # Shared history across all turns in this session
    conversation_history: List[dict] = []

    print("\nSOC Agent ready. Type your question (or 'exit' to quit, 'clear' to reset history).\n")

    while True:
        try:
            query = input("You › ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Session ended]")
            break

        if not query:
            continue

        if query.lower() in {"exit", "quit", "sair"}:
            print(f"[Session ended — {len(conversation_history) // 2} turn(s)]")
            break

        if query.lower() in {"clear", "limpar", "reset"}:
            conversation_history.clear()
            print("[History cleared]\n")
            continue

        await run_agent(query, agent, conversation_history)


def main() -> None:
    if len(sys.argv) > 1:
        # One-shot mode: behaves exactly like before, single question then exit
        async def _one_shot() -> None:
            llm = ChatOllama(model=OLLAMA_MODEL, temperature=0)
            client = MultiServerMCPClient(MCP_CONFIG)
            mcp_tools = await client.get_tools()
            agent = create_agent(llm, tools=mcp_tools, system_prompt=SYSTEM_PROMPT, debug=True)
            await run_agent(" ".join(sys.argv[1:]), agent, [])

        asyncio.run(_one_shot())
    else:
        asyncio.run(_session())


if __name__ == "__main__":
    main()