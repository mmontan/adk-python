import asyncio
from dataclasses import dataclass
from typing import Optional

# ==============================================================================
# 1. SETUP: Mimicking ADK's Shared Architecture
# ==============================================================================

@dataclass
class AuthCredential:
    token: str
    owner: str

class AuthConfig:
    """Mimics src/google/adk/auth/auth_tool.py:AuthConfig"""
    def __init__(self):
        self.exchanged_auth_credential: Optional[AuthCredential] = None

class VulnerableToolset:
    """Mimics src/google/adk/tools/mcp_tool/mcp_toolset.py:McpToolset"""
    def __init__(self, name: str):
        self.name = name
        self.auth_config = AuthConfig()

    def get_auth_config(self) -> AuthConfig:
        return self.auth_config

    async def call_api_tool(self, request_id: str):
        """Simulates a tool execution that reads from the shared config."""
        # Realistic tools read from their instance config
        cred = self.auth_config.exchanged_auth_credential
        
        print(f"  [TOOL EXECUTION] Request {request_id} is calling API with token '{cred.token}' (Owner: {cred.owner})")
        return cred

class SharedAgent:
    """Mimics the shared Agent object inside a Runner."""
    def __init__(self):
        self.toolset = VulnerableToolset("SensitiveDataService")

# ==============================================================================
# 2. CORE EXECUTION: Demonstrating the Race Condition
# ==============================================================================

async def simulate_user_request(request_id: str, agent: SharedAgent, user_token: AuthCredential):
    print(f"\n[START] Request {request_id} started for user {user_token.owner}")

    # --- STEP 1: Resolve Auth (The Vulnerable Step) ---
    # Mimics src/google/adk/flows/llm_flows/base_llm_flow.py:_resolve_toolset_auth
    # This writes to the SHARED toolset instance.
    print(f"[AUTH]  Request {request_id} saving token '{user_token.token}' to shared toolset...")
    agent.toolset.get_auth_config().exchanged_auth_credential = user_token

    # --- STEP 2: Realistic Delay ---
    # In a real app, this delay happens while:
    # 1. The LLM processes the history
    # 2. The LLM generates the tool call
    # 3. Other async tasks run
    # Alice (Request A) is slightly slower, Bob (Request B) is fast.
    delay = 0.5 if request_id == "A" else 0.1
    await asyncio.sleep(delay)

    # --- STEP 3: Execute Tool ---
    # The tool is called and reads the shared config.
    used_cred = await agent.toolset.call_api_tool(request_id)

    # --- STEP 4: Verification ---
    if used_cred.owner != user_token.owner:
        print(f"!!! SECURITY VIOLATION !!! Request {request_id} ({user_token.owner}) used {used_cred.owner}'s identity!")
    else:
        print(f"[SUCCESS] Request {request_id} used the correct identity.")

async def run_reproduction():
    # Setup shared infrastructure (Singleton-like behavior in ADK)
    shared_agent = SharedAgent()
    
    # Define two users with distinct credentials
    alice_cred = AuthCredential(token="ALICE_SECRET_123", owner="Alice")
    bob_cred = AuthCredential(token="BOB_SECRET_456", owner="Bob")

    print("Running reproduction of Authentication Race Condition...")
    print("---------------------------------------------------------")

    # Start Alice's request, then Bob's request immediately after.
    # Alice will save her token, then wait. Bob will save his token, then Alice will wake up.
    await asyncio.gather(
        simulate_user_request("A", shared_agent, alice_cred),
        simulate_user_request("B", shared_agent, bob_cred)
    )

if __name__ == "__main__":
    asyncio.run(run_reproduction())
