"""Framework integrations and benchmark adapters."""

from taintgate.integrations.langchain import (
    TaintGateToolWrapper,
    TaintGateSecurityError,
    wrap_tool,
)
from taintgate.integrations.openai_agents import TaintGateReActMediator
from taintgate.integrations.agentdojo import TaintGateDojoPipelineElement

__all__ = [
    "TaintGateToolWrapper",
    "TaintGateSecurityError",
    "wrap_tool",
    "TaintGateReActMediator",
    "TaintGateDojoPipelineElement",
]
