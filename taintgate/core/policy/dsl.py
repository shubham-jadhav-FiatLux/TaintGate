"""Policy condition DSL: a typed, AST-walking evaluator (no ``eval``).

Grammar (a strict subset of Python expression syntax)::

    expr  := expr 'and' expr | expr 'or' expr | 'not' expr | cmp | NAME(bool) | BOOL
    cmp   := atom (OP atom)+
    OP    := '==' | '!=' | '<' | '<=' | '>' | '>=' | 'in' | 'not in'
    atom  := NAME | NAME '.' NAME | STRING | BOOL

Names and their static types:

    data.confidentiality / context.confidentiality : Conf
    data.integrity       / context.integrity       : Integ
    effect, tool                                   : Str
    egress                                         : Bool
    recipient (alias: recipients)                  : Dest   (set of call destinations)
    contacts, allowed_domains                      : Set
    public | internal | secret                     : Conf literals
    untrusted | endorsed | trusted                 : Integ literals
    read | local_write | external | irreversible   : Str literals

Typing rules (checked when the policy is loaded, so a malformed rule can never
silently "not match" at run time):

* ``<, <=, >, >=`` only between two Conf or two Integ values.
* ``==, !=`` between two values of the same type (Conf, Integ, Str, Bool).
* ``x in S`` / ``x not in S`` with ``x : Str | Dest`` and ``S : Set``.

Destination quantification: ``recipient in contacts`` holds iff the call has at
least one destination and *every* destination is in ``contacts``;
``recipient not in contacts`` is its exact negation (some destination is not a
contact, or the destination is unknown). Integrity literals are compared on the
trust scale (``untrusted < endorsed < trusted``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, FrozenSet, Tuple

from taintgate.core.lattice import ConfidentialityLevel, IntegrityLevel


class PolicyDSLError(ValueError):
    """Raised when a policy condition is syntactically or type-incorrect."""


CONF, INTEG, STR, BOOL, SET, DEST = "Conf", "Integ", "Str", "Bool", "Set", "Dest"


@dataclass(frozen=True)
class EvalEnv:
    data_confidentiality: ConfidentialityLevel
    data_integrity: IntegrityLevel
    context_confidentiality: ConfidentialityLevel
    context_integrity: IntegrityLevel
    effect: str
    tool: str
    egress: bool
    destinations: FrozenSet[str] = field(default_factory=frozenset)
    contacts: FrozenSet[str] = field(default_factory=frozenset)
    allowed_domains: FrozenSet[str] = field(default_factory=frozenset)


_VARS = {
    "data.confidentiality": (CONF, lambda e: e.data_confidentiality),
    "data.integrity": (INTEG, lambda e: e.data_integrity),
    "target.confidentiality": (CONF, lambda e: e.data_confidentiality),
    "target.integrity": (INTEG, lambda e: e.data_integrity),
    "context.confidentiality": (CONF, lambda e: e.context_confidentiality),
    "context.integrity": (INTEG, lambda e: e.context_integrity),
    "session.confidentiality": (CONF, lambda e: e.context_confidentiality),
    "session.integrity": (INTEG, lambda e: e.context_integrity),
    "effect": (STR, lambda e: e.effect),
    "tool": (STR, lambda e: e.tool),
    "egress": (BOOL, lambda e: e.egress),
    "recipient": (DEST, lambda e: e.destinations),
    "recipients": (DEST, lambda e: e.destinations),
    "contacts": (SET, lambda e: e.contacts),
    "allowed_domains": (SET, lambda e: e.allowed_domains),
}

_LITERALS = {
    "public": (CONF, ConfidentialityLevel.PUBLIC),
    "internal": (CONF, ConfidentialityLevel.INTERNAL),
    "confidential": (CONF, ConfidentialityLevel.INTERNAL),
    "secret": (CONF, ConfidentialityLevel.SECRET),
    "untrusted": (INTEG, IntegrityLevel.UNTRUSTED),
    "tainted": (INTEG, IntegrityLevel.UNTRUSTED),
    "endorsed": (INTEG, IntegrityLevel.ENDORSED),
    "trusted": (INTEG, IntegrityLevel.TRUSTED),
    "clean": (INTEG, IntegrityLevel.TRUSTED),
    "read": (STR, "read"),
    "local_write": (STR, "local_write"),
    "external": (STR, "external"),
    "irreversible": (STR, "irreversible"),
    "true": (BOOL, True),
    "false": (BOOL, False),
}

Node = Tuple[str, Callable[[EvalEnv], Any]]  # (static type, evaluator)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    raise PolicyDSLError(f"Unsupported expression: {ast.dump(node)}")


def _compile_atom(node: ast.AST) -> Node:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            v = node.value
            return BOOL, lambda e: v
        if isinstance(node.value, str):
            s = node.value
            return STR, lambda e: s
        raise PolicyDSLError(f"Unsupported literal {node.value!r} (only strings and booleans)")
    name = _dotted_name(node)
    if name in _VARS:
        return _VARS[name]
    if name in _LITERALS:
        t, v = _LITERALS[name]
        return t, (lambda e, _v=v: _v)
    raise PolicyDSLError(f"Unknown name {name!r} in policy condition")


def _compile_compare(node: ast.Compare) -> Node:
    operands = [_compile_atom(node.left)] + [_compile_atom(c) for c in node.comparators]
    checks = []
    for op, (lt, lf), (rt, rf) in zip(node.ops, operands, operands[1:]):
        if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            if lt != rt or lt not in (CONF, INTEG):
                raise PolicyDSLError(f"Ordering comparison requires two Conf or two Integ values, got {lt} and {rt}")
            fn = {
                ast.Lt: lambda a, b: a < b,
                ast.LtE: lambda a, b: a <= b,
                ast.Gt: lambda a, b: a > b,
                ast.GtE: lambda a, b: a >= b,
            }[type(op)]
        elif isinstance(op, (ast.Eq, ast.NotEq)):
            if lt != rt or lt not in (CONF, INTEG, STR, BOOL):
                raise PolicyDSLError(f"Equality requires two values of the same scalar type, got {lt} and {rt}")
            fn = (lambda a, b: a == b) if isinstance(op, ast.Eq) else (lambda a, b: a != b)
        elif isinstance(op, (ast.In, ast.NotIn)):
            if rt != SET or lt not in (STR, DEST):
                raise PolicyDSLError(f"Membership requires (Str|Dest) in Set, got {lt} in {rt}")
            if lt == DEST:
                def member(a: FrozenSet[str], b: FrozenSet[str]) -> bool:
                    return bool(a) and all(x in b for x in a)
            else:
                def member(a: str, b: FrozenSet[str]) -> bool:
                    return a.lower() in b
            fn = member if isinstance(op, ast.In) else (lambda a, b, _m=member: not _m(a, b))
        else:
            raise PolicyDSLError(f"Unsupported comparison operator {type(op).__name__}")
        checks.append((fn, lf, rf))

    def run(e: EvalEnv) -> bool:
        return all(fn(lf(e), rf(e)) for fn, lf, rf in checks)

    return BOOL, run


def _compile_bool(node: ast.AST) -> Node:
    if isinstance(node, ast.BoolOp):
        parts = [_compile_bool(v) for v in node.values]
        fns = [f for _, f in parts]
        if isinstance(node.op, ast.And):
            return BOOL, lambda e: all(f(e) for f in fns)
        return BOOL, lambda e: any(f(e) for f in fns)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _, f = _compile_bool(node.operand)
        return BOOL, lambda e: not f(e)
    if isinstance(node, ast.Compare):
        return _compile_compare(node)
    t, f = _compile_atom(node)
    if t != BOOL:
        raise PolicyDSLError(f"Expected a boolean expression, got a value of type {t}")
    return BOOL, f


@lru_cache(maxsize=1024)
def compile_condition(expr: str) -> Callable[[EvalEnv], bool]:
    """Parses and type-checks a condition. Raises :class:`PolicyDSLError` on any problem."""
    if not isinstance(expr, str) or not expr.strip():
        raise PolicyDSLError("Empty policy condition")
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as exc:
        raise PolicyDSLError(f"Syntax error in policy condition {expr!r}: {exc.msg}") from exc
    _, fn = _compile_bool(tree.body)
    return fn
