"""Solidity AST analysis engine — structured extraction from solcx compilation.

Walks the Solidity AST (produced by solcx) to extract:
  - Contract hierarchy (inheritance chain)
  - Function definitions with modifiers, visibility, state mutability
  - State variables with types and visibility
  - External calls (call, delegatecall, staticcall, transfer, send)
  - Modifier definitions and usage
  - Event definitions and emissions
  - Error definitions and custom errors
  - Storage layout mapping
  - Inline assembly usage
  - Import paths and dependency tree

This is the foundation for CFG, taint analysis, and AST-powered detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Data Models ──────────────────────────────────────────────────────────────


class Visibility(str, Enum):
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"


class StateMutability(str, Enum):
    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"


class VarMutability(str, Enum):
    MUTABLE = "mutable"
    IMMUTABLE = "immutable"
    CONSTANT = "constant"


@dataclass
class SourceLocation:
    """Precise source location from AST src field (offset:length:fileIndex)."""
    offset: int = 0
    length: int = 0
    file_index: int = 0
    line: int = 0
    end_line: int = 0

    @classmethod
    def from_src(cls, src: str, source_code: str = "") -> "SourceLocation":
        """Parse AST 'src' field like '120:45:0'."""
        parts = src.split(":")
        if len(parts) < 3:
            return cls()
        offset = int(parts[0])
        length = int(parts[1])
        file_index = int(parts[2])
        line = source_code[:offset].count("\n") + 1 if source_code else 0
        end_offset = offset + length
        end_line = source_code[:end_offset].count("\n") + 1 if source_code else 0
        return cls(offset=offset, length=length, file_index=file_index,
                   line=line, end_line=end_line)


@dataclass
class ModifierInvocation:
    """A modifier applied to a function."""
    name: str
    arguments: list[str] = field(default_factory=list)


@dataclass
class Parameter:
    """Function parameter or return value."""
    name: str
    type_name: str
    storage_location: str = ""  # memory, storage, calldata
    indexed: bool = False  # for event params


@dataclass
class ExternalCall:
    """An external call made within a function."""
    target: str  # expression being called
    call_type: str  # call, delegatecall, staticcall, transfer, send, high-level
    arguments: list[str] = field(default_factory=list)
    value_sent: bool = False  # true if ETH is sent
    return_checked: bool = True
    src: SourceLocation = field(default_factory=SourceLocation)
    line: int = 0


@dataclass
class StateWrite:
    """A state variable write within a function."""
    variable: str
    src: SourceLocation = field(default_factory=SourceLocation)
    line: int = 0
    is_before_external_call: bool = False


@dataclass
class FunctionDef:
    """Parsed function definition from AST."""
    name: str
    selector: str = ""  # 4-byte selector
    visibility: Visibility = Visibility.PUBLIC
    state_mutability: StateMutability = StateMutability.NONPAYABLE
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    modifiers: list[ModifierInvocation] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    returns: list[Parameter] = field(default_factory=list)
    external_calls: list[ExternalCall] = field(default_factory=list)
    state_writes: list[StateWrite] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    local_variables: list[Parameter] = field(default_factory=list)
    has_inline_assembly: bool = False
    has_unchecked_block: bool = False
    emits_events: list[str] = field(default_factory=list)
    body_node: dict[str, Any] | None = None
    src: SourceLocation = field(default_factory=SourceLocation)
    line: int = 0
    end_line: int = 0
    complexity: int = 0  # cyclomatic complexity estimate


@dataclass
class StateDef:
    """Parsed state variable definition."""
    name: str
    type_name: str
    visibility: Visibility = Visibility.INTERNAL
    mutability: VarMutability = VarMutability.MUTABLE
    initial_value: str = ""
    is_mapping: bool = False
    is_array: bool = False
    slot: int | None = None  # storage slot if known
    src: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class EventDef:
    """Parsed event definition."""
    name: str
    parameters: list[Parameter] = field(default_factory=list)
    anonymous: bool = False
    src: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class ModifierDef:
    """Parsed modifier definition."""
    name: str
    parameters: list[Parameter] = field(default_factory=list)
    has_placeholder: bool = True  # _; statement
    body_node: dict[str, Any] | None = None
    src: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class InheritanceSpec:
    """Base contract in inheritance chain."""
    name: str
    arguments: list[str] = field(default_factory=list)


@dataclass
class ContractDef:
    """Complete parsed contract from AST."""
    name: str
    kind: str = "contract"  # contract, library, interface, abstract
    is_abstract: bool = False
    bases: list[InheritanceSpec] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    state_variables: list[StateDef] = field(default_factory=list)
    events: list[EventDef] = field(default_factory=list)
    modifiers: list[ModifierDef] = field(default_factory=list)
    structs: list[str] = field(default_factory=list)
    enums: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    using_for: list[tuple[str, str]] = field(default_factory=list)  # (library, type)
    src: SourceLocation = field(default_factory=SourceLocation)
    linearized_bases: list[str] = field(default_factory=list)

    # Computed properties
    @property
    def public_functions(self) -> list[FunctionDef]:
        return [f for f in self.functions
                if f.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL)
                and not f.is_constructor]

    @property
    def external_functions(self) -> list[FunctionDef]:
        return [f for f in self.functions if f.visibility == Visibility.EXTERNAL]

    @property
    def state_changing_functions(self) -> list[FunctionDef]:
        return [f for f in self.functions
                if f.state_mutability in (StateMutability.NONPAYABLE, StateMutability.PAYABLE)]

    @property
    def payable_functions(self) -> list[FunctionDef]:
        return [f for f in self.functions if f.state_mutability == StateMutability.PAYABLE]

    @property
    def has_selfdestruct(self) -> bool:
        return any("selfdestruct" in str(f.body_node) for f in self.functions if f.body_node)

    @property
    def has_delegatecall(self) -> bool:
        return any(c.call_type == "delegatecall" for f in self.functions for c in f.external_calls)

    @property
    def total_complexity(self) -> int:
        return sum(f.complexity for f in self.functions)

    def get_function(self, name: str) -> FunctionDef | None:
        return next((f for f in self.functions if f.name == name), None)


@dataclass
class ASTAnalysisResult:
    """Complete AST analysis result for a Solidity file."""
    contracts: list[ContractDef] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    pragma_version: str = ""
    license: str = ""
    source_code: str = ""
    file_name: str = ""

    @property
    def main_contract(self) -> ContractDef | None:
        """Return the 'main' contract (last non-library, non-interface)."""
        for c in reversed(self.contracts):
            if c.kind == "contract":
                return c
        return self.contracts[-1] if self.contracts else None


# ── AST Visitor / Walker ─────────────────────────────────────────────────────


class SolidityASTAnalyzer:
    """Walk solcx-produced Solidity AST and extract structured data.

    Supports AST node types from Solidity 0.4.x through 0.8.x.
    """

    def __init__(self, source_code: str = "") -> None:
        self._source = source_code
        self._state_var_names: set[str] = set()

    def analyze(
        self,
        ast: dict[str, Any],
        source_code: str = "",
        file_name: str = "Contract.sol",
    ) -> ASTAnalysisResult:
        """Analyze a complete Solidity AST from solcx compilation."""
        if source_code:
            self._source = source_code

        result = ASTAnalysisResult(source_code=self._source, file_name=file_name)

        if not ast:
            return result

        node_type = ast.get("nodeType", "")

        if node_type == "SourceUnit":
            result.pragma_version = self._extract_pragma(ast)
            result.license = ast.get("license", "")
            result.imports = self._extract_imports(ast)

            for node in ast.get("nodes", []):
                if node.get("nodeType") == "ContractDefinition":
                    contract = self._visit_contract(node)
                    result.contracts.append(contract)

        return result

    def analyze_sources(
        self,
        sources_ast: dict[str, Any],
        source_code: str = "",
    ) -> list[ASTAnalysisResult]:
        """Analyze multiple source file ASTs from compilation."""
        results: list[ASTAnalysisResult] = []
        for file_name, ast in sources_ast.items():
            r = self.analyze(ast, source_code=source_code, file_name=file_name)
            results.append(r)
        return results

    # ── Contract visitor ─────────────────────────────────────────────

    def _visit_contract(self, node: dict) -> ContractDef:
        """Visit a ContractDefinition node."""
        contract = ContractDef(
            name=node.get("name", ""),
            kind=node.get("contractKind", "contract"),
            is_abstract=node.get("abstract", False),
            src=SourceLocation.from_src(node.get("src", ""), self._source),
        )

        # Inheritance
        for base in node.get("baseContracts", []):
            base_name_node = base.get("baseName", {})
            name = base_name_node.get("name", "") or base_name_node.get("namePath", "")
            args_node = base.get("arguments", [])
            args = [str(a) for a in (args_node or [])]
            contract.bases.append(InheritanceSpec(name=name, arguments=args))

        # Linearized base contracts
        contract.linearized_bases = [
            str(b) for b in node.get("linearizedBaseContracts", [])
        ]

        # Using-for directives
        for child in node.get("nodes", []):
            nt = child.get("nodeType", "")

            if nt == "FunctionDefinition":
                func = self._visit_function(child)
                contract.functions.append(func)

            elif nt == "VariableDeclaration":
                var = self._visit_state_variable(child)
                contract.state_variables.append(var)
                self._state_var_names.add(var.name)

            elif nt == "EventDefinition":
                event = self._visit_event(child)
                contract.events.append(event)

            elif nt == "ModifierDefinition":
                modifier = self._visit_modifier(child)
                contract.modifiers.append(modifier)

            elif nt == "StructDefinition":
                contract.structs.append(child.get("name", ""))

            elif nt == "EnumDefinition":
                contract.enums.append(child.get("name", ""))

            elif nt == "ErrorDefinition":
                contract.errors.append(child.get("name", ""))

            elif nt == "UsingForDirective":
                lib = child.get("libraryName", {}).get("name", "")
                typ = self._type_name_to_str(child.get("typeName"))
                contract.using_for.append((lib, typ))

        return contract

    # ── Function visitor ─────────────────────────────────────────────

    def _visit_function(self, node: dict) -> FunctionDef:
        """Visit a FunctionDefinition node."""
        kind = node.get("kind", "function")
        name = node.get("name", "")

        func = FunctionDef(
            name=name or kind,
            visibility=Visibility(node.get("visibility", "public")),
            state_mutability=StateMutability(node.get("stateMutability", "nonpayable")),
            is_constructor=kind == "constructor",
            is_fallback=kind == "fallback",
            is_receive=kind == "receive",
            src=SourceLocation.from_src(node.get("src", ""), self._source),
            body_node=node.get("body"),
        )

        func.line = func.src.line
        func.end_line = func.src.end_line

        # Function selector from documentation or computed
        if node.get("functionSelector"):
            func.selector = node["functionSelector"]

        # Parameters
        params_node = node.get("parameters", {})
        for p in params_node.get("parameters", []):
            func.parameters.append(Parameter(
                name=p.get("name", ""),
                type_name=self._type_name_to_str(p.get("typeName")),
                storage_location=p.get("storageLocation", ""),
            ))

        # Return parameters
        returns_node = node.get("returnParameters", {})
        for p in returns_node.get("parameters", []):
            func.returns.append(Parameter(
                name=p.get("name", ""),
                type_name=self._type_name_to_str(p.get("typeName")),
                storage_location=p.get("storageLocation", ""),
            ))

        # Modifiers
        for mod in node.get("modifiers", []):
            mod_name = mod.get("modifierName", {}).get("name", "")
            args = []
            for a in mod.get("arguments", []) or []:
                args.append(self._extract_expression_text(a))
            func.modifiers.append(ModifierInvocation(name=mod_name, arguments=args))

        # Walk the function body for calls, state writes, reads, etc.
        body = node.get("body")
        if body:
            self._walk_function_body(func, body)

        return func

    def _walk_function_body(self, func: FunctionDef, node: dict, depth: int = 0) -> None:
        """Recursively walk function body to extract calls, writes, reads."""
        if not isinstance(node, dict):
            return

        nt = node.get("nodeType", "")

        # External calls
        if nt == "FunctionCall":
            call = self._extract_external_call(node)
            if call:
                func.external_calls.append(call)

        # State variable writes (Assignment)
        if nt == "Assignment":
            lhs = node.get("leftHandSide", {})
            var_name = self._extract_state_var_name(lhs)
            if var_name and var_name in self._state_var_names:
                sw = StateWrite(
                    variable=var_name,
                    src=SourceLocation.from_src(node.get("src", ""), self._source),
                )
                sw.line = sw.src.line
                sw.is_before_external_call = len(func.external_calls) == 0
                func.state_writes.append(sw)

        # State variable reads
        if nt == "Identifier":
            name = node.get("name", "")
            if name in self._state_var_names and name not in func.state_reads:
                func.state_reads.append(name)

        # Inline assembly
        if nt in ("InlineAssembly", "YulBlock"):
            func.has_inline_assembly = True

        # Unchecked blocks
        if nt == "UncheckedBlock":
            func.has_unchecked_block = True

        # Event emissions
        if nt == "EmitStatement":
            event_call = node.get("eventCall", {})
            expr = event_call.get("expression", {})
            event_name = expr.get("name", "") or expr.get("memberName", "")
            if event_name:
                func.emits_events.append(event_name)

        # Cyclomatic complexity (branches)
        if nt in ("IfStatement", "ForStatement", "WhileStatement",
                   "DoWhileStatement", "Conditional"):
            func.complexity += 1

        # Recurse into child nodes
        for key, value in node.items():
            if key in ("typeName", "typeDescriptions"):
                continue
            if isinstance(value, dict):
                self._walk_function_body(func, value, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk_function_body(func, item, depth + 1)

    def _extract_external_call(self, node: dict) -> ExternalCall | None:
        """Extract external call info from a FunctionCall node."""
        expression = node.get("expression", {})
        nt = expression.get("nodeType", "")

        # Low-level calls: addr.call{value:}(...)
        if nt == "MemberAccess":
            member = expression.get("memberName", "")
            if member in ("call", "delegatecall", "staticcall", "transfer", "send"):
                target = self._extract_expression_text(expression.get("expression", {}))
                value_sent = member in ("transfer", "send") or bool(node.get("names"))
                return ExternalCall(
                    target=target,
                    call_type=member,
                    value_sent=value_sent,
                    src=SourceLocation.from_src(node.get("src", ""), self._source),
                    line=SourceLocation.from_src(node.get("src", ""), self._source).line,
                )

        # High-level external calls: token.transfer(...)
        if nt == "MemberAccess":
            expr_type = expression.get("expression", {}).get("typeDescriptions", {})
            type_str = expr_type.get("typeString", "")
            if "contract " in type_str or "interface " in type_str:
                target = self._extract_expression_text(expression.get("expression", {}))
                member = expression.get("memberName", "")
                return ExternalCall(
                    target=f"{target}.{member}",
                    call_type="high-level",
                    src=SourceLocation.from_src(node.get("src", ""), self._source),
                    line=SourceLocation.from_src(node.get("src", ""), self._source).line,
                )

        return None

    # ── State variable visitor ───────────────────────────────────────

    def _visit_state_variable(self, node: dict) -> StateDef:
        """Visit a VariableDeclaration (state variable)."""
        mutability = VarMutability.MUTABLE
        if node.get("constant"):
            mutability = VarMutability.CONSTANT
        elif node.get("mutability") == "immutable":
            mutability = VarMutability.IMMUTABLE

        type_str = self._type_name_to_str(node.get("typeName"))

        return StateDef(
            name=node.get("name", ""),
            type_name=type_str,
            visibility=Visibility(node.get("visibility", "internal")),
            mutability=mutability,
            is_mapping="mapping" in type_str.lower(),
            is_array="[]" in type_str,
            src=SourceLocation.from_src(node.get("src", ""), self._source),
        )

    # ── Event visitor ────────────────────────────────────────────────

    def _visit_event(self, node: dict) -> EventDef:
        """Visit an EventDefinition node."""
        event = EventDef(
            name=node.get("name", ""),
            anonymous=node.get("anonymous", False),
            src=SourceLocation.from_src(node.get("src", ""), self._source),
        )
        for p in node.get("parameters", {}).get("parameters", []):
            event.parameters.append(Parameter(
                name=p.get("name", ""),
                type_name=self._type_name_to_str(p.get("typeName")),
                indexed=p.get("indexed", False),
            ))
        return event

    # ── Modifier visitor ─────────────────────────────────────────────

    def _visit_modifier(self, node: dict) -> ModifierDef:
        """Visit a ModifierDefinition node."""
        modifier = ModifierDef(
            name=node.get("name", ""),
            body_node=node.get("body"),
            src=SourceLocation.from_src(node.get("src", ""), self._source),
        )
        for p in node.get("parameters", {}).get("parameters", []):
            modifier.parameters.append(Parameter(
                name=p.get("name", ""),
                type_name=self._type_name_to_str(p.get("typeName")),
            ))
        return modifier

    # ── Helpers ──────────────────────────────────────────────────────

    def _type_name_to_str(self, type_node: dict | None) -> str:
        """Convert an AST TypeName node to a human-readable string."""
        if not type_node:
            return ""
        nt = type_node.get("nodeType", "")

        if nt == "ElementaryTypeName":
            return type_node.get("name", "")

        if nt == "UserDefinedTypeName":
            path = type_node.get("pathNode", type_node.get("name", ""))
            if isinstance(path, dict):
                return path.get("name", str(path))
            return str(path) if path else type_node.get("referencedDeclaration", "")

        if nt == "Mapping":
            key = self._type_name_to_str(type_node.get("keyType"))
            val = self._type_name_to_str(type_node.get("valueType"))
            return f"mapping({key} => {val})"

        if nt == "ArrayTypeName":
            base = self._type_name_to_str(type_node.get("baseType"))
            length = type_node.get("length")
            return f"{base}[{length if length else ''}]"

        if nt == "FunctionTypeName":
            return "function(...)"

        # Fallback
        type_str = type_node.get("typeDescriptions", {}).get("typeString", "")
        return type_str or str(type_node.get("name", "unknown"))

    def _extract_expression_text(self, node: dict) -> str:
        """Extract a readable text representation of an expression node."""
        if not isinstance(node, dict):
            return str(node)

        nt = node.get("nodeType", "")

        if nt == "Identifier":
            return node.get("name", "")

        if nt == "MemberAccess":
            expr = self._extract_expression_text(node.get("expression", {}))
            member = node.get("memberName", "")
            return f"{expr}.{member}"

        if nt == "IndexAccess":
            base = self._extract_expression_text(node.get("baseExpression", {}))
            idx = self._extract_expression_text(node.get("indexExpression", {}))
            return f"{base}[{idx}]"

        if nt == "Literal":
            return node.get("value", "")

        if nt == "FunctionCall":
            expr = self._extract_expression_text(node.get("expression", {}))
            return f"{expr}(...)"

        return node.get("name", "") or ""

    def _extract_state_var_name(self, node: dict) -> str:
        """Extract the state variable name from an assignment LHS."""
        if not isinstance(node, dict):
            return ""
        nt = node.get("nodeType", "")
        if nt == "Identifier":
            return node.get("name", "")
        if nt == "IndexAccess":
            return self._extract_state_var_name(node.get("baseExpression", {}))
        if nt == "MemberAccess":
            return self._extract_state_var_name(node.get("expression", {}))
        return ""

    def _extract_pragma(self, ast: dict) -> str:
        """Extract pragma solidity version from SourceUnit."""
        for node in ast.get("nodes", []):
            if node.get("nodeType") == "PragmaDirective":
                literals = node.get("literals", [])
                if literals and literals[0] == "solidity":
                    return "".join(literals[1:])
        return ""

    def _extract_imports(self, ast: dict) -> list[str]:
        """Extract import paths from SourceUnit."""
        imports: list[str] = []
        for node in ast.get("nodes", []):
            if node.get("nodeType") == "ImportDirective":
                imports.append(node.get("absolutePath", node.get("file", "")))
        return imports


# ── Convenience functions ────────────────────────────────────────────────────


def analyze_ast(
    ast: dict[str, Any],
    source_code: str = "",
    file_name: str = "Contract.sol",
) -> ASTAnalysisResult:
    """Convenience function to analyze a Solidity AST."""
    analyzer = SolidityASTAnalyzer(source_code)
    return analyzer.analyze(ast, source_code, file_name)


def analyze_compilation(
    sources_ast: dict[str, Any],
    source_code: str = "",
) -> list[ASTAnalysisResult]:
    """Analyze all source ASTs from a compilation result."""
    analyzer = SolidityASTAnalyzer(source_code)
    return analyzer.analyze_sources(sources_ast, source_code)
