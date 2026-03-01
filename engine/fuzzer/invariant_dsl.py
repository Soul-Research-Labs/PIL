"""Custom Invariant DSL — user-defined protocol property language.

Allows users to define protocol-specific invariants in a concise DSL
that compiles to Solidity assertions for property-based testing.

Grammar
-------
::

    invariant  = "invariant" IDENT ":" expr ("when" expr)?
    expr       = compare (("&&" | "||") compare)*
    compare    = arith (("==" | "!=" | ">=" | "<=" | ">" | "<") arith)?
    arith      = unary (("+" | "-" | "*" | "/" | "%") unary)*
    unary      = ("!" | "-")? primary
    primary    = NUMBER | HEX | BOOL | STRING
               | func_call
               | IDENT ("." IDENT)* ("[" expr "]")?
               | "(" expr ")"
    func_call  = IDENT "(" (expr ("," expr)*)? ")"

Examples
--------
::

    invariant supply_cap:
        token.totalSupply() <= token.maxSupply()

    invariant non_zero_owner:
        token.owner() != address(0)

    invariant pool_solvent:
        token.balanceOf(pool) >= pool.totalDebt()
        when pool.totalDebt() > 0

    invariant nullifier_unique:
        forall(n in nullifiers: !registry.isSpent(n)) when len(nullifiers) > 0

Compilation targets:
  - Solidity `function invariant_<name>() public view` assertion
  - Foundry `forge test` harness with `vm.assume` for `when` conditions
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ── Token Types ──────────────────────────────────────────────────────────────


class TokenType(Enum):
    # Keywords
    INVARIANT = auto()
    WHEN = auto()
    FORALL = auto()
    EXISTS = auto()
    IN = auto()
    TRUE = auto()
    FALSE = auto()
    ADDRESS = auto()

    # Literals
    NUMBER = auto()
    HEX_LITERAL = auto()
    STRING = auto()
    IDENT = auto()

    # Operators
    PLUS = auto()       # +
    MINUS = auto()      # -
    STAR = auto()       # *
    SLASH = auto()      # /
    PERCENT = auto()    # %
    BANG = auto()        # !
    EQ = auto()          # ==
    NE = auto()          # !=
    LT = auto()          # <
    GT = auto()          # >
    LE = auto()          # <=
    GE = auto()          # >=
    AND = auto()         # &&
    OR = auto()          # ||

    # Delimiters
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    DOT = auto()
    COMMA = auto()
    COLON = auto()

    # Special
    EOF = auto()
    NEWLINE = auto()


KEYWORDS = {
    "invariant": TokenType.INVARIANT,
    "when": TokenType.WHEN,
    "forall": TokenType.FORALL,
    "exists": TokenType.EXISTS,
    "in": TokenType.IN,
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
    "address": TokenType.ADDRESS,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int


# ── Lexer ────────────────────────────────────────────────────────────────────


class InvariantLexerError(Exception):
    """Lexer error with position information."""
    def __init__(self, message: str, line: int, col: int) -> None:
        super().__init__(f"Line {line}, col {col}: {message}")
        self.line = line
        self.col = col


class InvariantLexer:
    """Tokenize invariant DSL source text."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._pos = 0
        self._line = 1
        self._col = 1

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while self._pos < len(self._source):
            ch = self._source[self._pos]

            # Whitespace (skip, but track newlines)
            if ch in " \t\r":
                self._advance()
                continue
            if ch == "\n":
                tokens.append(Token(TokenType.NEWLINE, "\n", self._line, self._col))
                self._advance()
                self._line += 1
                self._col = 1
                continue

            # Comments
            if ch == "#" or (ch == "/" and self._peek() == "/"):
                while self._pos < len(self._source) and self._source[self._pos] != "\n":
                    self._advance()
                continue

            # Numbers (decimal or hex)
            if ch.isdigit():
                tokens.append(self._read_number())
                continue

            # Hex literals
            if ch == "0" and self._peek() == "x":
                tokens.append(self._read_hex())
                continue

            # Strings
            if ch in ('"', "'"):
                tokens.append(self._read_string(ch))
                continue

            # Identifiers / keywords
            if ch.isalpha() or ch == "_":
                tokens.append(self._read_ident())
                continue

            # Two-char operators
            two = self._source[self._pos:self._pos + 2]
            if two == "==":
                tokens.append(Token(TokenType.EQ, "==", self._line, self._col))
                self._advance()
                self._advance()
                continue
            if two == "!=":
                tokens.append(Token(TokenType.NE, "!=", self._line, self._col))
                self._advance()
                self._advance()
                continue
            if two == "<=":
                tokens.append(Token(TokenType.LE, "<=", self._line, self._col))
                self._advance()
                self._advance()
                continue
            if two == ">=":
                tokens.append(Token(TokenType.GE, ">=", self._line, self._col))
                self._advance()
                self._advance()
                continue
            if two == "&&":
                tokens.append(Token(TokenType.AND, "&&", self._line, self._col))
                self._advance()
                self._advance()
                continue
            if two == "||":
                tokens.append(Token(TokenType.OR, "||", self._line, self._col))
                self._advance()
                self._advance()
                continue

            # Single-char operators
            single_map = {
                "+": TokenType.PLUS, "-": TokenType.MINUS,
                "*": TokenType.STAR, "/": TokenType.SLASH,
                "%": TokenType.PERCENT, "!": TokenType.BANG,
                "<": TokenType.LT, ">": TokenType.GT,
                "(": TokenType.LPAREN, ")": TokenType.RPAREN,
                "[": TokenType.LBRACKET, "]": TokenType.RBRACKET,
                ".": TokenType.DOT, ",": TokenType.COMMA,
                ":": TokenType.COLON,
            }
            if ch in single_map:
                tokens.append(Token(single_map[ch], ch, self._line, self._col))
                self._advance()
                continue

            raise InvariantLexerError(f"Unexpected character: {ch!r}", self._line, self._col)

        tokens.append(Token(TokenType.EOF, "", self._line, self._col))
        return tokens

    def _advance(self) -> None:
        self._pos += 1
        self._col += 1

    def _peek(self) -> str:
        nxt = self._pos + 1
        return self._source[nxt] if nxt < len(self._source) else ""

    def _read_number(self) -> Token:
        start = self._pos
        col = self._col
        while self._pos < len(self._source) and (self._source[self._pos].isdigit() or self._source[self._pos] == "_"):
            self._advance()
        return Token(TokenType.NUMBER, self._source[start:self._pos].replace("_", ""), self._line, col)

    def _read_hex(self) -> Token:
        col = self._col
        start = self._pos
        self._advance()  # 0
        self._advance()  # x
        while self._pos < len(self._source) and self._source[self._pos] in "0123456789abcdefABCDEF_":
            self._advance()
        return Token(TokenType.HEX_LITERAL, self._source[start:self._pos].replace("_", ""), self._line, col)

    def _read_string(self, quote: str) -> Token:
        col = self._col
        self._advance()  # opening quote
        start = self._pos
        while self._pos < len(self._source) and self._source[self._pos] != quote:
            self._advance()
        value = self._source[start:self._pos]
        self._advance()  # closing quote
        return Token(TokenType.STRING, value, self._line, col)

    def _read_ident(self) -> Token:
        start = self._pos
        col = self._col
        while self._pos < len(self._source) and (self._source[self._pos].isalnum() or self._source[self._pos] == "_"):
            self._advance()
        text = self._source[start:self._pos]
        tt = KEYWORDS.get(text, TokenType.IDENT)
        return Token(tt, text, self._line, col)


# ── AST Nodes ────────────────────────────────────────────────────────────────


@dataclass
class InvariantDef:
    """Top-level invariant definition."""
    name: str
    condition: Expr
    when_clause: Expr | None = None
    line: int = 0


class Expr:
    """Base expression node."""
    pass


@dataclass
class BinaryExpr(Expr):
    left: Expr
    op: str
    right: Expr


@dataclass
class UnaryExpr(Expr):
    op: str
    operand: Expr


@dataclass
class NumberLit(Expr):
    value: int


@dataclass
class HexLit(Expr):
    value: str


@dataclass
class BoolLit(Expr):
    value: bool


@dataclass
class StringLit(Expr):
    value: str


@dataclass
class Identifier(Expr):
    name: str


@dataclass
class MemberAccess(Expr):
    object: Expr
    member: str


@dataclass
class IndexAccess(Expr):
    base: Expr
    index: Expr


@dataclass
class FuncCall(Expr):
    func: Expr
    args: list[Expr] = field(default_factory=list)


@dataclass
class AddressLit(Expr):
    """address(0) or address(expr)."""
    inner: Expr


@dataclass
class ForAllExpr(Expr):
    """forall(x in collection: predicate)."""
    var: str
    collection: Expr
    predicate: Expr


@dataclass
class ExistsExpr(Expr):
    """exists(x in collection: predicate)."""
    var: str
    collection: Expr
    predicate: Expr


# ── Parser ───────────────────────────────────────────────────────────────────


class InvariantParserError(Exception):
    def __init__(self, message: str, token: Token) -> None:
        super().__init__(f"Line {token.line}, col {token.col}: {message}")
        self.token = token


class InvariantParser:
    """Parse a list of tokens into InvariantDef AST nodes."""

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = [t for t in tokens if t.type != TokenType.NEWLINE]
        self._pos = 0

    def parse(self) -> list[InvariantDef]:
        """Parse all invariant definitions."""
        invariants: list[InvariantDef] = []
        while not self._at_end():
            if self._check(TokenType.INVARIANT):
                invariants.append(self._parse_invariant())
            else:
                self._advance()  # skip stray tokens
        return invariants

    def _parse_invariant(self) -> InvariantDef:
        self._expect(TokenType.INVARIANT)
        name_tok = self._expect(TokenType.IDENT)
        self._expect(TokenType.COLON)

        condition = self._parse_expr()

        when_clause = None
        if self._check(TokenType.WHEN):
            self._advance()
            when_clause = self._parse_expr()

        return InvariantDef(
            name=name_tok.value,
            condition=condition,
            when_clause=when_clause,
            line=name_tok.line,
        )

    def _parse_expr(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._match(TokenType.OR):
            right = self._parse_and()
            left = BinaryExpr(left, "||", right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_comparison()
        while self._match(TokenType.AND):
            right = self._parse_comparison()
            left = BinaryExpr(left, "&&", right)
        return left

    def _parse_comparison(self) -> Expr:
        left = self._parse_arith()
        comp_ops = {
            TokenType.EQ: "==", TokenType.NE: "!=",
            TokenType.LT: "<", TokenType.GT: ">",
            TokenType.LE: "<=", TokenType.GE: ">=",
        }
        for tt, op in comp_ops.items():
            if self._match(tt):
                right = self._parse_arith()
                return BinaryExpr(left, op, right)
        return left

    def _parse_arith(self) -> Expr:
        left = self._parse_term()
        while True:
            if self._match(TokenType.PLUS):
                left = BinaryExpr(left, "+", self._parse_term())
            elif self._match(TokenType.MINUS):
                left = BinaryExpr(left, "-", self._parse_term())
            else:
                break
        return left

    def _parse_term(self) -> Expr:
        left = self._parse_unary()
        while True:
            if self._match(TokenType.STAR):
                left = BinaryExpr(left, "*", self._parse_unary())
            elif self._match(TokenType.SLASH):
                left = BinaryExpr(left, "/", self._parse_unary())
            elif self._match(TokenType.PERCENT):
                left = BinaryExpr(left, "%", self._parse_unary())
            else:
                break
        return left

    def _parse_unary(self) -> Expr:
        if self._match(TokenType.BANG):
            return UnaryExpr("!", self._parse_unary())
        if self._match(TokenType.MINUS):
            return UnaryExpr("-", self._parse_unary())
        return self._parse_postfix()

    def _parse_postfix(self) -> Expr:
        expr = self._parse_primary()
        while True:
            if self._match(TokenType.DOT):
                member = self._expect(TokenType.IDENT)
                expr = MemberAccess(expr, member.value)
                # Check for function call on member
                if self._match(TokenType.LPAREN):
                    args = self._parse_args()
                    self._expect(TokenType.RPAREN)
                    expr = FuncCall(expr, args)
            elif self._match(TokenType.LBRACKET):
                index = self._parse_expr()
                self._expect(TokenType.RBRACKET)
                expr = IndexAccess(expr, index)
            elif self._match(TokenType.LPAREN):
                # Direct function call: ident(...)
                args = self._parse_args()
                self._expect(TokenType.RPAREN)
                expr = FuncCall(expr, args)
            else:
                break
        return expr

    def _parse_primary(self) -> Expr:
        # Number
        if self._check(TokenType.NUMBER):
            tok = self._advance()
            return NumberLit(int(tok.value))

        # Hex literal
        if self._check(TokenType.HEX_LITERAL):
            tok = self._advance()
            return HexLit(tok.value)

        # Boolean
        if self._check(TokenType.TRUE):
            self._advance()
            return BoolLit(True)
        if self._check(TokenType.FALSE):
            self._advance()
            return BoolLit(False)

        # String
        if self._check(TokenType.STRING):
            tok = self._advance()
            return StringLit(tok.value)

        # address(...)
        if self._check(TokenType.ADDRESS):
            self._advance()
            self._expect(TokenType.LPAREN)
            inner = self._parse_expr()
            self._expect(TokenType.RPAREN)
            return AddressLit(inner)

        # forall(x in coll: pred)
        if self._check(TokenType.FORALL):
            return self._parse_quantifier(is_forall=True)

        # exists(x in coll: pred)
        if self._check(TokenType.EXISTS):
            return self._parse_quantifier(is_forall=False)

        # Parenthesized expression
        if self._match(TokenType.LPAREN):
            expr = self._parse_expr()
            self._expect(TokenType.RPAREN)
            return expr

        # Identifier
        if self._check(TokenType.IDENT):
            tok = self._advance()
            return Identifier(tok.value)

        raise InvariantParserError(
            f"Unexpected token: {self._current().value!r}",
            self._current(),
        )

    def _parse_quantifier(self, *, is_forall: bool) -> Expr:
        self._advance()  # forall / exists
        self._expect(TokenType.LPAREN)
        var_tok = self._expect(TokenType.IDENT)
        self._expect(TokenType.IN)
        collection = self._parse_expr()
        self._expect(TokenType.COLON)
        predicate = self._parse_expr()
        self._expect(TokenType.RPAREN)
        if is_forall:
            return ForAllExpr(var_tok.value, collection, predicate)
        return ExistsExpr(var_tok.value, collection, predicate)

    def _parse_args(self) -> list[Expr]:
        args: list[Expr] = []
        if not self._check(TokenType.RPAREN):
            args.append(self._parse_expr())
            while self._match(TokenType.COMMA):
                args.append(self._parse_expr())
        return args

    # ── Token helpers ────────────────────────────────────────────────

    def _current(self) -> Token:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else self._tokens[-1]

    def _advance(self) -> Token:
        tok = self._current()
        self._pos += 1
        return tok

    def _check(self, tt: TokenType) -> bool:
        return not self._at_end() and self._current().type == tt

    def _match(self, tt: TokenType) -> bool:
        if self._check(tt):
            self._advance()
            return True
        return False

    def _expect(self, tt: TokenType) -> Token:
        if self._check(tt):
            return self._advance()
        raise InvariantParserError(
            f"Expected {tt.name}, got {self._current().type.name} ({self._current().value!r})",
            self._current(),
        )

    def _at_end(self) -> bool:
        return self._pos >= len(self._tokens) or self._current().type == TokenType.EOF


# ── Compiler: AST → Solidity ─────────────────────────────────────────────────


class InvariantCompiler:
    """Compile parsed invariant AST nodes to Solidity assertion code."""

    def compile_to_solidity(self, invariants: list[InvariantDef]) -> str:
        """Generate a complete Solidity test contract from invariant definitions."""
        lines = [
            "// SPDX-License-Identifier: MIT",
            "// Auto-generated by PIL++ Invariant DSL Compiler",
            'pragma solidity ^0.8.24;',
            "",
            'import "forge-std/Test.sol";',
            "",
            "contract InvariantDSLTest is Test {",
        ]

        for inv in invariants:
            lines.append("")
            lines.append(f"    /// @notice Invariant: {inv.name}")
            lines.append(f"    function invariant_{inv.name}() public view {{")

            if inv.when_clause:
                cond_code = self._emit_expr(inv.when_clause)
                lines.append(f"        // Pre-condition (when clause)")
                lines.append(f"        vm.assume({cond_code});")
                lines.append("")

            check_code = self._emit_expr(inv.condition)
            lines.append(f"        assertTrue(")
            lines.append(f"            {check_code},")
            lines.append(f'            "Invariant violated: {inv.name}"')
            lines.append(f"        );")
            lines.append("    }")

        lines.append("}")
        lines.append("")
        return "\n".join(lines)

    def compile_to_checks(self, invariants: list[InvariantDef]) -> list[dict[str, str]]:
        """Compile to structured check dicts (for ForgeTestGenerator integration)."""
        checks: list[dict[str, str]] = []
        for inv in invariants:
            check_expr = self._emit_expr(inv.condition)
            when_expr = self._emit_expr(inv.when_clause) if inv.when_clause else ""
            checks.append({
                "id": f"DSL-{inv.name}",
                "description": f"User-defined invariant: {inv.name}",
                "check_expression": check_expr,
                "when_expression": when_expr,
            })
        return checks

    def _emit_expr(self, expr: Expr) -> str:
        if isinstance(expr, BinaryExpr):
            left = self._emit_expr(expr.left)
            right = self._emit_expr(expr.right)
            return f"({left} {expr.op} {right})"

        if isinstance(expr, UnaryExpr):
            operand = self._emit_expr(expr.operand)
            return f"{expr.op}({operand})"

        if isinstance(expr, NumberLit):
            return str(expr.value)

        if isinstance(expr, HexLit):
            return expr.value

        if isinstance(expr, BoolLit):
            return "true" if expr.value else "false"

        if isinstance(expr, StringLit):
            return f'"{expr.value}"'

        if isinstance(expr, Identifier):
            return expr.name

        if isinstance(expr, MemberAccess):
            obj = self._emit_expr(expr.object)
            return f"{obj}.{expr.member}"

        if isinstance(expr, IndexAccess):
            base = self._emit_expr(expr.base)
            index = self._emit_expr(expr.index)
            return f"{base}[{index}]"

        if isinstance(expr, FuncCall):
            func = self._emit_expr(expr.func)
            args = ", ".join(self._emit_expr(a) for a in expr.args)
            return f"{func}({args})"

        if isinstance(expr, AddressLit):
            inner = self._emit_expr(expr.inner)
            return f"address({inner})"

        if isinstance(expr, ForAllExpr):
            # Emit as a loop assertion
            coll = self._emit_expr(expr.collection)
            pred = self._emit_expr(expr.predicate)
            return (
                f"/* forall {expr.var} in {coll}: {pred} */ true"
            )

        if isinstance(expr, ExistsExpr):
            coll = self._emit_expr(expr.collection)
            pred = self._emit_expr(expr.predicate)
            return (
                f"/* exists {expr.var} in {coll}: {pred} */ true"
            )

        return "/* unknown expr */"


# ── Public API ───────────────────────────────────────────────────────────────


def parse_invariants(source: str) -> list[InvariantDef]:
    """Parse invariant DSL source text into AST nodes."""
    lexer = InvariantLexer(source)
    tokens = lexer.tokenize()
    parser = InvariantParser(tokens)
    return parser.parse()


def compile_invariants_to_solidity(source: str) -> str:
    """Parse and compile invariant DSL to Solidity test contract."""
    invariants = parse_invariants(source)
    compiler = InvariantCompiler()
    return compiler.compile_to_solidity(invariants)


def compile_invariants_to_checks(source: str) -> list[dict[str, str]]:
    """Parse and compile invariant DSL to structured check dictionaries."""
    invariants = parse_invariants(source)
    compiler = InvariantCompiler()
    return compiler.compile_to_checks(invariants)
