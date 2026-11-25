"""
Module 2: Syntax Analysis and AST Generation
Implements AST node structures and parser for building Abstract Syntax Trees
"""

from typing import List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Enumeration of AST node types"""
    PROGRAM = "PROGRAM"
    FUNCTION_DECL = "FUNCTION_DECL"
    CLASS_DECL = "CLASS_DECL"
    VARIABLE_DECL = "VARIABLE_DECL"
    PARAMETER = "PARAMETER"
    BLOCK = "BLOCK"
    IF_STMT = "IF_STMT"
    WHILE_STMT = "WHILE_STMT"
    FOR_STMT = "FOR_STMT"
    RETURN_STMT = "RETURN_STMT"
    ASSIGNMENT = "ASSIGNMENT"
    BINARY_EXPR = "BINARY_EXPR"
    UNARY_EXPR = "UNARY_EXPR"
    CALL_EXPR = "CALL_EXPR"
    MEMBER_EXPR = "MEMBER_EXPR"
    IDENTIFIER = "IDENTIFIER"
    LITERAL = "LITERAL"
    ARRAY = "ARRAY"
    OBJECT = "OBJECT"
    PROPERTY = "PROPERTY"


@dataclass
class ASTNode:
    """Base class for AST nodes"""
    type: NodeType
    line: int
    column: int
    children: List['ASTNode'] = field(default_factory=list)
    
    def add_child(self, node: 'ASTNode'):
        """Add a child node"""
        self.children.append(node)
    
    def to_dict(self) -> dict:
        """Convert node to dictionary representation"""
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'children': [child.to_dict() for child in self.children]
        }


@dataclass
class ProgramNode(ASTNode):
    """Root node representing the entire program"""
    def __init__(self, line: int = 1, column: int = 1):
        super().__init__(NodeType.PROGRAM, line, column)


@dataclass
class FunctionDeclNode(ASTNode):
    """Function declaration node"""
    name: str = ""
    parameters: List[str] = field(default_factory=list)
    body: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'name': self.name,
            'parameters': self.parameters,
            'body': self.body.to_dict() if self.body else None
        }


@dataclass
class ClassDeclNode(ASTNode):
    """Class declaration node"""
    name: str = ""
    superclass: Optional[str] = None
    body: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'name': self.name,
            'superclass': self.superclass,
            'body': self.body.to_dict() if self.body else None
        }


@dataclass
class VariableDeclNode(ASTNode):
    """Variable declaration node"""
    name: str = ""
    var_type: Optional[str] = None
    init_value: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'name': self.name,
            'var_type': self.var_type,
            'init_value': self.init_value.to_dict() if self.init_value else None
        }


@dataclass
class IfStmtNode(ASTNode):
    """If statement node"""
    condition: Optional[ASTNode] = None
    then_branch: Optional[ASTNode] = None
    else_branch: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'condition': self.condition.to_dict() if self.condition else None,
            'then_branch': self.then_branch.to_dict() if self.then_branch else None,
            'else_branch': self.else_branch.to_dict() if self.else_branch else None
        }


@dataclass
class WhileStmtNode(ASTNode):
    """While statement node"""
    condition: Optional[ASTNode] = None
    body: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'condition': self.condition.to_dict() if self.condition else None,
            'body': self.body.to_dict() if self.body else None
        }


@dataclass
class ForStmtNode(ASTNode):
    """For statement node"""
    init: Optional[ASTNode] = None
    condition: Optional[ASTNode] = None
    increment: Optional[ASTNode] = None
    body: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'init': self.init.to_dict() if self.init else None,
            'condition': self.condition.to_dict() if self.condition else None,
            'increment': self.increment.to_dict() if self.increment else None,
            'body': self.body.to_dict() if self.body else None
        }


@dataclass
class ReturnStmtNode(ASTNode):
    """Return statement node"""
    value: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'value': self.value.to_dict() if self.value else None
        }


@dataclass
class AssignmentNode(ASTNode):
    """Assignment node"""
    target: str = ""
    operator: str = "="
    value: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'target': self.target,
            'operator': self.operator,
            'value': self.value.to_dict() if self.value else None
        }


@dataclass
class BinaryExprNode(ASTNode):
    """Binary expression node"""
    operator: str = ""
    left: Optional[ASTNode] = None
    right: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'operator': self.operator,
            'left': self.left.to_dict() if self.left else None,
            'right': self.right.to_dict() if self.right else None
        }


@dataclass
class UnaryExprNode(ASTNode):
    """Unary expression node"""
    operator: str = ""
    operand: Optional[ASTNode] = None
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'operator': self.operator,
            'operand': self.operand.to_dict() if self.operand else None
        }


@dataclass
class CallExprNode(ASTNode):
    """Function call expression node"""
    callee: str = ""
    arguments: List[ASTNode] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'callee': self.callee,
            'arguments': [arg.to_dict() for arg in self.arguments]
        }


@dataclass
class IdentifierNode(ASTNode):
    """Identifier node"""
    name: str = ""
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'name': self.name
        }


@dataclass
class LiteralNode(ASTNode):
    """Literal value node"""
    value: Any = None
    literal_type: str = "string"
    
    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'line': self.line,
            'column': self.column,
            'value': self.value,
            'literal_type': self.literal_type
        }


class ASTBuilder:
    """Builds AST from tokens"""
    
    def __init__(self):
        self.root: Optional[ProgramNode] = None
    
    def build_ast(self, tokens) -> ProgramNode:
        """
        Build an AST from a list of tokens
        
        Args:
            tokens: List of Token objects from tokenizer
            
        Returns:
            ProgramNode representing the root of the AST
        """
        self.root = ProgramNode()
        
        # Simple parsing logic (would be more sophisticated in production)
        current_function = None
        current_block = self.root
        
        for i, token in enumerate(tokens):
            if token.type.value == "KEYWORD":
                if token.value in ['def', 'function']:
                    # Function declaration
                    if i + 1 < len(tokens):
                        func_node = FunctionDeclNode(
                            type=NodeType.FUNCTION_DECL,
                            line=token.line,
                            column=token.column
                        )
                        func_node.name = tokens[i + 1].value
                        self.root.add_child(func_node)
                        current_function = func_node
                elif token.value == 'class':
                    # Class declaration
                    if i + 1 < len(tokens):
                        class_node = ClassDeclNode(
                            type=NodeType.CLASS_DECL,
                            line=token.line,
                            column=token.column
                        )
                        class_node.name = tokens[i + 1].value
                        self.root.add_child(class_node)
                elif token.value == 'if':
                    # If statement
                    if_node = IfStmtNode(type=NodeType.IF_STMT, line=token.line, column=token.column)
                    if current_function:
                        current_function.add_child(if_node)
                    else:
                        self.root.add_child(if_node)
                elif token.value == 'while':
                    # While statement
                    while_node = WhileStmtNode(type=NodeType.WHILE_STMT, line=token.line, column=token.column)
                    if current_function:
                        current_function.add_child(while_node)
                    else:
                        self.root.add_child(while_node)
                elif token.value == 'for':
                    # For statement
                    for_node = ForStmtNode(type=NodeType.FOR_STMT, line=token.line, column=token.column)
                    if current_function:
                        current_function.add_child(for_node)
                    else:
                        self.root.add_child(for_node)
                elif token.value == 'return':
                    # Return statement
                    return_node = ReturnStmtNode(type=NodeType.RETURN_STMT, line=token.line, column=token.column)
                    if current_function:
                        current_function.add_child(return_node)
        
        return self.root
    
    def get_ast_statistics(self) -> dict:
        """Get statistics about the AST"""
        if not self.root:
            return {}
        
        stats = {
            'total_nodes': 0,
            'functions': 0,
            'classes': 0,
            'if_statements': 0,
            'while_loops': 0,
            'for_loops': 0,
            'max_depth': 0
        }
        
        def count_nodes(node: ASTNode, depth: int = 0):
            stats['total_nodes'] += 1
            stats['max_depth'] = max(stats['max_depth'], depth)
            
            if isinstance(node, FunctionDeclNode):
                stats['functions'] += 1
            elif isinstance(node, ClassDeclNode):
                stats['classes'] += 1
            elif isinstance(node, IfStmtNode):
                stats['if_statements'] += 1
            elif isinstance(node, WhileStmtNode):
                stats['while_loops'] += 1
            elif isinstance(node, ForStmtNode):
                stats['for_loops'] += 1
            
            for child in node.children:
                count_nodes(child, depth + 1)
        
        count_nodes(self.root)
        return stats


def build_ast_from_tokens(tokens) -> tuple:
    """
    Convenience function to build AST from tokens
    
    Args:
        tokens: List of Token objects
        
    Returns:
        Tuple of (AST root node, statistics dictionary)
    """
    builder = ASTBuilder()
    ast = builder.build_ast(tokens)
    stats = builder.get_ast_statistics()
    return ast, stats
