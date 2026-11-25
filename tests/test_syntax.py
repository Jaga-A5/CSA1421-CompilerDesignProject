"""
Unit tests for Module 2: Syntax Analysis and AST Generation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.syntax.ast import ASTBuilder, NodeType, build_ast_from_tokens
from modules.lexical.tokenizer import tokenize_code


def test_ast_builder():
    """Test AST building"""
    builder = ASTBuilder()
    code = "def test(): pass"
    tokens, _ = tokenize_code(code)
    ast = builder.build_ast(tokens)
    
    assert ast is not None
    assert ast.type == NodeType.PROGRAM
    print("test_ast_builder: PASSED")


def test_ast_function_detection():
    """Test function detection in AST"""
    code = "def hello(): return 'world'"
    tokens, _ = tokenize_code(code)
    ast, stats = build_ast_from_tokens(tokens)
    
    assert stats['functions'] >= 1
    print("test_ast_function_detection: PASSED")


def test_ast_class_detection():
    """Test class detection in AST"""
    code = "class User: pass"
    tokens, _ = tokenize_code(code)
    ast, stats = build_ast_from_tokens(tokens)
    
    assert stats['classes'] >= 1
    print("test_ast_class_detection: PASSED")


def test_ast_statistics():
    """Test AST statistics"""
    code = """
def test1(): pass
def test2(): pass
class MyClass: pass
"""
    tokens, _ = tokenize_code(code)
    ast, stats = build_ast_from_tokens(tokens)
    
    assert 'total_nodes' in stats
    assert 'functions' in stats
    assert 'classes' in stats
    print("test_ast_statistics: PASSED")


if __name__ == '__main__':
    test_ast_builder()
    test_ast_function_detection()
    test_ast_class_detection()
    test_ast_statistics()
    print("\nAll syntax analysis tests passed!")
