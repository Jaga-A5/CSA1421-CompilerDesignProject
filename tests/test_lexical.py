"""
Unit tests for Module 1: Lexical Analysis
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.lexical.tokenizer import Tokenizer, TokenType, tokenize_code


def test_tokenizer_basic():
    """Test basic tokenization"""
    tokenizer = Tokenizer()
    code = "def hello(): return 'world'"
    tokens = tokenizer.tokenize(code)
    
    assert len(tokens) > 0
    assert any(t.type == TokenType.KEYWORD and t.value == 'def' for t in tokens)
    assert any(t.type == TokenType.IDENTIFIER and t.value == 'hello' for t in tokens)
    print("test_tokenizer_basic: PASSED")


def test_tokenizer_operators():
    """Test operator tokenization"""
    tokenizer = Tokenizer()
    code = "a + b * c / d"
    tokens = tokenizer.tokenize(code)
    
    operators = [t for t in tokens if t.type == TokenType.OPERATOR]
    assert len(operators) == 3
    print("test_tokenizer_operators: PASSED")


def test_tokenizer_literals():
    """Test literal tokenization"""
    tokenizer = Tokenizer()
    code = 'x = 42; y = "hello"'
    tokens = tokenizer.tokenize(code)
    
    literals = [t for t in tokens if t.type == TokenType.LITERAL]
    assert len(literals) >= 2
    print("test_tokenizer_literals: PASSED")


def test_tokenizer_statistics():
    """Test token statistics"""
    code = "def test(): return 42"
    tokens, stats = tokenize_code(code)
    
    assert stats['total_tokens'] > 0
    assert 'keywords' in stats
    assert 'identifiers' in stats
    print("test_tokenizer_statistics: PASSED")


def test_tokenizer_comments():
    """Test comment handling"""
    tokenizer = Tokenizer()
    code = "# This is a comment\ndef test(): pass"
    tokens = tokenizer.tokenize(code)
    
    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) > 0
    print("test_tokenizer_comments: PASSED")


if __name__ == '__main__':
    test_tokenizer_basic()
    test_tokenizer_operators()
    test_tokenizer_literals()
    test_tokenizer_statistics()
    test_tokenizer_comments()
    print("\nAll lexical analysis tests passed!")
