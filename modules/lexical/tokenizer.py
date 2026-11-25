"""
Module 1: Lexical Analysis
Implements a tokenizer for source code analysis
"""

import re
from enum import Enum
from typing import List, Tuple, Optional
from dataclasses import dataclass


class TokenType(Enum):
    """Enumeration of token types"""
    KEYWORD = "KEYWORD"
    IDENTIFIER = "IDENTIFIER"
    OPERATOR = "OPERATOR"
    LITERAL = "LITERAL"
    DELIMITER = "DELIMITER"
    COMMENT = "COMMENT"
    WHITESPACE = "WHITESPACE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Token:
    """Represents a token with its type, value, and position"""
    type: TokenType
    value: str
    line: int
    column: int
    
    def __repr__(self):
        return f"Token({self.type.value}, '{self.value}', line={self.line}, col={self.column})"


class Tokenizer:
    """Lexical analyzer for source code"""
    
    # Common keywords
    KEYWORDS = {
        'if', 'else', 'elif', 'for', 'while', 'def', 'class', 'return',
        'import', 'from', 'as', 'try', 'except', 'finally', 'with',
        'and', 'or', 'not', 'in', 'is', 'lambda', 'yield', 'global',
        'nonlocal', 'pass', 'break', 'continue', 'raise', 'assert',
        'async', 'await', 'True', 'False', 'None', 'int', 'str', 'float',
        'bool', 'list', 'dict', 'set', 'tuple', 'var', 'let', 'const',
        'function', 'switch', 'case', 'default', 'new', 'this', 'typeof',
        'instanceof', 'void', 'null', 'undefined', 'struct', 'enum',
        'interface', 'implements', 'extends', 'public', 'private',
        'protected', 'static', 'final', 'abstract', 'virtual', 'override'
    }
    
    # Operators
    OPERATORS = {
        '+', '-', '*', '/', '%', '**', '//', '==', '!=', '<', '>', '<=', '>=',
        '=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>',
        '&&', '||', '!', '&', '|', '^', '~', '->', '=>', '++', '--', '?:'
    }
    
    # Delimiters
    DELIMITERS = {
        '(', ')', '[', ']', '{', '}', ',', ':', ';', '.', '@', '#'
    }
    
    def __init__(self):
        self.tokens: List[Token] = []
        self.current_line = 1
        self.current_column = 1
    
    def tokenize(self, source_code: str) -> List[Token]:
        """
        Tokenize the source code
        
        Args:
            source_code: The source code string to tokenize
            
        Returns:
            List of Token objects
        """
        self.tokens = []
        self.current_line = 1
        self.current_column = 1
        
        i = 0
        n = len(source_code)
        
        while i < n:
            char = source_code[i]
            
            # Skip whitespace
            if char.isspace():
                if char == '\n':
                    self.current_line += 1
                    self.current_column = 1
                else:
                    self.current_column += 1
                i += 1
                continue
            
            # Handle comments
            if char == '#' and (i == 0 or source_code[i-1] in ['\n', ' ']):
                comment = self._extract_comment(source_code, i)
                if comment:
                    self.tokens.append(comment)
                    i += len(comment.value)
                    continue
            
            # Handle string literals
            if char in ['"', "'", '`']:
                string_token = self._extract_string(source_code, i)
                if string_token:
                    self.tokens.append(string_token)
                    i += len(string_token.value)
                    continue
            
            # Handle numbers
            if char.isdigit() or (char == '.' and i + 1 < n and source_code[i+1].isdigit()):
                number_token = self._extract_number(source_code, i)
                if number_token:
                    self.tokens.append(number_token)
                    i += len(number_token.value)
                    continue
            
            # Handle multi-character operators
            if i + 1 < n:
                two_char = source_code[i:i+2]
                if two_char in self.OPERATORS:
                    self.tokens.append(Token(
                        TokenType.OPERATOR,
                        two_char,
                        self.current_line,
                        self.current_column
                    ))
                    self.current_column += 2
                    i += 2
                    continue
            
            # Handle single-character tokens
            if char in self.OPERATORS:
                self.tokens.append(Token(
                    TokenType.OPERATOR,
                    char,
                    self.current_line,
                    self.current_column
                ))
                self.current_column += 1
                i += 1
                continue
            
            if char in self.DELIMITERS:
                self.tokens.append(Token(
                    TokenType.DELIMITER,
                    char,
                    self.current_line,
                    self.current_column
                ))
                self.current_column += 1
                i += 1
                continue
            
            # Handle identifiers and keywords
            if char.isalpha() or char == '_':
                identifier = self._extract_identifier(source_code, i)
                if identifier:
                    self.tokens.append(identifier)
                    i += len(identifier.value)
                    continue
            
            # Unknown token
            self.tokens.append(Token(
                TokenType.UNKNOWN,
                char,
                self.current_line,
                self.current_column
            ))
            self.current_column += 1
            i += 1
        
        return self.tokens
    
    def _extract_comment(self, source: str, start: int) -> Optional[Token]:
        """Extract a comment from source code"""
        end = start
        while end < len(source) and source[end] != '\n':
            end += 1
        comment = source[start:end]
        return Token(TokenType.COMMENT, comment, self.current_line, self.current_column)
    
    def _extract_string(self, source: str, start: int) -> Optional[Token]:
        """Extract a string literal from source code"""
        quote = source[start]
        end = start + 1
        while end < len(source) and source[end] != quote:
            if source[end] == '\\' and end + 1 < len(source):
                end += 2
            else:
                end += 1
        if end < len(source):
            end += 1
        string_literal = source[start:end]
        return Token(TokenType.LITERAL, string_literal, self.current_line, self.current_column)
    
    def _extract_number(self, source: str, start: int) -> Optional[Token]:
        """Extract a number from source code"""
        end = start
        is_float = False
        
        while end < len(source):
            if source[end].isdigit():
                end += 1
            elif source[end] == '.' and not is_float:
                is_float = True
                end += 1
            else:
                break
        
        number = source[start:end]
        return Token(TokenType.LITERAL, number, self.current_line, self.current_column)
    
    def _extract_identifier(self, source: str, start: int) -> Optional[Token]:
        """Extract an identifier or keyword from source code"""
        end = start
        while end < len(source) and (source[end].isalnum() or source[end] == '_'):
            end += 1
        
        identifier = source[start:end]
        token_type = TokenType.KEYWORD if identifier in self.KEYWORDS else TokenType.IDENTIFIER
        
        return Token(token_type, identifier, self.current_line, self.current_column)
    
    def get_token_statistics(self) -> dict:
        """Get statistics about the tokenized code"""
        stats = {
            'total_tokens': len(self.tokens),
            'keywords': 0,
            'identifiers': 0,
            'operators': 0,
            'literals': 0,
            'delimiters': 0,
            'comments': 0,
            'whitespace': 0,
            'unknown': 0
        }
        
        for token in self.tokens:
            token_type = token.type.value.lower()
            if token_type in stats:
                stats[token_type] += 1
        
        return stats


def tokenize_code(source_code: str) -> Tuple[List[Token], dict]:
    """
    Convenience function to tokenize code and return tokens with statistics
    
    Args:
        source_code: The source code to tokenize
        
    Returns:
        Tuple of (tokens list, statistics dictionary)
    """
    tokenizer = Tokenizer()
    tokens = tokenizer.tokenize(source_code)
    stats = tokenizer.get_token_statistics()
    return tokens, stats
