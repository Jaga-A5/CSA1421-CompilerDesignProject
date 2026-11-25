"""
Module 4: AI-Assisted Secure Code Optimization
Implements code optimization suggestions and security improvements
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class OptimizationType(Enum):
    """Enumeration of optimization types"""
    SECURITY_FIX = "Security Fix"
    PERFORMANCE = "Performance Improvement"
    CODE_QUALITY = "Code Quality"
    BEST_PRACTICE = "Best Practice"
    DEPENDENCY = "Dependency Update"


class Priority(Enum):
    """Optimization priority levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Optimization:
    """Represents a code optimization suggestion"""
    type: OptimizationType
    priority: Priority
    line: int
    column: int
    original_code: str
    suggested_code: str
    description: str
    rationale: str
    impact: str
    
    def to_dict(self) -> dict:
        """Convert optimization to dictionary"""
        return {
            'type': self.type.value,
            'priority': self.priority.value,
            'line': self.line,
            'column': self.column,
            'original_code': self.original_code,
            'suggested_code': self.suggested_code,
            'description': self.description,
            'rationale': self.rationale,
            'impact': self.impact
        }


class CodeOptimizer:
    """Provides code optimization suggestions"""
    
    # Security optimization patterns
    SECURITY_PATTERNS = [
        {
            'pattern': r'execute\s*\(\s*["\'].*?\+.*?["\']\s*\)',
            'suggestion': 'Use parameterized queries',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.CRITICAL,
            'description': 'SQL injection vulnerability detected',
            'rationale': 'String concatenation in SQL queries allows SQL injection attacks',
            'impact': 'Prevents SQL injection attacks'
        },
        {
            'pattern': r'password\s*=\s*["\'][^"\']{4,}["\']',
            'suggestion': 'Use environment variables or config files',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.CRITICAL,
            'description': 'Hardcoded password detected',
            'rationale': 'Hardcoded credentials can be extracted from source code',
            'impact': 'Prevents credential leakage'
        },
        {
            'pattern': r'eval\s*\(',
            'suggestion': 'Use safer alternatives (JSON.parse, Function constructor with care)',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.CRITICAL,
            'description': 'Use of eval() function',
            'rationale': 'eval() can execute arbitrary code and is a security risk',
            'impact': 'Prevents code injection attacks'
        },
        {
            'pattern': r'md5\s*\(',
            'suggestion': 'Use SHA-256 or stronger hash algorithms',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.HIGH,
            'description': 'Weak cryptographic hash (MD5)',
            'rationale': 'MD5 is vulnerable to collision attacks',
            'impact': 'Improves cryptographic security'
        },
        {
            'pattern': r'sha1\s*\(',
            'suggestion': 'Use SHA-256 or stronger hash algorithms',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.HIGH,
            'description': 'Weak cryptographic hash (SHA1)',
            'rationale': 'SHA1 is vulnerable to collision attacks',
            'impact': 'Improves cryptographic security'
        },
        {
            'pattern': r'random\.random\s*\(',
            'suggestion': 'Use secrets module (Python) or crypto.randomBytes (Node.js)',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.HIGH,
            'description': 'Insecure random number generator',
            'rationale': 'Standard random functions are not cryptographically secure',
            'impact': 'Improves randomness security'
        },
        {
            'pattern': r'system\s*\(',
            'suggestion': 'Use subprocess with proper sanitization or safer APIs',
            'type': OptimizationType.SECURITY_FIX,
            'priority': Priority.CRITICAL,
            'description': 'Direct system command execution',
            'rationale': 'Direct system calls can lead to command injection',
            'impact': 'Prevents command injection attacks'
        },
    ]
    
    # Performance optimization patterns
    PERFORMANCE_PATTERNS = [
        {
            'pattern': r'for\s+\w+\s+in\s+range\(len\([^)]+\)\)',
            'suggestion': 'Use enumerate() or iterate directly',
            'type': OptimizationType.PERFORMANCE,
            'priority': Priority.MEDIUM,
            'description': 'Inefficient loop with range(len())',
            'rationale': 'Using enumerate() is more Pythonic and slightly faster',
            'impact': 'Improves code readability and performance'
        },
        {
            'pattern': r'\[\s*\w+\s+for\s+\w+\s+in\s+\w+\s+if\s+\w+\s+in\s+\w+\]',
            'suggestion': 'Consider using set for membership tests',
            'type': OptimizationType.PERFORMANCE,
            'priority': Priority.MEDIUM,
            'description': 'List comprehension with membership test',
            'rationale': 'Set membership is O(1) vs list membership O(n)',
            'impact': 'Improves performance for large collections'
        },
        {
            'pattern': r'"\s*\+\s*"[^"]*"\s*\+\s*"[^"]*"',
            'suggestion': 'Use f-strings or format()',
            'type': OptimizationType.PERFORMANCE,
            'priority': Priority.LOW,
            'description': 'String concatenation with + operator',
            'rationale': 'f-strings are more readable and faster',
            'impact': 'Improves performance and readability'
        },
    ]
    
    # Code quality patterns
    QUALITY_PATTERNS = [
        {
            'pattern': r'except\s*:',
            'suggestion': 'Specify exception type',
            'type': OptimizationType.CODE_QUALITY,
            'priority': Priority.MEDIUM,
            'description': 'Bare except clause',
            'rationale': 'Bare except catches all exceptions including SystemExit',
            'impact': 'Improves error handling precision'
        },
        {
            'pattern': r'global\s+\w+',
            'suggestion': 'Consider using class or function parameters',
            'type': OptimizationType.CODE_QUALITY,
            'priority': Priority.MEDIUM,
            'description': 'Use of global variable',
            'rationale': 'Global variables make code harder to test and maintain',
            'impact': 'Improves code maintainability'
        },
        {
            'pattern': r'def\s+\w+\([^)]*\):\s*$',
            'suggestion': 'Add docstring to function',
            'type': OptimizationType.CODE_QUALITY,
            'priority': Priority.LOW,
            'description': 'Function without docstring',
            'rationale': 'Docstrings improve code documentation',
            'impact': 'Improves code documentation'
        },
    ]
    
    def __init__(self):
        self.optimizations: List[Optimization] = []
    
    def optimize(self, source_code: str, vulnerabilities=None) -> List[Optimization]:
        """
        Analyze source code and provide optimization suggestions
        
        Args:
            source_code: The source code to optimize
            vulnerabilities: Optional list of detected vulnerabilities
            
        Returns:
            List of optimization suggestions
        """
        self.optimizations = []
        lines = source_code.split('\n')
        
        # Check all pattern categories
        all_patterns = (
            self.SECURITY_PATTERNS +
            self.PERFORMANCE_PATTERNS +
            self.QUALITY_PATTERNS
        )
        
        for line_num, line in enumerate(lines, start=1):
            for pattern_info in all_patterns:
                self._check_line_for_pattern(line, line_num, pattern_info, source_code)
        
        # Generate security fixes based on vulnerabilities
        if vulnerabilities:
            self._generate_security_fixes(vulnerabilities, source_code)
        
        return self.optimizations
    
    def _check_line_for_pattern(self, line: str, line_num: int, pattern_info: dict, source_code: str):
        """Check a single line for optimization patterns"""
        pattern = pattern_info['pattern']
        matches = re.finditer(pattern, line, re.IGNORECASE)
        
        for match in matches:
            col_start = match.start() + 1
            original_code = line.strip()
            
            optimization = Optimization(
                type=pattern_info['type'],
                priority=pattern_info['priority'],
                line=line_num,
                column=col_start,
                original_code=original_code,
                suggested_code=pattern_info['suggestion'],
                description=pattern_info['description'],
                rationale=pattern_info['rationale'],
                impact=pattern_info['impact']
            )
            self.optimizations.append(optimization)
    
    def _generate_security_fixes(self, vulnerabilities: List, source_code: str):
        """Generate specific security fixes based on detected vulnerabilities"""
        lines = source_code.split('\n')
        
        for vuln in vulnerabilities:
            line_num = vuln.line
            if 1 <= line_num <= len(lines):
                line = lines[line_num - 1]
                
                # Generate specific fixes based on vulnerability type
                if 'SQL Injection' in str(vuln.type):
                    optimization = Optimization(
                        type=OptimizationType.SECURITY_FIX,
                        priority=Priority.CRITICAL,
                        line=line_num,
                        column=vuln.column,
                        original_code=line.strip(),
                        suggested_code='Use parameterized query: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                        description='Fix SQL injection vulnerability',
                        rationale='Parameterized queries prevent SQL injection by separating SQL logic from data',
                        impact='Eliminates SQL injection attack vector'
                    )
                    self.optimizations.append(optimization)
                
                elif 'Hardcoded Credentials' in str(vuln.type):
                    optimization = Optimization(
                        type=OptimizationType.SECURITY_FIX,
                        priority=Priority.CRITICAL,
                        line=line_num,
                        column=vuln.column,
                        original_code=line.strip(),
                        suggested_code='password = os.getenv("DB_PASSWORD")',
                        description='Remove hardcoded credentials',
                        rationale='Environment variables keep credentials out of source code',
                        impact='Prevents credential exposure in version control'
                    )
                    self.optimizations.append(optimization)
    
    def apply_ai_suggestions(self, source_code: str, api_key: Optional[str] = None) -> List[Optimization]:
        """
        Apply AI-powered code suggestions (placeholder for OpenAI integration)
        
        Args:
            source_code: The source code to analyze
            api_key: Optional OpenAI API key
            
        Returns:
            List of AI-generated optimization suggestions
        """
        # This is a placeholder for AI integration
        # In production, this would call OpenAI API or similar
        
        ai_suggestions = []
        
        # Example AI-generated suggestions (would be from actual AI in production)
        if 'def ' in source_code and 'return ' not in source_code:
            suggestion = Optimization(
                type=OptimizationType.CODE_QUALITY,
                priority=Priority.MEDIUM,
                line=1,
                column=1,
                original_code='Function without return',
                suggested_code='Add appropriate return statement',
                description='AI suggestion: Function appears to be missing a return statement',
                rationale='Functions should explicitly return values when expected',
                impact='Improves code correctness'
            )
            ai_suggestions.append(suggestion)
        
        return ai_suggestions
    
    def get_optimization_summary(self) -> dict:
        """Get a summary of optimization suggestions"""
        summary = {
            'total': len(self.optimizations),
            'by_priority': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'by_type': {}
        }
        
        for opt in self.optimizations:
            priority_key = opt.priority.value.lower()
            summary['by_priority'][priority_key] += 1
            
            type_key = opt.type.value
            if type_key not in summary['by_type']:
                summary['by_type'][type_key] = 0
            summary['by_type'][type_key] += 1
        
        return summary
    
    def generate_optimized_code(self, source_code: str) -> str:
        """
        Generate an optimized version of the code
        
        Args:
            source_code: Original source code
            
        Returns:
            Optimized source code (simplified version)
        """
        lines = source_code.split('\n')
        optimized_lines = []
        
        for line in lines:
            optimized_line = line
            
            # Apply simple optimizations
            # Replace md5 with sha256 (example)
            if 'md5(' in optimized_line:
                optimized_line = optimized_line.replace('md5(', 'sha256(')
            
            # Replace random.random with secrets (example)
            if 'random.random()' in optimized_line:
                optimized_line = optimized_line.replace('random.random()', 'secrets.randbelow(n)')
            
            optimized_lines.append(optimized_line)
        
        return '\n'.join(optimized_lines)


def optimize_code(source_code: str, vulnerabilities=None, use_ai: bool = False) -> tuple:
    """
    Convenience function to optimize code
    
    Args:
        source_code: The source code to optimize
        vulnerabilities: Optional list of vulnerabilities
        use_ai: Whether to use AI-powered suggestions
        
    Returns:
        Tuple of (optimizations list, summary dict, optimized code)
    """
    optimizer = CodeOptimizer()
    optimizations = optimizer.optimize(source_code, vulnerabilities)
    
    if use_ai:
        ai_suggestions = optimizer.apply_ai_suggestions(source_code)
        optimizations.extend(ai_suggestions)
    
    summary = optimizer.get_optimization_summary()
    optimized_code = optimizer.generate_optimized_code(source_code)
    
    return optimizations, summary, optimized_code
