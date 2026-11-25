"""
Unit tests for Module 4: Code Optimization
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.optimization.optimizer import CodeOptimizer, OptimizationType, Priority, optimize_code


def test_security_optimization():
    """Test security-related optimizations"""
    optimizer = CodeOptimizer()
    code = 'password = "admin123"'
    optimizations = optimizer.optimize(code)
    
    security_opts = [o for o in optimizations if o.type == OptimizationType.SECURITY_FIX]
    assert len(security_opts) > 0
    print("test_security_optimization: PASSED")


def test_performance_optimization():
    """Test performance-related optimizations"""
    optimizer = CodeOptimizer()
    code = 'for i in range(len(items)): pass'
    optimizations = optimizer.optimize(code)
    
    perf_opts = [o for o in optimizations if o.type == OptimizationType.PERFORMANCE]
    assert len(perf_opts) > 0
    print("test_performance_optimization: PASSED")


def test_code_quality_optimization():
    """Test code quality optimizations"""
    optimizer = CodeOptimizer()
    code = 'except: pass'
    optimizations = optimizer.optimize(code)
    
    quality_opts = [o for o in optimizations if o.type == OptimizationType.CODE_QUALITY]
    assert len(quality_opts) > 0
    print("test_code_quality_optimization: PASSED")


def test_optimization_summary():
    """Test optimization summary generation"""
    code = 'password = "admin123"\nfor i in range(len(items)): pass'
    optimizations, summary, _ = optimize_code(code)
    
    assert 'by_priority' in summary
    assert 'by_type' in summary
    assert summary['total'] > 0
    print("test_optimization_summary: PASSED")


def test_optimized_code_generation():
    """Test optimized code generation"""
    code = 'hash = md5(data)'
    optimizations, summary, optimized = optimize_code(code)
    
    assert optimized is not None
    assert len(optimized) > 0
    print("test_optimized_code_generation: PASSED")


if __name__ == '__main__':
    test_security_optimization()
    test_performance_optimization()
    test_code_quality_optimization()
    test_optimization_summary()
    test_optimized_code_generation()
    print("\nAll optimization tests passed!")
