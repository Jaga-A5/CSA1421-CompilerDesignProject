"""
Test runner for VulnX
Runs all unit tests for all modules
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_module_tests(module_name, test_file):
    """Run tests for a specific module"""
    print(f"\n{'=' * 60}")
    print(f"Running tests for {module_name}")
    print('=' * 60)
    
    try:
        with open(test_file, 'r') as f:
            code = f.read()
        
        exec(code, {'__name__': '__main__'})
        return True
    except Exception as e:
        print(f"Error running {module_name} tests: {e}")
        return False


def main():
    """Run all tests"""
    print("VulnX Test Suite")
    print("=" * 60)
    
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    tests = [
        ('Module 1: Lexical Analysis', os.path.join(test_dir, 'test_lexical.py')),
        ('Module 2: Syntax Analysis', os.path.join(test_dir, 'test_syntax.py')),
        ('Module 3: Semantic Analysis', os.path.join(test_dir, 'test_semantic.py')),
        ('Module 4: Code Optimization', os.path.join(test_dir, 'test_optimization.py')),
    ]
    
    results = []
    for module_name, test_file in tests:
        if os.path.exists(test_file):
            success = run_module_tests(module_name, test_file)
            results.append((module_name, success))
        else:
            print(f"Test file not found: {test_file}")
            results.append((module_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for module_name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"{module_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} test suites passed")
    
    if passed == total:
        print("\nAll tests passed!")
        return 0
    else:
        print(f"\n{total - passed} test suite(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
