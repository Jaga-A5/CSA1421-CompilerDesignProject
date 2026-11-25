"""
VulnX - Main Integration Script
AI-Driven Code Intelligence Platform for Vulnerability Detection and Secure Code Optimization
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.lexical.tokenizer import tokenize_code
from modules.syntax.ast import build_ast_from_tokens
from modules.semantic.analyzer import analyze_vulnerabilities
from modules.optimization.optimizer import optimize_code
from modules.reporting.reporter import generate_security_report, ReportGenerator


class VulnXAnalyzer:
    """Main analyzer class that integrates all modules"""
    
    def __init__(self):
        self.report_generator = ReportGenerator()
    
    def analyze(self, source_code: str, file_name: str = "unknown", use_ai: bool = False) -> dict:
        """
        Perform complete code analysis through all modules
        
        Args:
            source_code: The source code to analyze
            file_name: Name of the file being analyzed
            use_ai: Whether to use AI-powered suggestions
            
        Returns:
            Dictionary containing complete analysis results
        """
        try:
            # Module 1: Lexical Analysis
            print("Module 1: Performing Lexical Analysis...")
            tokens, token_stats = tokenize_code(source_code)
            print(f"  - Found {token_stats['total_tokens']} tokens")
            
            # Module 2: Syntax Analysis and AST Generation
            print("Module 2: Building AST...")
            ast, ast_stats = build_ast_from_tokens(tokens)
            print(f"  - Built AST with {ast_stats['total_nodes']} nodes")
            
            # Module 3: Semantic Analysis and Vulnerability Detection
            print("Module 3: Analyzing vulnerabilities...")
            vulnerabilities, vulnerability_summary, security_score = analyze_vulnerabilities(
                source_code, tokens, ast
            )
            print(f"  - Found {len(vulnerabilities)} vulnerabilities")
            print(f"  - Security Score: {security_score}/100")
            
            # Module 4: AI-Assisted Secure Code Optimization
            print("Module 4: Generating optimization suggestions...")
            optimizations, optimization_summary, optimized_code = optimize_code(
                source_code, vulnerabilities, use_ai
            )
            print(f"  - Generated {len(optimizations)} optimization suggestions")
            
            # Module 5: Security Report Generation
            print("Module 5: Generating security report...")
            report = generate_security_report(
                source_code=source_code,
                file_name=file_name,
                vulnerabilities=vulnerabilities,
                vulnerability_summary=vulnerability_summary,
                security_score=security_score,
                optimizations=optimizations,
                optimization_summary=optimization_summary,
                token_stats=token_stats,
                ast_stats=ast_stats
            )
            print("  - Report generated successfully")
            
            # Return complete analysis results
            return {
                'token_stats': token_stats,
                'ast_stats': ast_stats,
                'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                'vulnerability_summary': vulnerability_summary,
                'security_score': security_score,
                'optimizations': [o.to_dict() for o in optimizations],
                'optimization_summary': optimization_summary,
                'optimized_code': optimized_code,
                'report': report.to_dict()
            }
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            raise
    
    def analyze_file(self, file_path: str, use_ai: bool = False) -> dict:
        """
        Analyze a file
        
        Args:
            file_path: Path to the file to analyze
            use_ai: Whether to use AI-powered suggestions
            
        Returns:
            Dictionary containing complete analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            file_name = os.path.basename(file_path)
            return self.analyze(source_code, file_name, use_ai)
            
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            raise
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            raise
    
    def get_dashboard_data(self) -> dict:
        """Get dashboard data"""
        return self.report_generator.generate_dashboard_data()


def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='VulnX - AI-Driven Code Intelligence Platform'
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='Source code file to analyze'
    )
    parser.add_argument(
        '--code',
        help='Source code string to analyze'
    )
    parser.add_argument(
        '--output',
        choices=['json', 'html', 'markdown'],
        default='json',
        help='Output format for the report'
    )
    parser.add_argument(
        '--ai',
        action='store_true',
        help='Use AI-powered suggestions'
    )
    
    args = parser.parse_args()
    
    analyzer = VulnXAnalyzer()
    
    if args.code:
        # Analyze code string
        results = analyzer.analyze(args.code, use_ai=args.ai)
    elif args.file:
        # Analyze file
        results = analyzer.analyze_file(args.file, use_ai=args.ai)
    else:
        # Interactive mode
        print("VulnX - AI-Driven Code Intelligence Platform")
        print("=" * 50)
        print("Enter your source code (Ctrl+D to finish):")
        
        try:
            source_code = sys.stdin.read()
            if source_code.strip():
                results = analyzer.analyze(source_code, use_ai=args.ai)
            else:
                print("No code provided. Exiting.")
                return
        except KeyboardInterrupt:
            print("\nAnalysis cancelled.")
            return
    
    # Display results
    print("\n" + "=" * 50)
    print("ANALYSIS RESULTS")
    print("=" * 50)
    print(f"Security Score: {results['security_score']}/100")
    print(f"Total Vulnerabilities: {results['vulnerability_summary']['total']}")
    print(f"Total Optimizations: {results['optimization_summary']['total']}")
    
    print("\nVulnerabilities by Severity:")
    for severity, count in results['vulnerability_summary']['by_severity'].items():
        print(f"  {severity.capitalize()}: {count}")
    
    print("\nTop Vulnerabilities:")
    for vuln in results['vulnerabilities'][:5]:
        print(f"  - {vuln['type']} ({vuln['severity']}) at line {vuln['line']}")
    
    print("\nRecommendations:")
    for rec in results['report']['recommendations'][:5]:
        print(f"  - {rec}")


if __name__ == '__main__':
    main()
