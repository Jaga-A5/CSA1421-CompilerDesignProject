"""
Flask Backend API for VulnX
Integrates all modules and provides REST API endpoints
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.lexical.tokenizer import tokenize_code
from modules.syntax.ast import build_ast_from_tokens
from modules.semantic.analyzer import analyze_vulnerabilities
from modules.optimization.optimizer import optimize_code
from modules.reporting.reporter import generate_security_report, ReportGenerator
from backend.error_handlers import handle_errors, validate_input

app = Flask(__name__)
CORS(app)

# Global report generator for dashboard
report_generator = ReportGenerator()


@app.route('/')
def index():
    """Serve the frontend"""
    return send_from_directory('../frontend', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('../frontend', path)


@app.route('/api/analyze', methods=['POST'])
@handle_errors
@validate_input(['code'])
def analyze_code():
    """
    Main analysis endpoint
    Performs complete code analysis through all modules
    """
    data = request.get_json()
    source_code = data['code']
    file_name = data.get('file_name', 'unknown')
    use_ai = data.get('use_ai', False)
    
    # Module 1: Lexical Analysis
    tokens, token_stats = tokenize_code(source_code)
    
    # Module 2: Syntax Analysis and AST Generation
    ast, ast_stats = build_ast_from_tokens(tokens)
    
    # Module 3: Semantic Analysis and Vulnerability Detection
    vulnerabilities, vulnerability_summary, security_score = analyze_vulnerabilities(
        source_code, tokens, ast
    )
    
    # Module 4: AI-Assisted Secure Code Optimization
    optimizations, optimization_summary, optimized_code = optimize_code(
        source_code, vulnerabilities, use_ai
    )
    
    # Module 5: Security Report Generation
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
    
    # Return complete analysis results
    return jsonify({
        'success': True,
        'analysis': {
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
    })


@app.route('/api/tokenize', methods=['POST'])
@handle_errors
@validate_input(['code'])
def tokenize_endpoint():
    """Module 1: Tokenize source code"""
    data = request.get_json()
    source_code = data['code']
    tokens, stats = tokenize_code(source_code)
    
    return jsonify({
        'success': True,
        'tokens': [t.__dict__ for t in tokens],
        'stats': stats
    })


@app.route('/api/parse', methods=['POST'])
@handle_errors
@validate_input(['code'])
def parse_endpoint():
    """Module 2: Parse tokens and build AST"""
    data = request.get_json()
    source_code = data['code']
    tokens, _ = tokenize_code(source_code)
    ast, stats = build_ast_from_tokens(tokens)
    
    return jsonify({
        'success': True,
        'ast': ast.to_dict(),
        'stats': stats
    })


@app.route('/api/analyze-vulnerabilities', methods=['POST'])
@handle_errors
@validate_input(['code'])
def analyze_vulnerabilities_endpoint():
    """Module 3: Analyze vulnerabilities"""
    data = request.get_json()
    source_code = data['code']
    vulnerabilities, summary, score = analyze_vulnerabilities(source_code)
    
    return jsonify({
        'success': True,
        'vulnerabilities': [v.to_dict() for v in vulnerabilities],
        'summary': summary,
        'security_score': score
    })


@app.route('/api/optimize', methods=['POST'])
@handle_errors
@validate_input(['code'])
def optimize_endpoint():
    """Module 4: Optimize code"""
    data = request.get_json()
    source_code = data['code']
    use_ai = data.get('use_ai', False)
    
    optimizations, summary, optimized_code = optimize_code(source_code, use_ai=use_ai)
    
    return jsonify({
        'success': True,
        'optimizations': [o.to_dict() for o in optimizations],
        'summary': summary,
        'optimized_code': optimized_code
    })


@app.route('/api/report', methods=['POST'])
@handle_errors
@validate_input(['code'])
def report_endpoint():
    """Module 5: Generate security report"""
    data = request.get_json()
    source_code = data['code']
    file_name = data.get('file_name', 'unknown')
    format_type = data.get('format', 'json')
    
    # Run full analysis
    tokens, token_stats = tokenize_code(source_code)
    ast, ast_stats = build_ast_from_tokens(tokens)
    vulnerabilities, vulnerability_summary, security_score = analyze_vulnerabilities(
        source_code, tokens, ast
    )
    optimizations, optimization_summary, _ = optimize_code(source_code, vulnerabilities)
    
    # Generate report
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
    
    if format_type == 'json':
        return jsonify({
            'success': True,
            'report': report.to_dict()
        })
    elif format_type == 'html':
        return jsonify({
            'success': True,
            'report_html': report_generator.export_report(report, 'html')
        })
    elif format_type == 'markdown':
        return jsonify({
            'success': True,
            'report_markdown': report_generator.export_report(report, 'markdown')
        })
    else:
        return jsonify({'error': 'Unsupported format'}), 400


@app.route('/api/dashboard', methods=['GET'])
@handle_errors
def dashboard_endpoint():
    """Get dashboard data"""
    dashboard_data = report_generator.generate_dashboard_data()
    return jsonify({
        'success': True,
        'dashboard': dashboard_data
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'modules': {
            'lexical': 'available',
            'syntax': 'available',
            'semantic': 'available',
            'optimization': 'available',
            'reporting': 'available'
        }
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
