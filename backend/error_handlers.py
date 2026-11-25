"""
Error handling utilities for VulnX
"""

from functools import wraps
from flask import jsonify
import traceback
import sys


class VulnXError(Exception):
    """Base exception for VulnX errors"""
    pass


class TokenizationError(VulnXError):
    """Error during tokenization"""
    pass


class ParsingError(VulnXError):
    """Error during parsing/AST generation"""
    pass


class AnalysisError(VulnXError):
    """Error during vulnerability analysis"""
    pass


class OptimizationError(VulnXError):
    """Error during code optimization"""
    pass


class ReportGenerationError(VulnXError):
    """Error during report generation"""
    pass


def handle_errors(f):
    """Decorator for handling errors in API endpoints"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except TokenizationError as e:
            return jsonify({
                'error': 'Tokenization failed',
                'details': str(e)
            }), 400
        except ParsingError as e:
            return jsonify({
                'error': 'Parsing failed',
                'details': str(e)
            }), 400
        except AnalysisError as e:
            return jsonify({
                'error': 'Analysis failed',
                'details': str(e)
            }), 400
        except OptimizationError as e:
            return jsonify({
                'error': 'Optimization failed',
                'details': str(e)
            }), 400
        except ReportGenerationError as e:
            return jsonify({
                'error': 'Report generation failed',
                'details': str(e)
            }), 400
        except Exception as e:
            # Log the full traceback for debugging
            traceback.print_exc()
            return jsonify({
                'error': 'Internal server error',
                'details': str(e) if '--debug' in sys.argv else 'An unexpected error occurred'
            }), 500
    return wrapper


def validate_input(required_fields):
    """Decorator for validating input data"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request
            
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
            
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            
            if missing_fields:
                return jsonify({
                    'error': 'Missing required fields',
                    'fields': missing_fields
                }), 400
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def safe_execute(default=None, log_error=True):
    """Decorator for safe execution with default return value"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                if log_error:
                    print(f"Error in {f.__name__}: {str(e)}")
                return default
        return wrapper
    return decorator
