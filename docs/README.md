# VulnX - AI-Driven Code Intelligence Platform

An AI-driven code intelligence platform for vulnerability detection and secure code optimization. This project implements a complete compiler design pipeline with five integrated modules for analyzing source code, detecting security vulnerabilities, and providing optimization suggestions.

## Features

- **Module 1: Lexical Analysis** - Tokenizes source code and provides token statistics
- **Module 2: Syntax Analysis & AST Generation** - Builds Abstract Syntax Trees and provides code structure analysis
- **Module 3: Semantic Analysis & Vulnerability Detection** - Detects security vulnerabilities including SQL injection, XSS, hardcoded credentials, and more
- **Module 4: AI-Assisted Secure Code Optimization** - Provides optimization suggestions for security, performance, and code quality
- **Module 5: Security Report & Dashboard** - Generates comprehensive security reports and provides a dashboard view

## Project Structure

```
VulnX/
├── backend/
│   ├── app.py              # Flask API server
│   └── error_handlers.py   # Error handling utilities
├── frontend/
│   ├── index.html          # Main web interface
│   ├── styles.css          # Styling
│   └── script.js           # Frontend JavaScript
├── modules/
│   ├── lexical/
│   │   └── tokenizer.py    # Module 1: Lexical Analysis
│   ├── syntax/
│   │   └── ast.py          # Module 2: AST Generation
│   ├── semantic/
│   │   └── analyzer.py     # Module 3: Vulnerability Detection
│   ├── optimization/
│   │   └── optimizer.py    # Module 4: Code Optimization
│   └── reporting/
│       └── reporter.py     # Module 5: Report Generation
├── tests/
│   ├── test_lexical.py     # Tests for Module 1
│   ├── test_syntax.py      # Tests for Module 2
│   ├── test_semantic.py    # Tests for Module 3
│   ├── test_optimization.py # Tests for Module 4
│   └── run_tests.py        # Test runner
├── docs/
│   └── README.md           # This file
├── main.py                 # CLI interface
├── run.py                  # Web application starter
├── requirements.txt        # Python dependencies
└── .env.example            # Environment configuration template
```

## Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd "D:\Compiler Design\project"
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment (optional)**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

## Usage

### Web Application

1. **Start the web server**
   ```bash
   python run.py
   ```

2. **Open your browser**
   Navigate to `http://localhost:5000`

3. **Use the interface**
   - Paste your source code in the input area
   - Click "Analyze Code" to run the full analysis
   - View results for all five modules
   - Export reports in JSON, HTML, or Markdown format

### Command Line Interface

**Analyze a file:**
```bash
python main.py path/to/your/code.py
```

**Analyze code string:**
```bash
python main.py --code "def test(): return 42"
```

**Interactive mode:**
```bash
python main.py
# Then paste your code and press Ctrl+D
```

**Export report:**
```bash
python main.py --code "your code here" --output html
```

**Use AI suggestions:**
```bash
python main.py --code "your code here" --ai
```

## API Endpoints

### Main Analysis
- `POST /api/analyze` - Full code analysis through all modules

### Individual Modules
- `POST /api/tokenize` - Module 1: Tokenize code
- `POST /api/parse` - Module 2: Build AST
- `POST /api/analyze-vulnerabilities` - Module 3: Detect vulnerabilities
- `POST /api/optimize` - Module 4: Optimize code
- `POST /api/report` - Module 5: Generate report

### Dashboard & Health
- `GET /api/dashboard` - Get dashboard data
- `GET /api/health` - Health check

## Detected Vulnerabilities

The platform detects the following vulnerability types:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Hardcoded Credentials
- Insecure Random Number Generation
- Buffer Overflow Risk
- Integer Overflow Risk
- Unvalidated Input
- Insecure Deserialization
- Path Traversal
- Command Injection
- Weak Cryptography
- Information Leakage
- Unrestricted File Upload
- Insecure Direct Object Reference

## Optimization Categories

- **Security Fixes** - Address security vulnerabilities
- **Performance Improvements** - Optimize code performance
- **Code Quality** - Improve code maintainability
- **Best Practices** - Follow industry best practices
- **Dependency Updates** - Suggest dependency updates

## Testing

Run all tests:
```bash
python tests/run_tests.py
```

Run individual module tests:
```bash
python tests/test_lexical.py
python tests/test_syntax.py
python tests/test_semantic.py
python tests/test_optimization.py
```

## Security Score

The platform calculates a security score from 0 to 100 based on:
- Number of detected vulnerabilities
- Severity of vulnerabilities (Critical, High, Medium, Low)
- Type of vulnerabilities

Score interpretation:
- 80-100: Good security posture
- 50-79: Moderate security posture
- 0-49: Poor security posture

## Report Formats

Reports can be exported in three formats:

1. **JSON** - Machine-readable format for integration
2. **HTML** - Human-readable formatted report
3. **Markdown** - Documentation-friendly format

## Configuration

Environment variables (see `.env.example`):

- `FLASK_ENV` - Flask environment (development/production)
- `FLASK_DEBUG` - Enable debug mode
- `SECRET_KEY` - Flask secret key
- `OPENAI_API_KEY` - OpenAI API key for AI features (optional)
- `HOST` - Server host address
- `PORT` - Server port

## Technology Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript
- **Testing**: Python unittest
- **Security**: Pattern-based vulnerability detection

## Future Enhancements

- Integration with real AI models (OpenAI, etc.)
- Support for multiple programming languages
- Real-time code analysis
- Integration with CI/CD pipelines
- Database support for historical reports
- User authentication and multi-tenant support

## License

This is a compiler design project for educational purposes.

## Contributors

Compiler Design Project Team

## Support

For issues or questions, please refer to the project documentation or contact the development team.
