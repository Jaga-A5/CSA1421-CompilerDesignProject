# VulnX API Documentation

## Base URL

```
http://localhost:5000/api
```

## Authentication

Currently, no authentication is required. This may be added in future versions.

## Endpoints

### 1. Full Code Analysis

Analyze source code through all five modules.

**Endpoint:** `POST /api/analyze`

**Request Body:**
```json
{
  "code": "string (required) - Source code to analyze",
  "file_name": "string (optional) - Name of the file",
  "use_ai": "boolean (optional) - Use AI-powered suggestions"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "token_stats": {
      "total_tokens": 42,
      "keywords": 5,
      "identifiers": 10,
      "operators": 8,
      "literals": 3,
      "delimiters": 12,
      "comments": 4
    },
    "ast_stats": {
      "total_nodes": 15,
      "functions": 2,
      "classes": 1,
      "if_statements": 3,
      "while_loops": 0,
      "for_loops": 1,
      "max_depth": 4
    },
    "vulnerabilities": [
      {
        "type": "SQL Injection",
        "severity": "High",
        "line": 5,
        "column": 10,
        "description": "String concatenation in SQL query",
        "code_snippet": "query = \"SELECT * FROM users WHERE name = '\" + input + \"'\"",
        "recommendation": "Use parameterized queries",
        "cwe_id": "CWE-89"
      }
    ],
    "vulnerability_summary": {
      "total": 3,
      "by_severity": {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0
      },
      "by_type": {
        "SQL Injection": 1,
        "Hardcoded Credentials": 1,
        "Weak Cryptography": 1
      }
    },
    "security_score": 55.0,
    "optimizations": [
      {
        "type": "Security Fix",
        "priority": "Critical",
        "line": 5,
        "column": 10,
        "original_code": "query = \"SELECT * FROM users WHERE name = '\" + input + \"'\"",
        "suggested_code": "Use parameterized query: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "description": "SQL injection vulnerability detected",
        "rationale": "Parameterized queries prevent SQL injection",
        "impact": "Eliminates SQL injection attack vector"
      }
    ],
    "optimization_summary": {
      "total": 5,
      "by_priority": {
        "critical": 2,
        "high": 2,
        "medium": 1,
        "low": 0
      },
      "by_type": {
        "Security Fix": 3,
        "Performance": 1,
        "Code Quality": 1
      }
    },
    "optimized_code": "string - Optimized version of the code",
    "report": {
      "timestamp": "2024-01-01T12:00:00",
      "source_code_hash": "abc123",
      "file_name": "example.py",
      "security_score": 55.0,
      "vulnerability_summary": {},
      "vulnerabilities": [],
      "optimization_summary": {},
      "optimizations": [],
      "code_metrics": {},
      "recommendations": []
    }
  }
}
```

### 2. Tokenize Code (Module 1)

Tokenize source code.

**Endpoint:** `POST /api/tokenize`

**Request Body:**
```json
{
  "code": "string (required) - Source code to tokenize"
}
```

**Response:**
```json
{
  "success": true,
  "tokens": [
    {
      "type": "KEYWORD",
      "value": "def",
      "line": 1,
      "column": 1
    }
  ],
  "stats": {
    "total_tokens": 42,
    "keywords": 5,
    "identifiers": 10,
    "operators": 8,
    "literals": 3,
    "delimiters": 12,
    "comments": 4
  }
}
```

### 3. Parse Code (Module 2)

Build AST from source code.

**Endpoint:** `POST /api/parse`

**Request Body:**
```json
{
  "code": "string (required) - Source code to parse"
}
```

**Response:**
```json
{
  "success": true,
  "ast": {
    "type": "PROGRAM",
    "line": 1,
    "column": 1,
    "children": [
      {
        "type": "FUNCTION_DECL",
        "line": 1,
        "column": 1,
        "name": "test",
        "parameters": [],
        "body": null
      }
    ]
  },
  "stats": {
    "total_nodes": 15,
    "functions": 2,
    "classes": 1,
    "if_statements": 3,
    "while_loops": 0,
    "for_loops": 1,
    "max_depth": 4
  }
}
```

### 4. Analyze Vulnerabilities (Module 3)

Detect security vulnerabilities.

**Endpoint:** `POST /api/analyze-vulnerabilities`

**Request Body:**
```json
{
  "code": "string (required) - Source code to analyze"
}
```

**Response:**
```json
{
  "success": true,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "line": 5,
      "column": 10,
      "description": "String concatenation in SQL query",
      "code_snippet": "query = \"SELECT * FROM users WHERE name = '\" + input + \"'\"",
      "recommendation": "Use parameterized queries",
      "cwe_id": "CWE-89"
    }
  ],
  "summary": {
    "total": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "by_type": {
      "SQL Injection": 1,
      "Hardcoded Credentials": 1,
      "Weak Cryptography": 1
    }
  },
  "security_score": 55.0
}
```

### 5. Optimize Code (Module 4)

Generate optimization suggestions.

**Endpoint:** `POST /api/optimize`

**Request Body:**
```json
{
  "code": "string (required) - Source code to optimize",
  "use_ai": "boolean (optional) - Use AI-powered suggestions"
}
```

**Response:**
```json
{
  "success": true,
  "optimizations": [
    {
      "type": "Security Fix",
      "priority": "Critical",
      "line": 5,
      "column": 10,
      "original_code": "query = \"SELECT * FROM users WHERE name = '\" + input + \"'\"",
      "suggested_code": "Use parameterized query",
      "description": "SQL injection vulnerability detected",
      "rationale": "Parameterized queries prevent SQL injection",
      "impact": "Eliminates SQL injection attack vector"
    }
  ],
  "summary": {
    "total": 5,
    "by_priority": {
      "critical": 2,
      "high": 2,
      "medium": 1,
      "low": 0
    },
    "by_type": {
      "Security Fix": 3,
      "Performance": 1,
      "Code Quality": 1
    }
  },
  "optimized_code": "string - Optimized version of the code"
}
```

### 6. Generate Report (Module 5)

Generate security report in various formats.

**Endpoint:** `POST /api/report`

**Request Body:**
```json
{
  "code": "string (required) - Source code to analyze",
  "file_name": "string (optional) - Name of the file",
  "format": "string (optional) - Output format: json, html, markdown"
}
```

**Response (JSON format):**
```json
{
  "success": true,
  "report": {
    "timestamp": "2024-01-01T12:00:00",
    "source_code_hash": "abc123",
    "file_name": "example.py",
    "security_score": 55.0,
    "vulnerability_summary": {},
    "vulnerabilities": [],
    "optimization_summary": {},
    "optimizations": [],
    "code_metrics": {},
    "recommendations": []
  }
}
```

**Response (HTML format):**
```json
{
  "success": true,
  "report_html": "<!DOCTYPE html>...</html>"
}
```

**Response (Markdown format):**
```json
{
  "success": true,
  "report_markdown": "# Security Report\n..."
}
```

### 7. Get Dashboard Data

Get aggregated dashboard data.

**Endpoint:** `GET /api/dashboard`

**Response:**
```json
{
  "success": true,
  "dashboard": {
    "total_reports": 10,
    "avg_security_score": 72.5,
    "total_vulnerabilities": 45,
    "total_optimizations": 30,
    "severity_distribution": {
      "critical": 5,
      "high": 15,
      "medium": 20,
      "low": 5,
      "info": 0
    },
    "vulnerability_type_distribution": {
      "SQL Injection": 10,
      "Hardcoded Credentials": 8,
      "XSS": 5,
      "Weak Cryptography": 12,
      "Command Injection": 10
    },
    "recent_reports": [
      {
        "timestamp": "2024-01-01T12:00:00",
        "file_name": "example.py",
        "security_score": 55.0
      }
    ]
  }
}
```

### 8. Health Check

Check API health status.

**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "status": "healthy",
  "modules": {
    "lexical": "available",
    "syntax": "available",
    "semantic": "available",
    "optimization": "available",
    "reporting": "available"
  }
}
```

## Error Responses

All endpoints may return error responses:

**400 Bad Request:**
```json
{
  "error": "No code provided"
}
```

**500 Internal Server Error:**
```json
{
  "error": "Internal server error",
  "details": "Error message"
}
```

**404 Not Found:**
```json
{
  "error": "Endpoint not found"
}
```

## Vulnerability Types

The following vulnerability types are detected:

- SQL Injection (CWE-89)
- Cross-Site Scripting (XSS) (CWE-79)
- Cross-Site Request Forgery (CSRF) (CWE-352)
- Hardcoded Credentials (CWE-798)
- Insecure Random Number Generation (CWE-338)
- Buffer Overflow Risk (CWE-120)
- Integer Overflow Risk (CWE-190)
- Unvalidated Input (CWE-20)
- Insecure Deserialization (CWE-502)
- Path Traversal (CWE-22)
- Command Injection (CWE-78)
- Weak Cryptography (CWE-327)
- Information Leakage (CWE-200)
- Unrestricted File Upload (CWE-434)
- Insecure Direct Object Reference (CWE-639)

## Security Score Calculation

The security score is calculated as follows:

- Base score: 100
- Deductions per vulnerability:
  - Critical: -25 points
  - High: -15 points
  - Medium: -8 points
  - Low: -3 points
  - Info: -1 point

Final score is clamped between 0 and 100.

## Rate Limiting

Currently, no rate limiting is implemented. This may be added in future versions.

## CORS

The API supports CORS (Cross-Origin Resource Sharing) for frontend integration.
