"""
Module 5: Security Report and Dashboard
Implements security report generation and dashboard data
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class SecurityReport:
    """Comprehensive security report"""
    timestamp: str
    source_code_hash: str
    file_name: str
    security_score: float
    vulnerability_summary: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    optimization_summary: Dict[str, Any]
    optimizations: List[Dict[str, Any]]
    code_metrics: Dict[str, Any]
    recommendations: List[str]
    
    def to_dict(self) -> dict:
        """Convert report to dictionary"""
        return {
            'timestamp': self.timestamp,
            'source_code_hash': self.source_code_hash,
            'file_name': self.file_name,
            'security_score': self.security_score,
            'vulnerability_summary': self.vulnerability_summary,
            'vulnerabilities': self.vulnerabilities,
            'optimization_summary': self.optimization_summary,
            'optimizations': self.optimizations,
            'code_metrics': self.code_metrics,
            'recommendations': self.recommendations
        }
    
    def to_json(self) -> str:
        """Convert report to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class ReportGenerator:
    """Generates security reports and dashboard data"""
    
    def __init__(self):
        self.reports: List[SecurityReport] = []
    
    def generate_report(
        self,
        source_code: str,
        file_name: str = "unknown",
        vulnerabilities: List = None,
        vulnerability_summary: Dict = None,
        security_score: float = 100.0,
        optimizations: List = None,
        optimization_summary: Dict = None,
        token_stats: Dict = None,
        ast_stats: Dict = None
    ) -> SecurityReport:
        """
        Generate a comprehensive security report
        
        Args:
            source_code: The analyzed source code
            file_name: Name of the analyzed file
            vulnerabilities: List of detected vulnerabilities
            vulnerability_summary: Summary of vulnerabilities
            security_score: Overall security score (0-100)
            optimizations: List of optimization suggestions
            optimization_summary: Summary of optimizations
            token_stats: Token statistics from lexical analysis
            ast_stats: AST statistics from syntax analysis
            
        Returns:
            SecurityReport object
        """
        # Generate code hash
        source_hash = self._generate_hash(source_code)
        
        # Calculate code metrics
        code_metrics = self._calculate_code_metrics(source_code, token_stats, ast_stats)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            vulnerabilities,
            security_score,
            optimization_summary
        )
        
        # Convert objects to dictionaries
        vuln_dicts = [v.to_dict() if hasattr(v, 'to_dict') else v for v in (vulnerabilities or [])]
        opt_dicts = [o.to_dict() if hasattr(o, 'to_dict') else o for o in (optimizations or [])]
        
        report = SecurityReport(
            timestamp=datetime.now().isoformat(),
            source_code_hash=source_hash,
            file_name=file_name,
            security_score=security_score,
            vulnerability_summary=vulnerability_summary or {},
            vulnerabilities=vuln_dicts,
            optimization_summary=optimization_summary or {},
            optimizations=opt_dicts,
            code_metrics=code_metrics,
            recommendations=recommendations
        )
        
        self.reports.append(report)
        return report
    
    def _generate_hash(self, source_code: str) -> str:
        """Generate a simple hash of the source code"""
        import hashlib
        return hashlib.md5(source_code.encode()).hexdigest()[:16]
    
    def _calculate_code_metrics(
        self,
        source_code: str,
        token_stats: Dict = None,
        ast_stats: Dict = None
    ) -> Dict[str, Any]:
        """Calculate code metrics"""
        lines = source_code.split('\n')
        
        metrics = {
            'total_lines': len(lines),
            'code_lines': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
            'blank_lines': len([l for l in lines if not l.strip()]),
            'avg_line_length': sum(len(l) for l in lines) / len(lines) if lines else 0,
            'max_line_length': max(len(l) for l in lines) if lines else 0,
        }
        
        # Add token statistics if available
        if token_stats:
            metrics['token_stats'] = token_stats
        
        # Add AST statistics if available
        if ast_stats:
            metrics['ast_stats'] = ast_stats
        
        return metrics
    
    def _generate_recommendations(
        self,
        vulnerabilities: List,
        security_score: float,
        optimization_summary: Dict = None
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Security score based recommendations
        if security_score < 50:
            recommendations.append(
                "CRITICAL: Your code has a very low security score. "
                "Immediate action is required to address vulnerabilities."
            )
        elif security_score < 70:
            recommendations.append(
                "WARNING: Your code has a moderate security score. "
                "Address high and critical vulnerabilities soon."
            )
        elif security_score < 90:
            recommendations.append(
                "INFO: Your code has a good security score but room for improvement. "
                "Address remaining vulnerabilities to improve security."
            )
        
        # Vulnerability based recommendations
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if getattr(v, 'severity', '').value == 'Critical')
            high_count = sum(1 for v in vulnerabilities if getattr(v, 'severity', '').value == 'High')
            
            if critical_count > 0:
                recommendations.append(
                    f"Address {critical_count} critical vulnerability(ies) immediately."
                )
            if high_count > 0:
                recommendations.append(
                    f"Address {high_count} high-severity vulnerability(ies) as soon as possible."
                )
        
        # Optimization based recommendations
        if optimization_summary:
            total_opts = optimization_summary.get('total', 0)
            if total_opts > 0:
                recommendations.append(
                    f"Consider applying {total_opts} optimization suggestion(s) to improve code quality."
                )
        
        return recommendations
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """
        Generate data for the security dashboard
        
        Returns:
            Dictionary containing dashboard data
        """
        if not self.reports:
            return {
                'total_reports': 0,
                'avg_security_score': 0,
                'total_vulnerabilities': 0,
                'total_optimizations': 0,
                'severity_distribution': {},
                'vulnerability_type_distribution': {},
                'recent_reports': []
            }
        
        # Calculate aggregate statistics
        total_reports = len(self.reports)
        avg_security_score = sum(r.security_score for r in self.reports) / total_reports
        
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in self.reports)
        total_optimizations = sum(len(r.optimizations) for r in self.reports)
        
        # Severity distribution
        severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for report in self.reports:
            for vuln in report.vulnerabilities:
                severity = vuln.get('severity', '').lower()
                if severity in severity_dist:
                    severity_dist[severity] += 1
        
        # Vulnerability type distribution
        type_dist = {}
        for report in self.reports:
            for vuln in report.vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                type_dist[vuln_type] = type_dist.get(vuln_type, 0) + 1
        
        # Recent reports (last 5)
        recent_reports = [r.to_dict() for r in self.reports[-5:]]
        
        return {
            'total_reports': total_reports,
            'avg_security_score': round(avg_security_score, 1),
            'total_vulnerabilities': total_vulnerabilities,
            'total_optimizations': total_optimizations,
            'severity_distribution': severity_dist,
            'vulnerability_type_distribution': type_dist,
            'recent_reports': recent_reports
        }
    
    def export_report(self, report: SecurityReport, format: str = 'json') -> str:
        """
        Export a report in the specified format
        
        Args:
            report: The SecurityReport to export
            format: Export format ('json', 'html', 'markdown')
            
        Returns:
            Exported report as string
        """
        if format == 'json':
            return report.to_json()
        elif format == 'html':
            return self._generate_html_report(report)
        elif format == 'markdown':
            return self._generate_markdown_report(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, report: SecurityReport) -> str:
        """Generate an HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {report.file_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .score {{ font-size: 24px; font-weight: bold; }}
        .score-high {{ color: green; }}
        .score-medium {{ color: orange; }}
        .score-low {{ color: red; }}
        .section {{ margin: 20px 0; }}
        .vulnerability {{ padding: 10px; margin: 10px 0; border-left: 4px solid #ccc; }}
        .critical {{ border-left-color: red; }}
        .high {{ border-left-color: orange; }}
        .medium {{ border-left-color: yellow; }}
        .low {{ border-left-color: green; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Report</h1>
        <p>File: {report.file_name}</p>
        <p>Generated: {report.timestamp}</p>
        <p>Security Score: <span class="score {self._get_score_class(report.security_score)}">{report.security_score}/100</span></p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p>Total Vulnerabilities: {report.vulnerability_summary.get('total', 0)}</p>
        <p>Total Optimizations: {report.optimization_summary.get('total', 0)}</p>
    </div>
    
    <div class="section">
        <h2>Vulnerabilities</h2>
        {self._generate_vulnerabilities_html(report.vulnerabilities)}
    </div>
    
    <div class="section">
        <h2>Optimizations</h2>
        {self._generate_optimizations_html(report.optimizations)}
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            {"".join(f"<li>{rec}</li>" for rec in report.recommendations)}
        </ul>
    </div>
</body>
</html>
"""
        return html
    
    def _get_score_class(self, score: float) -> str:
        """Get CSS class for security score"""
        if score >= 80:
            return 'score-high'
        elif score >= 50:
            return 'score-medium'
        else:
            return 'score-low'
    
    def _generate_vulnerabilities_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for vulnerabilities section"""
        if not vulnerabilities:
            return "<p>No vulnerabilities detected.</p>"
        
        html = ""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').lower()
            html += f"""
            <div class="vulnerability {severity}">
                <strong>{vuln.get('type', 'Unknown')}</strong> - {vuln.get('severity', 'Unknown')}<br>
                <em>Line {vuln.get('line', 0)}: {vuln.get('description', '')}</em><br>
                <code>{vuln.get('code_snippet', '')}</code><br>
                <strong>Recommendation:</strong> {vuln.get('recommendation', '')}
            </div>
            """
        return html
    
    def _generate_optimizations_html(self, optimizations: List[Dict]) -> str:
        """Generate HTML for optimizations section"""
        if not optimizations:
            return "<p>No optimization suggestions.</p>"
        
        html = "<table><tr><th>Type</th><th>Priority</th><th>Description</th><th>Suggestion</th></tr>"
        for opt in optimizations:
            html += f"""
            <tr>
                <td>{opt.get('type', '')}</td>
                <td>{opt.get('priority', '')}</td>
                <td>{opt.get('description', '')}</td>
                <td>{opt.get('suggested_code', '')}</td>
            </tr>
            """
        html += "</table>"
        return html
    
    def _generate_markdown_report(self, report: SecurityReport) -> str:
        """Generate a Markdown report"""
        md = f"""# Security Report

**File:** {report.file_name}  
**Generated:** {report.timestamp}  
**Security Score:** {report.security_score}/100

## Summary

- Total Vulnerabilities: {report.vulnerability_summary.get('total', 0)}
- Total Optimizations: {report.optimization_summary.get('total', 0)}

## Vulnerabilities

"""
        for vuln in report.vulnerabilities:
            md += f"""
### {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}

- **Line:** {vuln.get('line', 0)}
- **Description:** {vuln.get('description', '')}
- **Code:** `{vuln.get('code_snippet', '')}`
- **Recommendation:** {vuln.get('recommendation', '')}

"""
        
        md += "## Optimizations\n\n"
        for opt in report.optimizations:
            md += f"""
### {opt.get('type', '')} - {opt.get('priority', '')}

- **Description:** {opt.get('description', '')}
- **Suggestion:** {opt.get('suggested_code', '')}

"""
        
        md += "## Recommendations\n\n"
        for rec in report.recommendations:
            md += f"- {rec}\n"
        
        return md


def generate_security_report(
    source_code: str,
    file_name: str = "unknown",
    vulnerabilities: List = None,
    vulnerability_summary: Dict = None,
    security_score: float = 100.0,
    optimizations: List = None,
    optimization_summary: Dict = None,
    token_stats: Dict = None,
    ast_stats: Dict = None
) -> SecurityReport:
    """
    Convenience function to generate a security report
    
    Returns:
        SecurityReport object
    """
    generator = ReportGenerator()
    return generator.generate_report(
        source_code,
        file_name,
        vulnerabilities,
        vulnerability_summary,
        security_score,
        optimizations,
        optimization_summary,
        token_stats,
        ast_stats
    )
