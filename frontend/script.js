// VulnX Frontend JavaScript

// API Base URL - use relative path in production or fallback to localhost if opened directly as a file
const API_BASE = window.location.protocol === 'file:' 
    ? 'http://localhost:5000/api' 
    : '/api';

// DOM Elements
const codeInput = document.getElementById('code-input');
const fileNameInput = document.getElementById('file-name');
const useAiCheckbox = document.getElementById('use-ai');
const analyzeBtn = document.getElementById('analyze-btn');
const clearBtn = document.getElementById('clear-btn');
const loadSampleBtn = document.getElementById('load-sample-btn');
const resultsSection = document.getElementById('results-section');
const loadingOverlay = document.getElementById('loading-overlay');

// Navigation
const navBtns = document.querySelectorAll('.nav-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Current analysis data
let currentAnalysis = null;

// Sample code for testing
const sampleCode = `# Sample Python code with vulnerabilities
import hashlib
import random

def process_user_input(user_data):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_data + "'"
    cursor.execute(query)
    
    # Hardcoded password
    password = "admin123"
    
    # Weak hash
    hash_value = md5(user_data.encode()).hexdigest()
    
    # Insecure random
    session_id = random.random()
    
    # Command injection
    os.system("ls " + user_data)
    
    return hash_value

def evaluate_expression(expr):
    # Use of eval - dangerous
    result = eval(expr)
    return result

class UserHandler:
    def __init__(self):
        self.api_key = "sk-1234567890abcdef"
        
    def authenticate(self, username, password):
        # Information leakage
        print(f"Authenticating: {username}, {password}")
        return True
`;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    loadDashboard();
});

// Setup event listeners
function setupEventListeners() {
    // Navigation
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    // Analysis buttons
    analyzeBtn.addEventListener('click', analyzeCode);
    clearBtn.addEventListener('click', clearInput);
    loadSampleBtn.addEventListener('click', loadSample);
    
    // Export buttons
    document.getElementById('export-json').addEventListener('click', () => exportReport('json'));
    document.getElementById('export-html').addEventListener('click', () => exportReport('html'));
    document.getElementById('export-md').addEventListener('click', () => exportReport('markdown'));
}

// Switch tabs
function switchTab(tabName) {
    navBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    tabContents.forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}-tab`);
    });
    
    if (tabName === 'dashboard') {
        loadDashboard();
    }
}

// Analyze code
async function analyzeCode() {
    const code = codeInput.value.trim();
    
    if (!code) {
        alert('Please enter some code to analyze');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                file_name: fileNameInput.value || 'unknown',
                use_ai: useAiCheckbox.checked
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentAnalysis = data.analysis;
            displayResults(data.analysis);
        } else {
            alert('Analysis failed: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error analyzing code. Make sure the backend server is running.');
    } finally {
        showLoading(false);
    }
}

// Display analysis results
function displayResults(analysis) {
    resultsSection.classList.remove('hidden');
    
    // Security score
    const scoreElement = document.getElementById('security-score');
    scoreElement.textContent = analysis.security_score;
    scoreElement.className = 'score-value';
    if (analysis.security_score >= 80) {
        scoreElement.classList.add('high');
    } else if (analysis.security_score >= 50) {
        scoreElement.classList.add('medium');
    } else {
        scoreElement.classList.add('low');
    }
    
    // Token stats
    document.getElementById('total-tokens').textContent = analysis.token_stats.total_tokens || 0;
    document.getElementById('keyword-count').textContent = analysis.token_stats.keywords || 0;
    document.getElementById('identifier-count').textContent = analysis.token_stats.identifiers || 0;
    document.getElementById('operator-count').textContent = analysis.token_stats.operators || 0;
    
    // AST stats
    document.getElementById('total-nodes').textContent = analysis.ast_stats.total_nodes || 0;
    document.getElementById('function-count').textContent = analysis.ast_stats.functions || 0;
    document.getElementById('class-count').textContent = analysis.ast_stats.classes || 0;
    document.getElementById('max-depth').textContent = analysis.ast_stats.max_depth || 0;
    
    // Vulnerability summary
    const vulnSummary = analysis.vulnerability_summary;
    document.getElementById('critical-count').textContent = vulnSummary.by_severity.critical || 0;
    document.getElementById('high-count').textContent = vulnSummary.by_severity.high || 0;
    document.getElementById('medium-count').textContent = vulnSummary.by_severity.medium || 0;
    document.getElementById('low-count').textContent = vulnSummary.by_severity.low || 0;
    
    // Vulnerabilities list
    displayVulnerabilities(analysis.vulnerabilities);
    
    // Optimizations list
    displayOptimizations(analysis.optimizations);
    
    // Recommendations
    displayRecommendations(analysis.report.recommendations);
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Display vulnerabilities
function displayVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilities-list');
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #10b981;">No vulnerabilities detected!</p>';
        return;
    }
    
    container.innerHTML = vulnerabilities.map(vuln => `
        <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
            <div class="vuln-header">
                <span class="vuln-type">${vuln.type}</span>
                <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </div>
            <div class="vuln-details">
                <strong>Line ${vuln.line}:</strong> ${vuln.description}
            </div>
            <div class="vuln-code">${escapeHtml(vuln.code_snippet)}</div>
            <div class="vuln-recommendation">
                <strong>Recommendation:</strong> ${vuln.recommendation}
            </div>
        </div>
    `).join('');
}

// Display optimizations
function displayOptimizations(optimizations) {
    const container = document.getElementById('optimizations-list');
    
    if (!optimizations || optimizations.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #666;">No optimization suggestions.</p>';
        return;
    }
    
    container.innerHTML = optimizations.map(opt => `
        <div class="optimization-item">
            <div class="opt-header">
                <span class="opt-type">${opt.type}</span>
                <span class="opt-priority">${opt.priority}</span>
            </div>
            <div class="opt-description">${opt.description}</div>
            <div class="opt-suggestion">${escapeHtml(opt.suggested_code)}</div>
        </div>
    `).join('');
}

// Display recommendations
function displayRecommendations(recommendations) {
    const container = document.getElementById('recommendations-list');
    
    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #666;">No specific recommendations.</p>';
        return;
    }
    
    container.innerHTML = recommendations.map(rec => `
        <div class="recommendation-item">
            ${escapeHtml(rec)}
        </div>
    `).join('');
}

// Load dashboard
async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/dashboard`);
        const data = await response.json();
        
        if (data.success) {
            displayDashboard(data.dashboard);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Display dashboard
function displayDashboard(dashboard) {
    document.getElementById('dash-total-reports').textContent = dashboard.total_reports;
    document.getElementById('dash-avg-score').textContent = dashboard.avg_security_score || '--';
    document.getElementById('dash-total-vulns').textContent = dashboard.total_vulnerabilities;
    document.getElementById('dash-total-opts').textContent = dashboard.total_optimizations;
    
    // Severity distribution chart (simple text representation)
    const severityChart = document.getElementById('severity-chart');
    const severityDist = dashboard.severity_distribution;
    severityChart.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 8px; width: 100%;">
            ${Object.entries(severityDist).map(([severity, count]) => `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="width: 80px; font-size: 0.9rem;">${severity.charAt(0).toUpperCase() + severity.slice(1)}:</span>
                    <div style="flex: 1; background: #e0e0e0; border-radius: 4px; height: 24px;">
                        <div style="width: ${count > 0 ? Math.min(100, count * 10) : 0}%; background: ${getSeverityColor(severity)}; height: 100%; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8rem;">${count}</div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    
    // Type distribution chart
    const typeChart = document.getElementById('type-chart');
    const typeDist = dashboard.vulnerability_type_distribution;
    const typeEntries = Object.entries(typeDist).slice(0, 5);
    typeChart.innerHTML = typeEntries.length > 0 ? `
        <div style="display: flex; flex-direction: column; gap: 8px; width: 100%;">
            ${typeEntries.map(([type, count]) => `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="width: 120px; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${type}:</span>
                    <div style="flex: 1; background: #e0e0e0; border-radius: 4px; height: 24px;">
                        <div style="width: ${count > 0 ? Math.min(100, count * 15) : 0}%; background: #667eea; height: 100%; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8rem;">${count}</div>
                    </div>
                </div>
            `).join('')}
        </div>
    ` : '<p style="text-align: center; color: #999;">No data available</p>';
    
    // Recent reports
    const recentReportsList = document.getElementById('recent-reports-list');
    if (dashboard.recent_reports && dashboard.recent_reports.length > 0) {
        recentReportsList.innerHTML = dashboard.recent_reports.map(report => `
            <div class="report-item">
                <div class="report-info">
                    <h4>${escapeHtml(report.file_name)}</h4>
                    <p>${new Date(report.timestamp).toLocaleString()}</p>
                </div>
                <div class="report-score">${report.security_score}</div>
            </div>
        `).join('');
    } else {
        recentReportsList.innerHTML = '<p style="text-align: center; color: #999;">No reports yet</p>';
    }
}

// Get severity color
function getSeverityColor(severity) {
    const colors = {
        critical: '#ef4444',
        high: '#f59e0b',
        medium: '#eab308',
        low: '#10b981',
        info: '#6b7280'
    };
    return colors[severity] || '#6b7280';
}

// Export report
async function exportReport(format) {
    if (!currentAnalysis) {
        alert('No analysis data to export');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: codeInput.value,
                file_name: fileNameInput.value || 'unknown',
                format: format
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            let content, filename, mimeType;
            
            if (format === 'json') {
                content = JSON.stringify(data.report, null, 2);
                filename = 'security_report.json';
                mimeType = 'application/json';
            } else if (format === 'html') {
                content = data.report_html;
                filename = 'security_report.html';
                mimeType = 'text/html';
            } else if (format === 'markdown') {
                content = data.report_markdown;
                filename = 'security_report.md';
                mimeType = 'text/markdown';
            }
            
            downloadFile(content, filename, mimeType);
        } else {
            alert('Export failed: ' + data.error);
        }
    } catch (error) {
        console.error('Error exporting report:', error);
        alert('Error exporting report');
    }
}

// Download file
function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Clear input
function clearInput() {
    codeInput.value = '';
    fileNameInput.value = '';
    resultsSection.classList.add('hidden');
    currentAnalysis = null;
}

// Load sample code
function loadSample() {
    codeInput.value = sampleCode;
    fileNameInput.value = 'sample.py';
}

// Show/hide loading
function showLoading(show) {
    loadingOverlay.classList.toggle('hidden', !show);
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
