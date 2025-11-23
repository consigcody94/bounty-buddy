"""
Report generation for IoTHackBot scan results
Supports HTML, JSON, and Markdown output formats
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict


class ReportGenerator:
    """Generate comprehensive reports from tool results"""

    def __init__(self, title: str = "IoTHackBot Security Assessment Report"):
        self.title = title
        self.timestamp = datetime.now().isoformat()
        self.results: List[Dict[str, Any]] = []

    def add_result(self, tool_name: str, result: 'ToolResult'):
        """Add a tool result to the report"""
        self.results.append({
            'tool': tool_name,
            'timestamp': datetime.now().isoformat(),
            'success': result.success,
            'data': result.data,
            'errors': result.errors,
            'metadata': result.metadata,
            'execution_time': result.execution_time
        })

    def generate_json(self, filepath: Optional[str] = None) -> str:
        """Generate JSON report"""
        report = {
            'title': self.title,
            'generated_at': self.timestamp,
            'total_scans': len(self.results),
            'successful_scans': sum(1 for r in self.results if r['success']),
            'failed_scans': sum(1 for r in self.results if not r['success']),
            'results': self.results
        }

        json_output = json.dumps(report, indent=2, default=str)

        if filepath:
            Path(filepath).write_text(json_output)

        return json_output

    def generate_html(self, filepath: Optional[str] = None) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }}
        .summary {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .summary-item {{
            display: inline-block;
            margin-right: 30px;
            font-size: 1.1em;
        }}
        .summary-item strong {{
            color: #2c3e50;
        }}
        .result {{
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background: #fafafa;
        }}
        .result-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        .tool-name {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .status {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .status.success {{
            background: #2ecc71;
            color: white;
        }}
        .status.failure {{
            background: #e74c3c;
            color: white;
        }}
        .metadata {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .metadata-item {{
            margin: 5px 0;
        }}
        .errors {{
            background: #fde8e8;
            color: #c0392b;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 4px solid #e74c3c;
        }}
        .data {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            overflow-x: auto;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .execution-time {{
            color: #7f8c8d;
            font-style: italic;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #34495e;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{self.title}</h1>
        <div class="summary">
            <div class="summary-item"><strong>Generated:</strong> {self.timestamp}</div>
            <div class="summary-item"><strong>Total Scans:</strong> {len(self.results)}</div>
            <div class="summary-item"><strong>Successful:</strong> {sum(1 for r in self.results if r['success'])}</div>
            <div class="summary-item"><strong>Failed:</strong> {sum(1 for r in self.results if not r['success'])}</div>
        </div>

        <h2>Scan Results</h2>
"""

        for idx, result in enumerate(self.results, 1):
            status_class = "success" if result['success'] else "failure"
            status_text = "SUCCESS" if result['success'] else "FAILURE"

            html += f"""
        <div class="result">
            <div class="result-header">
                <span class="tool-name">{idx}. {result['tool']}</span>
                <span class="status {status_class}">{status_text}</span>
            </div>
            <div class="timestamp">Executed: {result['timestamp']}</div>
            <div class="execution-time">Execution time: {result['execution_time']:.2f}s</div>
"""

            if result.get('errors'):
                html += """
            <div class="errors">
                <strong>Errors:</strong>
                <ul>
"""
                for error in result['errors']:
                    html += f"                    <li>{error}</li>\n"
                html += """
                </ul>
            </div>
"""

            if result.get('metadata'):
                html += """
            <div class="metadata">
                <strong>Metadata:</strong>
"""
                for key, value in result['metadata'].items():
                    html += f"""                <div class="metadata-item"><strong>{key}:</strong> {value}</div>\n"""
                html += """
            </div>
"""

            if result.get('data'):
                html += f"""
            <div class="data">
                <strong>Data:</strong>
                <pre>{json.dumps(result['data'], indent=2)}</pre>
            </div>
"""

            html += """
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        if filepath:
            Path(filepath).write_text(html)

        return html

    def generate_markdown(self, filepath: Optional[str] = None) -> str:
        """Generate Markdown report"""
        md = f"""# {self.title}

**Generated:** {self.timestamp}
**Total Scans:** {len(self.results)}
**Successful:** {sum(1 for r in self.results if r['success'])}
**Failed:** {sum(1 for r in self.results if not r['success'])}

---

## Scan Results

"""

        for idx, result in enumerate(self.results, 1):
            status = "✅ SUCCESS" if result['success'] else "❌ FAILURE"

            md += f"""### {idx}. {result['tool']} - {status}

**Executed:** {result['timestamp']}
**Execution Time:** {result['execution_time']:.2f}s

"""

            if result.get('errors'):
                md += "**Errors:**\n\n"
                for error in result['errors']:
                    md += f"- {error}\n"
                md += "\n"

            if result.get('metadata'):
                md += "**Metadata:**\n\n"
                for key, value in result['metadata'].items():
                    md += f"- **{key}:** {value}\n"
                md += "\n"

            if result.get('data'):
                md += "**Data:**\n\n```json\n"
                md += json.dumps(result['data'], indent=2)
                md += "\n```\n\n"

            md += "---\n\n"

        if filepath:
            Path(filepath).write_text(md)

        return md


def create_scan_report(
    results: List[Dict[str, Any]],
    output_format: str = 'html',
    output_file: Optional[str] = None,
    title: str = "IoTHackBot Security Assessment Report"
) -> str:
    """
    Create a scan report from multiple tool results.

    Args:
        results: List of result dictionaries (tool_name, ToolResult pairs)
        output_format: 'html', 'json', or 'markdown'
        output_file: Optional output file path
        title: Report title

    Returns:
        Generated report as string
    """
    generator = ReportGenerator(title=title)

    for result_data in results:
        generator.add_result(
            tool_name=result_data.get('tool', 'unknown'),
            result=result_data.get('result')
        )

    if output_format == 'html':
        return generator.generate_html(output_file)
    elif output_format == 'json':
        return generator.generate_json(output_file)
    elif output_format == 'markdown':
        return generator.generate_markdown(output_file)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
