from fpdf import FPDF
from datetime import datetime
from .security_config import SecurityAuditConfig

class SecurityReport(FPDF):
    def __init__(self):
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297
        self.config = SecurityAuditConfig()
        
    def header(self):
        self.set_font('Arial', 'B', 24)
        self.set_fill_color(40, 40, 40)
        self.set_text_color(255, 255, 255)
        self.cell(0, 30, 'Smart Contract Security Audit Report', 0, 1, 'C', fill=True)
        
        self.set_font('Arial', '', 10)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 16)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(40, 40, 40)
        self.cell(0, 15, title, 0, 1, 'L', fill=True)
        self.ln(10)

    def create_executive_summary(self, results):
        total_checks = len([r for r in results if ': ' in r])
        failed_checks = len([r for r in results if 'FAILED' in r])
        passed_checks = len([r for r in results if 'PASSED' in r])
        
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 6, 'This report presents the results of an automated security audit of the smart contract. The analysis covers common vulnerability patterns and best practices in smart contract development.')
        self.ln(5)
        
        # Summary statistics
        self.set_fill_color(245, 245, 245)
        self.set_font('Arial', 'B', 12)
        self.cell(60, 10, 'Key Statistics', 0, 1, 'L')
        
        stats = [
            ('Total Checks Performed:', total_checks),
            ('Vulnerabilities Found:', failed_checks),
            ('Checks Passed:', passed_checks),
            ('Overall Health Score:', f"{(passed_checks/total_checks*100):.1f}%")
        ]
        
        for label, value in stats:
            self.set_font('Arial', '', 11)
            self.cell(100, 8, label, 0, 0, 'L')
            self.set_font('Arial', 'B', 11)
            self.cell(0, 8, str(value), 0, 1, 'L')
        
        self.ln(10)

    def add_vulnerability_details(self, results):
        descriptions = self.config.get_vulnerability_descriptions()
        recommendations = self.config.get_vulnerability_recommendations()
        severity_levels = self.config.get_severity_levels()
        
        severity_colors = {
            'CRITICAL': (255, 0, 0),
            'HIGH': (255, 87, 87),
            'MEDIUM': (255, 193, 69),
            'LOW': (255, 221, 87)
        }
        
        for line in results:
            if ': ' in line:
                check_name, result = line.split(': ', 1)
                description = descriptions.get(check_name, "No description available.")
                severity = severity_levels.get(check_name, "LOW")
                
                # Vulnerability header
                self.set_fill_color(*severity_colors[severity])
                self.set_font('Arial', 'B', 12)
                self.cell(0, 2, '', 0, 1, 'L')  # Spacing
                self.cell(0, 8, f'{check_name}', 0, 1, 'L', fill=True)
                
                # Status and severity
                self.set_font('Arial', '', 10)
                status_color = (220, 53, 69) if 'FAILED' in result else (40, 167, 69)
                self.set_text_color(*status_color)
                self.cell(60, 6, result, 0, 0, 'L')
                self.set_text_color(0, 0, 0)
                self.cell(0, 6, f'Severity: {severity}', 0, 1, 'R')
                
                # Description
                self.set_font('Arial', '', 10)
                self.multi_cell(0, 5, f'Description: {description}')
                
                # Recommendations if vulnerability is found
                if 'FAILED' in result:
                    self.ln(2)
                    self.set_font('Arial', 'B', 10)
                    self.cell(0, 6, 'Recommendations:', 0, 1, 'L')
                    self.set_font('Arial', '', 10)
                    recommendation = recommendations.get(check_name, "No specific recommendations available.")
                    self.multi_cell(0, 5, recommendation.strip())
                
                self.ln(5)
                self.cell(0, 1, '', 'B', 1, 'L')  # Separator line
                self.ln(5)


def save_results_to_pdf(results, output_file):
    pdf = SecurityReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Executive Summary
    pdf.chapter_title('Executive Summary')
    pdf.create_executive_summary(results)
    
    # Detailed Findings
    pdf.add_page()
    pdf.chapter_title('Detailed Findings')
    
    pdf.add_vulnerability_details(results)
    
    pdf.output(output_file)
    print(f"Enhanced security report saved to {output_file}")