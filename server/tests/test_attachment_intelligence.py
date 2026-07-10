import unittest
import base64
import io
import zipfile
import gzip
import asyncio
from models.email_model import Email
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine

class TestAttachmentIntelligence(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_scenario_1_legit_pdf(self):
        # Legitimate PDF invoice (clean structure)
        payload = {
            "subject": "Your Invoice",
            "sender": "billing@company.com",
            "body": "Hi, please see attached invoice.",
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 15,
                    "content_base64": base64.b64encode(b"%PDF-1.4\n%clean pdf file structure\n").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("ATT_005", report.triggered_rules)
        self.assertNotIn("ATT_006", report.triggered_rules)

    def test_scenario_2_legit_docx(self):
        # Legitimate DOCX resume (clean zip structure, no macros)
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/document.xml", "<document>Clean text</document>")
        payload = {
            "subject": "Resume update",
            "sender": "applicant@gmail.com",
            "body": "Please find my resume attached.",
            "attachments": [
                {
                    "filename": "resume.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("ATT_008", report.triggered_rules)

    def test_scenario_3_legit_xlsx(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("xl/workbook.xml", "<workbook></workbook>")
        payload = {
            "subject": "Q2 Invoice Report",
            "sender": "finance@company.com",
            "body": "Report attached.",
            "attachments": [
                {
                    "filename": "report.xlsx",
                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("ATT_008", report.triggered_rules)

    def test_scenario_4_legit_zip(self):
        # Clean zip source code archive
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("main.py", "print('hello')")
            zf.writestr("README.md", "# Project")
        payload = {
            "subject": "Code Submission",
            "sender": "dev@company.com",
            "body": "Zip code attached.",
            "attachments": [
                {
                    "filename": "source.zip",
                    "content_type": "application/zip",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("ATT_007", report.triggered_rules)

    def test_scenario_5_double_extension(self):
        payload = {
            "subject": "Urgent Invoice details",
            "sender": "attacker@gmail.com",
            "body": "Double extension file attached.",
            "attachments": [
                {
                    "filename": "invoice.pdf.exe",
                    "content_type": "application/x-msdownload",
                    "size_bytes": 10,
                    "content_base64": base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_003", report.triggered_rules)

    def test_scenario_6_mime_mismatch_masquerading(self):
        # Declared png, but detected as exe signature
        payload = {
            "subject": "Receipt printout",
            "sender": "attacker@gmail.com",
            "body": "Masquerading executable attached.",
            "attachments": [
                {
                    "filename": "receipt.png",
                    "content_type": "image/png",
                    "size_bytes": 12,
                    "content_base64": base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_005", report.triggered_rules)

    def test_scenario_7_magic_byte_mismatch(self):
        # Declared docx, but magic byte points to pdf
        payload = {
            "subject": "Contract draft",
            "sender": "attacker@gmail.com",
            "body": "Masquerading PDF attached.",
            "attachments": [
                {
                    "filename": "draft.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "size_bytes": 15,
                    "content_base64": base64.b64encode(b"%PDF-1.5\n%object stream\n").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_005", report.triggered_rules)

    def test_scenario_8_docx_macros(self):
        # DOCX containing word/vbaProject.bin macro indicator
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/vbaProject.bin", b"VBA MACRO BYTES")
        payload = {
            "subject": "Macro Invoice details",
            "sender": "attacker@gmail.com",
            "body": "Macro docx attached.",
            "attachments": [
                {
                    "filename": "invoice_macro.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_008", report.triggered_rules)

    def test_scenario_9_pdf_js(self):
        # PDF containing /JavaScript stream
        payload = {
            "subject": "Alert statement",
            "sender": "attacker@gmail.com",
            "body": "PDF with JS attached.",
            "attachments": [
                {
                    "filename": "alert.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 40,
                    "content_base64": base64.b64encode(b"%PDF-1.4\n1 0 obj\n<< /JavaScript (app.alert('Compromised');) >>\nendobj").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_006", report.triggered_rules)

    def test_scenario_10_pdf_open_launch(self):
        # PDF containing /OpenAction /Launch
        payload = {
            "subject": "Urgent load details",
            "sender": "attacker@gmail.com",
            "body": "PDF with LaunchAction attached.",
            "attachments": [
                {
                    "filename": "launch.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 35,
                    "content_base64": base64.b64encode(b"%PDF-1.4\n<< /OpenAction << /S /Launch /F (cmd.exe) >> >>").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_006", report.triggered_rules)

    def test_scenario_11_zip_bomb(self):
        # Zip bomb simulation (expansion ratio > 100)
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Add highly compressed file of zeroes (10MB compressed to a few bytes)
            zf.writestr("zero.txt", b"\x00" * 2 * 1024 * 1024)
        payload = {
            "subject": "Large logs archive",
            "sender": "attacker@gmail.com",
            "body": "Zip bomb attached.",
            "attachments": [
                {
                    "filename": "logs.zip",
                    "content_type": "application/zip",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_007", report.triggered_rules)

    def test_scenario_12_nested_archive_recursion(self):
        # Deeply nested archive path simulation
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as zf:
            zf.writestr("dir1/dir2/dir3/dir4/exploit.exe", b"MZ")
        payload = {
            "subject": "Nested updates folder",
            "sender": "attacker@gmail.com",
            "body": "Nested zip attached.",
            "attachments": [
                {
                    "filename": "nested.zip",
                    "content_type": "application/zip",
                    "size_bytes": len(bio.getvalue()),
                    "content_base64": base64.b64encode(bio.getvalue()).decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_007", report.triggered_rules)

    def test_scenario_13_dangerous_scripts(self):
        # Executable VBS or PS1 script attachment
        payload = {
            "subject": "Automation updates script",
            "sender": "attacker@gmail.com",
            "body": "VBS script attached.",
            "attachments": [
                {
                    "filename": "run.vbs",
                    "content_type": "text/vbscript",
                    "size_bytes": 50,
                    "content_base64": base64.b64encode(b"Set obj = CreateObject(\"WScript.Shell\")\nobj.Run \"cmd.exe\"").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_009", report.triggered_rules)

    def test_scenario_14_svg_scripts(self):
        # SVG image containing script tags
        payload = {
            "subject": "Company Logo Vector",
            "sender": "attacker@gmail.com",
            "body": "SVG image attached.",
            "attachments": [
                {
                    "filename": "logo.svg",
                    "content_type": "image/svg+xml",
                    "size_bytes": 100,
                    "content_base64": base64.b64encode(b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_010", report.triggered_rules)

    def test_scenario_15_iso_lnk_shortcut(self):
        # Dangerous shortcut links or ISO image packages
        payload = {
            "subject": "System installer image",
            "sender": "attacker@gmail.com",
            "body": "Shortcut attached.",
            "attachments": [
                {
                    "filename": "update.lnk",
                    "content_type": "application/octet-stream",
                    "size_bytes": 5,
                    "content_base64": base64.b64encode(b"LNK\x00").decode("utf-8")
                }
            ]
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("ATT_001", report.triggered_rules)

if __name__ == '__main__':
    unittest.main()
