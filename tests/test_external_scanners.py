# -*- coding: utf-8 -*-
"""外部扫描器单元测试。

使用 unittest.mock 模拟 _run_command，确保测试不依赖外部工具安装。
覆盖所有 9 个外部扫描器的输出解析逻辑、空输出处理和 is_available 方法。
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vulnscan.models import Severity


# ---------------------------------------------------------------------------
# 辅助函数: 构建 CompletedProcess mock
# ---------------------------------------------------------------------------

def _make_completed_process(stdout: str = "", stderr: str = "", returncode: int = 0):
    """返回一个模拟的 subprocess.CompletedProcess 实例。"""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ===========================================================================
# 1. NucleiScanner
# ===========================================================================

class TestNucleiScanner:
    """NucleiScanner 单元测试。"""

    def test_nuclei_parse_output(self):
        """mock _run_command 返回包含漏洞的 JSONL 输出，验证解析正确。"""
        from vulnscan.scanners.external.nuclei_scanner import NucleiScanner

        jsonl_output = "\n".join([
            json.dumps({
                "info": {
                    "name": "XSS Detection",
                    "severity": "high",
                    "description": "Reflected XSS found",
                    "reference": ["https://example.com/ref1", "https://example.com/ref2"],
                },
                "matcher-name": "xss-match",
                "matched-at": "https://target.com/vuln",
            }),
            json.dumps({
                "info": {
                    "name": "Open Redirect",
                    "severity": "medium",
                    "description": "Open redirect vulnerability",
                    "reference": [],
                },
                "extracted-results": ["token123", "token456"],
                "matched-at": "https://target.com/redirect",
            }),
        ])

        scanner = NucleiScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=jsonl_output)):
            result = scanner.run("https://target.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert v0.name == "XSS Detection"
        assert v0.severity == Severity.HIGH
        assert v0.evidence == "xss-match"
        assert v0.location == "https://target.com/vuln"
        assert v0.reference == "https://example.com/ref1"

        v1 = result.vulnerabilities[1]
        assert v1.name == "Open Redirect"
        assert v1.severity == Severity.MEDIUM
        assert "token123" in v1.evidence
        assert v1.reference == ""

    def test_nuclei_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.nuclei_scanner import NucleiScanner

        scanner = NucleiScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("https://target.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_nuclei_is_available_found(self):
        """executable 在 PATH 中时 is_available 应返回 True。"""
        from vulnscan.scanners.external.nuclei_scanner import NucleiScanner

        scanner = NucleiScanner()
        with patch("shutil.which", return_value="/usr/bin/nuclei"):
            available, msg = scanner.is_available()

        assert available is True
        assert "found at" in msg

    def test_nuclei_is_available_not_found(self):
        """executable 不在 PATH 中时 is_available 应返回 False。"""
        from vulnscan.scanners.external.nuclei_scanner import NucleiScanner

        scanner = NucleiScanner()
        with patch("shutil.which", return_value=None):
            available, msg = scanner.is_available()

        assert available is False
        assert "not found" in msg

    def test_nuclei_command_exception(self):
        """_run_command 抛出异常时应返回 success=False。"""
        from vulnscan.scanners.external.nuclei_scanner import NucleiScanner

        scanner = NucleiScanner()
        with patch.object(scanner, "_run_command", side_effect=OSError("command not found")):
            result = scanner.run("https://target.com")

        assert result.success is False
        assert "命令执行失败" in result.error_message


# ===========================================================================
# 2. NmapScanner
# ===========================================================================

class TestNmapScanner:
    """NmapScanner 单元测试。"""

    NMAP_XML_OUTPUT = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="5.7"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    def test_nmap_parse_xml_output(self):
        """mock _run_command 返回 XML，验证端口和服务解析正确。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        scanner = NmapScanner()
        # 第一次调用(TCP)返回有端口的 XML，后续调用(UDP)返回空 XML
        empty_xml = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
        with patch.object(scanner, "_run_command", side_effect=[
            _make_completed_process(stdout=self.NMAP_XML_OUTPUT),
            _make_completed_process(stdout=empty_xml),
        ]):
            result = scanner.run("https://example.com")

        assert result.success is True
        # 只有 open 状态的端口才应被解析，共 2 个 (22, 3306)
        assert len(result.vulnerabilities) == 2

        port_names = [v.name for v in result.vulnerabilities]
        assert any("22" in name for name in port_names)
        assert any("3306" in name for name in port_names)

        # mysql 属于高危服务，应为 MEDIUM
        mysql_vulns = [v for v in result.vulnerabilities if "3306" in v.name]
        assert mysql_vulns[0].severity == Severity.MEDIUM

        # ssh 不在高危列表，应为 INFO
        ssh_vulns = [v for v in result.vulnerabilities if "22" in v.name]
        assert ssh_vulns[0].severity == Severity.INFO

    def test_nmap_empty_output(self):
        """空输出（无效 XML）时应返回 success=False。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        scanner = NmapScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("https://example.com")

        # 空 XML 会触发 ParseError（TCP 阶段即失败，不会进入 UDP）
        assert result.success is False
        assert "XML 解析失败" in result.error_message

    def test_nmap_xml_with_vuln_script(self):
        """XML 中包含 script 输出且含 VULNERABLE 关键字时应额外生成漏洞。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        xml_with_script = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-heartbleed" output="VULNERABLE: Heartbleed (CVE-2014-0160)"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        scanner = NmapScanner()
        empty_xml = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
        with patch.object(scanner, "_run_command", side_effect=[
            _make_completed_process(stdout=xml_with_script),
            _make_completed_process(stdout=empty_xml),
        ]):
            result = scanner.run("https://example.com")

        assert result.success is True
        # 1 个 open port + 1 个 script vuln
        assert len(result.vulnerabilities) == 2
        script_vulns = [v for v in result.vulnerabilities if "ssl-heartbleed" in v.name]
        assert len(script_vulns) == 1
        assert script_vulns[0].severity == Severity.HIGH

    def test_nmap_xml_with_hostscript(self):
        """XML 中包含 hostscript 且含 CVE- 关键字时应生成漏洞。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        xml_hostscript = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: CVE-2017-0143 (EternalBlue)"/>
    </hostscript>
  </host>
</nmaprun>"""

        scanner = NmapScanner()
        empty_xml = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
        with patch.object(scanner, "_run_command", side_effect=[
            _make_completed_process(stdout=xml_hostscript),
            _make_completed_process(stdout=empty_xml),
        ]):
            result = scanner.run("https://example.com")

        assert result.success is True
        hostscript_vulns = [v for v in result.vulnerabilities if "hostscript" in v.name]
        assert len(hostscript_vulns) == 1
        assert hostscript_vulns[0].severity == Severity.HIGH

    def test_nmap_invalid_target(self):
        """无法提取主机名时应返回 success=False。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        scanner = NmapScanner()
        # 空字符串无法解析出主机
        result = scanner.run("")

        assert result.success is False
        assert "无法从目标提取主机名" in result.error_message

    def test_nmap_is_available(self):
        """is_available 应正确检测 nmap 是否在 PATH 中。"""
        from vulnscan.scanners.external.nmap_scanner import NmapScanner

        scanner = NmapScanner()
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            available, msg = scanner.is_available()
        assert available is True

        with patch("shutil.which", return_value=None):
            available, msg = scanner.is_available()
        assert available is False


# ===========================================================================
# 3. SqlmapScanner
# ===========================================================================

class TestSqlmapScanner:
    """SqlmapScanner 单元测试。"""

    SQLMAP_OUTPUT_WITH_VULNS = """\
[INFO] testing connection to the target URL
[INFO] the back-end DBMS is MySQL
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1

Parameter: id (GET)
    Type: time-based blind
    Payload: id=1 AND SLEEP(5)

[INFO] the parameter 'id' is vulnerable
"""

    def test_sqlmap_parse_output(self):
        """mock _run_command 返回包含注入结果的输出，验证解析正确。"""
        from vulnscan.scanners.external.sqlmap_scanner import SqlmapScanner

        scanner = SqlmapScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.SQLMAP_OUTPUT_WITH_VULNS)):
            with patch.object(scanner, "_cleanup"):
                result = scanner.run("https://target.com/page?id=1")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert "id" in v0.name
        assert "boolean-based blind" in v0.description
        assert v0.severity == Severity.HIGH
        assert v0.cwe_id == "CWE-89"

        v1 = result.vulnerabilities[1]
        assert "time-based blind" in v1.description

    def test_sqlmap_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.sqlmap_scanner import SqlmapScanner

        scanner = SqlmapScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            with patch.object(scanner, "_cleanup"):
                result = scanner.run("https://target.com/page?id=1")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_sqlmap_vulnerable_but_no_parameter(self):
        """输出中包含 'is vulnerable' 但没有具体参数信息时应生成通用漏洞。"""
        from vulnscan.scanners.external.sqlmap_scanner import SqlmapScanner

        output = "[INFO] target URL is vulnerable to SQL injection\n"

        scanner = SqlmapScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=output)):
            with patch.object(scanner, "_cleanup"):
                result = scanner.run("https://target.com/page?id=1")

        assert result.success is True
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].name == "SQL Injection Detected"

    def test_sqlmap_is_available(self):
        """is_available 应正确检测 sqlmap 是否在 PATH 中。"""
        from vulnscan.scanners.external.sqlmap_scanner import SqlmapScanner

        scanner = SqlmapScanner()
        with patch("shutil.which", return_value="/usr/bin/sqlmap"):
            available, _ = scanner.is_available()
        assert available is True


# ===========================================================================
# 4. NiktoScanner
# ===========================================================================

class TestNiktoScanner:
    """NiktoScanner 单元测试。"""

    NIKTO_JSON_OUTPUT = json.dumps({
        "vulnerabilities": [
            {
                "OSVDB": "3092",
                "method": "GET",
                "url": "/admin/",
                "msg": "Admin directory found",
                "id": "001",
            },
            {
                "OSVDB": "0",
                "method": "GET",
                "url": "/icons/",
                "msg": "Directory indexing found",
                "id": "002",
            },
        ]
    })

    NIKTO_TEXT_OUTPUT = """\
- Nikto v2.1.6
+ Target IP: 1.2.3.4
+ Target Hostname: example.com
+ OSVDB-3092: /admin/: Admin directory found
+ Server: Apache/2.4.41
+ No CGI Directories found
"""

    def test_nikto_parse_json_output(self):
        """mock _run_command 返回 JSON 输出，验证解析正确。"""
        from vulnscan.scanners.external.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.NIKTO_JSON_OUTPUT)):
            result = scanner.run("https://target.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert v0.name == "Admin directory found"
        assert v0.severity == Severity.MEDIUM  # 有 OSVDB 编号
        assert v0.reference == "OSVDB-3092"

        v1 = result.vulnerabilities[1]
        assert v1.severity == Severity.LOW  # OSVDB=0
        assert v1.reference == ""

    def test_nikto_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("https://target.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_nikto_text_fallback_parse(self):
        """JSON 解析失败时应回退到文本解析。"""
        from vulnscan.scanners.external.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()
        # 返回纯文本（非 JSON），触发 _parse_text 回退
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.NIKTO_TEXT_OUTPUT)):
            result = scanner.run("https://target.com")

        assert result.success is True
        assert len(result.vulnerabilities) > 0

        # 包含 OSVDB 的行应为 MEDIUM
        osvdb_vulns = [v for v in result.vulnerabilities if v.reference and "OSVDB" in v.reference]
        assert len(osvdb_vulns) >= 1
        assert osvdb_vulns[0].severity == Severity.MEDIUM

    def test_nikto_is_available_nikto_pl(self):
        """如果 nikto 不存在但 nikto.pl 存在，应返回可用。"""
        from vulnscan.scanners.external.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()

        def mock_which(name):
            if name == "nikto":
                return None
            if name == "nikto.pl":
                return "/usr/bin/nikto.pl"
            return None

        with patch("shutil.which", side_effect=mock_which):
            available, msg = scanner.is_available()

        assert available is True
        assert "nikto.pl" in msg

    def test_nikto_is_available_not_found(self):
        """nikto 和 nikto.pl 都不存在时应返回不可用。"""
        from vulnscan.scanners.external.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()
        with patch("shutil.which", return_value=None):
            available, msg = scanner.is_available()

        assert available is False
        assert "not found" in msg


# ===========================================================================
# 5. FfufScanner
# ===========================================================================

class TestFfufScanner:
    """FfufScanner 单元测试。"""

    FFUF_JSON_OUTPUT = json.dumps({
        "results": [
            {
                "url": "https://target.com/admin",
                "status": 200,
                "length": 1234,
                "words": 56,
            },
            {
                "url": "https://target.com/robots.txt",
                "status": 200,
                "length": 50,
                "words": 5,
            },
            {
                "url": "https://target.com/secret",
                "status": 403,
                "length": 200,
                "words": 10,
            },
        ]
    })

    def test_ffuf_parse_json_output(self):
        """直接测试 _parse_output 方法解析 JSON 输出。"""
        from vulnscan.scanners.external.ffuf_scanner import FfufScanner

        scanner = FfufScanner()
        vulns = scanner._parse_output(self.FFUF_JSON_OUTPUT, "https://target.com")

        assert len(vulns) == 3

        # /admin 是敏感路径且 200 -> MEDIUM
        admin_vulns = [v for v in vulns if "admin" in v.location]
        assert len(admin_vulns) == 1
        assert admin_vulns[0].severity == Severity.MEDIUM

        # /robots.txt 非敏感路径且 200 -> LOW
        robots_vulns = [v for v in vulns if "robots" in v.location]
        assert len(robots_vulns) == 1
        assert robots_vulns[0].severity == Severity.LOW

        # /secret 是 403 -> INFO
        secret_vulns = [v for v in vulns if "secret" in v.location]
        assert len(secret_vulns) == 1
        assert secret_vulns[0].severity == Severity.INFO

    def test_ffuf_empty_output(self):
        """空 JSON 输出时 _parse_output 应返回空列表。"""
        from vulnscan.scanners.external.ffuf_scanner import FfufScanner

        scanner = FfufScanner()
        vulns = scanner._parse_output("{}", "https://target.com")
        assert len(vulns) == 0

    def test_ffuf_empty_string_output(self):
        """完全空字符串时 _parse_output 应返回空列表。"""
        from vulnscan.scanners.external.ffuf_scanner import FfufScanner

        scanner = FfufScanner()
        vulns = scanner._parse_output("", "https://target.com")
        assert len(vulns) == 0

    def test_ffuf_redirect_status(self):
        """重定向状态码 (301/302/307) 应为 INFO。"""
        from vulnscan.scanners.external.ffuf_scanner import FfufScanner

        output = json.dumps({
            "results": [
                {"url": "https://target.com/old-page", "status": 301, "length": 0, "words": 0},
                {"url": "https://target.com/temp", "status": 307, "length": 0, "words": 0},
            ]
        })

        scanner = FfufScanner()
        vulns = scanner._parse_output(output, "https://target.com")

        assert len(vulns) == 2
        for v in vulns:
            assert v.severity == Severity.INFO
            assert "Redirect" in v.name

    def test_ffuf_is_available(self):
        """is_available 应正确检测 ffuf。"""
        from vulnscan.scanners.external.ffuf_scanner import FfufScanner

        scanner = FfufScanner()
        with patch("shutil.which", return_value="/usr/bin/ffuf"):
            available, _ = scanner.is_available()
        assert available is True


# ===========================================================================
# 6. BanditScanner
# ===========================================================================

class TestBanditScanner:
    """BanditScanner 单元测试。"""

    BANDIT_JSON_OUTPUT = json.dumps({
        "results": [
            {
                "test_name": "hardcoded_password_string",
                "test_id": "B105",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password: 'secret123'",
                "filename": "/app/config.py",
                "line_number": 10,
                "code": "password = 'secret123'",
                "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
            },
            {
                "test_name": "flask_debug_true",
                "test_id": "B201",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "A Flask app appears to be run with debug=True",
                "filename": "/app/main.py",
                "line_number": 42,
                "code": "app.run(debug=True)",
                "issue_cwe": {},
            },
        ]
    })

    def test_bandit_parse_output(self):
        """mock _run_command 返回 Bandit JSON 输出，验证解析正确。"""
        from vulnscan.scanners.external.bandit_scanner import BanditScanner

        scanner = BanditScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.BANDIT_JSON_OUTPUT)):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert "hardcoded_password_string" in v0.name
        assert "B105" in v0.name
        assert v0.severity == Severity.HIGH
        assert v0.cwe_id == "CWE-259"
        assert v0.location == "/app/config.py:10"

        v1 = result.vulnerabilities[1]
        assert v1.severity == Severity.MEDIUM
        assert v1.cwe_id == ""  # issue_cwe 为空字典
        assert v1.confidence == "high"

    def test_bandit_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.bandit_scanner import BanditScanner

        scanner = BanditScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_bandit_invalid_json(self):
        """无效 JSON 输出时应返回 success=False。"""
        from vulnscan.scanners.external.bandit_scanner import BanditScanner

        scanner = BanditScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="not valid json")):
            result = scanner.run("/app")

        assert result.success is False
        assert "JSON 解析失败" in result.error_message

    def test_bandit_is_available(self):
        """is_available 应正确检测 bandit。"""
        from vulnscan.scanners.external.bandit_scanner import BanditScanner

        scanner = BanditScanner()
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            available, _ = scanner.is_available()
        assert available is True


# ===========================================================================
# 7. SemgrepScanner
# ===========================================================================

class TestSemgrepScanner:
    """SemgrepScanner 单元测试。"""

    SEMGREP_JSON_OUTPUT = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.injection.sql-injection",
                "path": "app/db.py",
                "start": {"line": 15, "col": 1},
                "end": {"line": 15, "col": 50},
                "extra": {
                    "message": "Detected SQL injection risk",
                    "severity": "ERROR",
                    "lines": "cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "owasp": ["A03:2021 - Injection"],
                    },
                },
            },
            {
                "check_id": "python.lang.security.deserialization.avoid-pickle",
                "path": "app/utils.py",
                "start": {"line": 30, "col": 1},
                "end": {"line": 32, "col": 20},
                "extra": {
                    "message": "Avoid using pickle for deserialization",
                    "severity": "WARNING",
                    "lines": "pickle.loads(data)",
                    "metadata": {
                        "cwe": "CWE-502",
                        "owasp": [],
                    },
                },
            },
        ]
    })

    def test_semgrep_parse_output(self):
        """mock _run_command 返回 Semgrep JSON 输出，验证解析正确。"""
        from vulnscan.scanners.external.semgrep_scanner import SemgrepScanner

        scanner = SemgrepScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.SEMGREP_JSON_OUTPUT)):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert v0.name == "python.lang.security.injection.sql-injection"
        assert v0.severity == Severity.HIGH  # ERROR -> HIGH
        assert v0.cwe_id == "CWE-89: SQL Injection"
        assert v0.location == "app/db.py:15"
        assert "CWE" in v0.reference
        assert "OWASP" in v0.reference

        v1 = result.vulnerabilities[1]
        assert v1.severity == Severity.MEDIUM  # WARNING -> MEDIUM
        assert v1.location == "app/utils.py:30-32"
        # cwe 是字符串时也应正确处理
        assert v1.cwe_id == "CWE-502"

    def test_semgrep_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.semgrep_scanner import SemgrepScanner

        scanner = SemgrepScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_semgrep_invalid_json(self):
        """无效 JSON 输出时应返回 success=False。"""
        from vulnscan.scanners.external.semgrep_scanner import SemgrepScanner

        scanner = SemgrepScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="{broken json")):
            result = scanner.run("/app")

        assert result.success is False
        assert "JSON 解析失败" in result.error_message

    def test_semgrep_is_available(self):
        """is_available 应正确检测 semgrep。"""
        from vulnscan.scanners.external.semgrep_scanner import SemgrepScanner

        scanner = SemgrepScanner()
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            available, _ = scanner.is_available()
        assert available is True


# ===========================================================================
# 8. TrivyScanner
# ===========================================================================

class TestTrivyScanner:
    """TrivyScanner 单元测试。"""

    TRIVY_JSON_OUTPUT = json.dumps({
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "Severity": "CRITICAL",
                        "Title": "Remote Code Execution in flask",
                        "Description": "A critical RCE vulnerability",
                        "PkgName": "flask",
                        "InstalledVersion": "2.0.0",
                        "FixedVersion": "2.3.3",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-99999",
                        "Severity": "LOW",
                        "Title": "Minor issue in requests",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "",
                    },
                ],
                "Secrets": [
                    {
                        "Severity": "HIGH",
                        "Title": "AWS Access Key",
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                    },
                ],
                "Misconfigurations": [
                    {
                        "Severity": "MEDIUM",
                        "Title": "Insecure Dockerfile",
                        "Message": "Running as root user",
                        "Resolution": "Use a non-root user",
                    },
                ],
            }
        ]
    })

    def test_trivy_parse_output(self):
        """mock _run_command 返回 Trivy JSON 输出，验证解析正确。"""
        from vulnscan.scanners.external.trivy_scanner import TrivyScanner

        scanner = TrivyScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.TRIVY_JSON_OUTPUT)):
            result = scanner.run("/app")

        assert result.success is True
        # 2 vulns + 1 secret + 1 misconfig = 4
        assert len(result.vulnerabilities) == 4

        # CVE 漏洞
        cve_vulns = [v for v in result.vulnerabilities if v.cve_id.startswith("CVE-")]
        assert len(cve_vulns) >= 1
        critical = [v for v in cve_vulns if v.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "flask" in critical[0].evidence
        assert critical[0].remediation == "Update to version 2.3.3"

        # 无修复版本时 remediation 应为空
        low_vulns = [v for v in cve_vulns if v.severity == Severity.LOW]
        assert len(low_vulns) == 1
        assert low_vulns[0].remediation == ""

        # Secret
        secret_vulns = [v for v in result.vulnerabilities if "Secret" in v.name]
        assert len(secret_vulns) == 1
        assert secret_vulns[0].severity == Severity.HIGH

        # Misconfig
        misconfig_vulns = [v for v in result.vulnerabilities if "Misconfig" in v.name]
        assert len(misconfig_vulns) == 1
        assert misconfig_vulns[0].severity == Severity.MEDIUM
        assert misconfig_vulns[0].remediation == "Use a non-root user"

    def test_trivy_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.trivy_scanner import TrivyScanner

        scanner = TrivyScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_trivy_no_vulnerabilities_key(self):
        """Results 中 Vulnerabilities 为 null 时应安全处理。"""
        from vulnscan.scanners.external.trivy_scanner import TrivyScanner

        output = json.dumps({
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": None,
                    "Secrets": None,
                    "Misconfigurations": None,
                }
            ]
        })

        scanner = TrivyScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=output)):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_trivy_is_available(self):
        """is_available 应正确检测 trivy。"""
        from vulnscan.scanners.external.trivy_scanner import TrivyScanner

        scanner = TrivyScanner()
        with patch("shutil.which", return_value="/usr/bin/trivy"):
            available, _ = scanner.is_available()
        assert available is True


# ===========================================================================
# 9. GrypeScanner
# ===========================================================================

class TestGrypeScanner:
    """GrypeScanner 单元测试。"""

    GRYPE_JSON_OUTPUT = json.dumps({
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2022-42969",
                    "severity": "high",
                    "description": "ReDoS vulnerability in py library",
                    "fix": {
                        "versions": ["1.12.0"],
                        "state": "fixed",
                    },
                    "urls": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2022-42969",
                    ],
                },
                "artifact": {
                    "name": "py",
                    "version": "1.11.0",
                    "locations": [
                        {"path": "requirements.txt"},
                    ],
                },
            },
            {
                "vulnerability": {
                    "id": "GHSA-xxxx-yyyy",
                    "severity": "critical",
                    "description": "",
                    "fix": {
                        "versions": [],
                        "state": "not-fixed",
                    },
                    "urls": [],
                },
                "artifact": {
                    "name": "jinja2",
                    "version": "3.0.0",
                    "locations": [],
                },
            },
        ]
    })

    def test_grype_parse_output(self):
        """mock _run_command 返回 Grype JSON 输出，验证解析正确。"""
        from vulnscan.scanners.external.grype_scanner import GrypeScanner

        scanner = GrypeScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=self.GRYPE_JSON_OUTPUT)):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 2

        v0 = result.vulnerabilities[0]
        assert v0.name == "CVE-2022-42969"
        assert v0.severity == Severity.HIGH
        assert v0.cve_id == "CVE-2022-42969"
        assert "py 1.11.0" in v0.evidence
        assert v0.remediation == "Update to version 1.12.0"
        assert v0.location == "requirements.txt"
        assert v0.reference == "https://nvd.nist.gov/vuln/detail/CVE-2022-42969"

        v1 = result.vulnerabilities[1]
        assert v1.name == "GHSA-xxxx-yyyy"
        assert v1.severity == Severity.CRITICAL
        assert v1.cve_id == ""  # 非 CVE 前缀
        assert v1.remediation == ""  # 无修复版本
        assert v1.location == ""  # 无 locations
        # description 为空时应使用 fallback
        assert "jinja2" in v1.description

    def test_grype_empty_output(self):
        """空输出时应返回 success=True 且无漏洞。"""
        from vulnscan.scanners.external.grype_scanner import GrypeScanner

        scanner = GrypeScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="")):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_grype_invalid_json(self):
        """无效 JSON 输出时应返回 success=False。"""
        from vulnscan.scanners.external.grype_scanner import GrypeScanner

        scanner = GrypeScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout="invalid json {{")):
            result = scanner.run("/app")

        assert result.success is False
        assert "JSON 解析失败" in result.error_message

    def test_grype_no_matches(self):
        """JSON 中 matches 为空数组时应返回无漏洞。"""
        from vulnscan.scanners.external.grype_scanner import GrypeScanner

        output = json.dumps({"matches": []})

        scanner = GrypeScanner()
        with patch.object(scanner, "_run_command", return_value=_make_completed_process(stdout=output)):
            result = scanner.run("/app")

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_grype_is_available(self):
        """is_available 应正确检测 grype。"""
        from vulnscan.scanners.external.grype_scanner import GrypeScanner

        scanner = GrypeScanner()
        with patch("shutil.which", return_value="/usr/bin/grype"):
            available, _ = scanner.is_available()
        assert available is True

        with patch("shutil.which", return_value=None):
            available, msg = scanner.is_available()
        assert available is False
        assert "not found" in msg
