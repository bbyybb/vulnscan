# Security Policy / 安全策略

## Supported Versions / 支持的版本

The following versions of VulnScan receive security updates:

以下版本的 VulnScan 会收到安全更新：

| Version / 版本 | Supported / 支持状态 |
|---------------|---------------------|
| 1.0.0         | :white_check_mark: Yes / 是 |
| < 1.0.0       | :x: No / 否 |

## Reporting a Vulnerability / 报告漏洞

**Please do NOT report security vulnerabilities through public GitHub issues.**

**请不要在公开的 GitHub Issue 中报告安全漏洞。**

If you discover a security vulnerability in VulnScan, please report it responsibly:

如果你在 VulnScan 中发现了安全漏洞，请以负责任的方式报告：

1. **Send an email to / 发送邮件至**: [bbyybb@users.noreply.github.com](mailto:bbyybb@users.noreply.github.com)
2. **Include the following information / 请包含以下信息**:
   - Description of the vulnerability / 漏洞描述
   - Steps to reproduce / 复现步骤
   - Potential impact / 潜在影响
   - Suggested fix (if any) / 建议的修复方案（如果有）
3. **Response time / 响应时间**: We will acknowledge your report within **48 hours** / 我们将在 **48 小时** 内确认收到你的报告

## What to Expect / 后续流程

After you submit a vulnerability report:

在你提交漏洞报告后：

1. **Acknowledgment / 确认** -- We will confirm receipt within 48 hours / 我们将在 48 小时内确认收到
2. **Assessment / 评估** -- We will assess the severity and impact / 我们将评估严重程度和影响范围
3. **Fix / 修复** -- We will develop and test a fix / 我们将开发并测试修复方案
4. **Release / 发布** -- We will release a security update / 我们将发布安全更新
5. **Credit / 致谢** -- We will credit you in the release notes (unless you prefer to remain anonymous) / 我们将在发布说明中致谢（除非你希望保持匿名）

## Security Update Process / 安全更新流程

When a security vulnerability is confirmed:

当安全漏洞被确认后：

1. A fix will be developed on a private branch / 将在私有分支上开发修复
2. The fix will be thoroughly tested / 修复将经过全面测试
3. A new patch version will be released / 将发布新的补丁版本
4. A security advisory will be published on GitHub / 将在 GitHub 上发布安全公告
5. Users will be notified through GitHub release notes / 用户将通过 GitHub 发布说明获得通知

## Best Practices / 最佳实践

When using VulnScan, please keep in mind:

使用 VulnScan 时，请注意：

- Always use the latest version / 始终使用最新版本
- Only scan targets you have authorization to test / 仅扫描你已获授权测试的目标
- Keep your dependencies up to date / 保持依赖项更新
- Review scan reports for sensitive information before sharing / 分享前检查扫描报告中是否包含敏感信息
