# Contributing / 贡献指南

## Welcome / 欢迎

Thank you for your interest in contributing to VulnScan! Every contribution helps make this project better.

感谢你对 VulnScan 项目的关注！每一份贡献都能让这个项目变得更好。

## How to Contribute / 如何贡献

### Reporting Bugs / 报告问题

If you find a bug, please open an issue using the [Bug Report template](https://github.com/bbyybb/vulnscan/issues/new?template=bug_report.md). Include as much detail as possible:

如果你发现了 Bug，请使用 [问题报告模板](https://github.com/bbyybb/vulnscan/issues/new?template=bug_report.md) 提交 Issue，并尽量包含以下信息：

- A clear and descriptive title / 简洁明了的标题
- Steps to reproduce / 复现步骤
- Expected vs actual behavior / 预期行为与实际行为
- Environment information (OS, Python version, VulnScan version) / 环境信息（操作系统、Python 版本、VulnScan 版本）

### Suggesting Features / 建议功能

Feature suggestions are welcome! Please use the [Feature Request template](https://github.com/bbyybb/vulnscan/issues/new?template=feature_request.md).

欢迎提出功能建议！请使用 [功能建议模板](https://github.com/bbyybb/vulnscan/issues/new?template=feature_request.md)。

### Pull Requests / 提交 PR

1. Fork the repository / Fork 本仓库
2. Create a feature branch (`git checkout -b feature/your-feature`) / 创建功能分支
3. Make your changes / 进行修改
4. Add or update tests / 添加或更新测试
5. Ensure all tests pass / 确保所有测试通过
6. Submit a pull request / 提交 Pull Request

## Development Setup / 开发环境搭建

```bash
git clone https://github.com/bbyybb/vulnscan.git
cd vulnscan
pip install -r requirements.txt
pip install pytest pytest-cov
python -m pytest tests/ -v
```

## Code Style / 代码风格

Please follow these coding conventions / 请遵循以下编码规范：

- **Python 3.10+** -- Use modern Python features / 使用现代 Python 特性
- **UTF-8 encoding** -- All source files must use UTF-8 / 所有源文件必须使用 UTF-8 编码
- **Type hints** -- Add type annotations to function signatures / 为函数签名添加类型注解
- Follow PEP 8 style guidelines / 遵循 PEP 8 代码风格
- Use meaningful variable and function names / 使用有意义的变量和函数名

## Adding a New Scanner / 添加新扫描器

To add a new scanner to VulnScan, follow these steps:

要向 VulnScan 添加新的扫描器，请按照以下步骤操作：

1. **Create the scanner file / 创建扫描器文件**
   - Built-in scanner: `vulnscan/scanners/builtin/your_scanner.py`
   - External tool scanner: `vulnscan/scanners/external/your_scanner.py`

   内置扫描器放在 `vulnscan/scanners/builtin/` 目录下，外部工具扫描器放在 `vulnscan/scanners/external/` 目录下。

2. **Inherit the base class / 继承基类**
   - Built-in: inherit from `Scanner` / 内置扫描器继承 `Scanner`
   - External: inherit from `ExternalScanner` / 外部扫描器继承 `ExternalScanner`

3. **Implement the `run()` method / 实现 `run()` 方法**
   - The `run()` method should return a `ScanResult` object.
   - `run()` 方法应返回 `ScanResult` 对象。

4. **Register in registry / 在 registry.py 中注册**
   - Add your scanner to the scanner registry in `vulnscan/registry.py`.
   - 在 `vulnscan/registry.py` 中注册你的扫描器。

5. **Add tests / 添加测试**
   - Write unit tests in the `tests/` directory.
   - 在 `tests/` 目录下编写单元测试。

## Commit Message / 提交信息规范

Please use the following commit message prefixes / 请使用以下提交信息前缀：

| Prefix / 前缀 | Usage / 用途 |
|---------------|-------------|
| `feat:`       | New feature / 新功能 |
| `fix:`        | Bug fix / 修复 |
| `docs:`       | Documentation / 文档 |
| `test:`       | Tests / 测试 |
| `refactor:`   | Refactoring / 重构 |

Examples / 示例：

```
feat: add XSS scanner
fix: resolve SSL timeout issue
docs: update contributing guide
test: add unit tests for port scanner
refactor: simplify engine task scheduling
```

---

Thank you for contributing! / 感谢你的贡献！
