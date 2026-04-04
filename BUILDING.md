# Building Executables / 构建可执行文件

This guide explains how to build standalone executables for VulnScan using PyInstaller.
本指南说明如何使用 PyInstaller 构建 VulnScan 的独立可执行文件。

## Prerequisites / 前置要求

- Python 3.10+
- PyInstaller

```bash
pip install pyinstaller
```

## Recommended: Using the Build Script / 推荐：使用构建脚本

The project includes a build script that automates the entire process, including hash updates for integrity checks.
项目包含构建脚本，自动完成整个流程（包括完整性校验哈希更新）。

```bash
# Build both CLI and GUI / 构建 CLI 和 GUI
python scripts/build.py --all

# Build CLI only / 仅构建 CLI
python scripts/build.py --console

# Build GUI only / 仅构建 GUI
python scripts/build.py --gui
```

## Manual Build Commands / 手动构建命令

### Windows

```bash
pyinstaller --name vulnscan --onefile --windowed \
  --add-data "vulnscan/data;vulnscan/data" \
  --add-data "vulnscan/assets;vulnscan/assets" \
  --add-data "vulnscan/locale;vulnscan/locale" \
  --icon=vulnscan/assets/icon.ico \
  main.py
```

### macOS

```bash
pyinstaller --name vulnscan --onefile --windowed \
  --add-data "vulnscan/data:vulnscan/data" \
  --add-data "vulnscan/assets:vulnscan/assets" \
  --add-data "vulnscan/locale:vulnscan/locale" \
  main.py
```

### Linux

```bash
pyinstaller --name vulnscan --onefile \
  --add-data "vulnscan/data:vulnscan/data" \
  --add-data "vulnscan/assets:vulnscan/assets" \
  --add-data "vulnscan/locale:vulnscan/locale" \
  main.py
```

## Notes / 注意事项

- **Path separator / 路径分隔符**: macOS and Linux use `:` as the `--add-data` separator; Windows uses `;`. macOS 和 Linux 使用 `:` 作为 `--add-data` 的分隔符，Windows 使用 `;`。
- **`--windowed` flag**: Creates a GUI application without a console window. Use `--console` instead if you need CLI-only mode. `--windowed` 参数创建无控制台窗口的 GUI 应用，如需仅 CLI 模式请改用 `--console`。
- **Output directory / 输出目录**: The built executable will be placed in the `dist/` directory. 构建完成的可执行文件位于 `dist/` 目录。
- **Icon / 图标**: The `--icon` flag is only used on Windows. Windows 下使用 `--icon` 指定应用图标。
- **File size / 文件大小**: The `--onefile` option bundles everything into a single executable, which may be larger but is easier to distribute. `--onefile` 将所有内容打包为单个可执行文件，体积较大但更便于分发。

## Troubleshooting / 常见问题

- If data files are not found at runtime, ensure the `--add-data` paths match the project structure. 如果运行时找不到数据文件，请确认 `--add-data` 路径与项目结构一致。
- On macOS, you may need to sign the application for distribution. macOS 下分发时可能需要对应用进行签名。
- On Linux, ensure the executable has execute permissions: `chmod +x dist/vulnscan`. Linux 下确保可执行文件有执行权限：`chmod +x dist/vulnscan`。
