"""VulnScan unified entry point.

- No arguments or 'gui' argument  -> launch the GUI
- Any other arguments              -> run the CLI
"""

from __future__ import annotations

import sys

from vulnscan.i18n import auto_detect_language, set_language
from vulnscan.locale.messages import register_all


def main() -> None:
    # 初始化国际化
    register_all()
    set_language(auto_detect_language())

    # 完整性校验
    from vulnscan.integrity import startup_check
    startup_check()

    args = sys.argv[1:]

    if not args or (len(args) == 1 and args[0].lower() == "gui"):
        from vulnscan.gui import launch_gui
        launch_gui(_skip_init=True)
    else:
        from vulnscan.cli import main as cli_main
        cli_main(args, _skip_init=True)


if __name__ == "__main__":
    main()
