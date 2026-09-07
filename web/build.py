from pathlib import Path

root = Path(__file__).parent
shell = (root / "shell.html").read_text(encoding="utf-8")
for name in ("core", "ui"):
    shell = shell.replace(
        "__" + name.upper() + "__", (root / (name + ".js")).read_text(encoding="utf-8")
    )
(root / "index.html").write_text(shell, encoding="utf-8")

(root.parent / "src/browser_session_export_privacy_scrubber/browser.html").write_text(
    shell, encoding="utf-8"
)
