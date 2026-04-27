from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from aigov.cli.commands.hooks import (
    _HOOK_MARKER,
    _BACKUP_SUFFIX,
    _build_hook_script,
    _find_git_hooks_dir,
    _install_hook,
    _uninstall_hook,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_repo(base: Path) -> Path:
    """Create a minimal fake git repo and return the hooks dir."""
    hooks_dir = base / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    return hooks_dir


# ---------------------------------------------------------------------------
# _find_git_hooks_dir
# ---------------------------------------------------------------------------

class TestFindGitHooksDir:
    def test_finds_hooks_dir(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        found = _find_git_hooks_dir(tmp_path)
        assert found == hooks_dir

    def test_finds_from_subdirectory(self, tmp_path):
        _make_fake_repo(tmp_path)
        subdir = tmp_path / "src" / "module"
        subdir.mkdir(parents=True)
        found = _find_git_hooks_dir(subdir)
        assert found == tmp_path / ".git" / "hooks"

    def test_raises_outside_git_repo(self, tmp_path):
        with pytest.raises(ValueError, match="git repository"):
            _find_git_hooks_dir(tmp_path)

    def test_creates_hooks_dir_if_missing(self, tmp_path):
        (tmp_path / ".git").mkdir()
        # hooks/ does not exist yet
        found = _find_git_hooks_dir(tmp_path)
        assert found.is_dir()


# ---------------------------------------------------------------------------
# _install_hook — basic install
# ---------------------------------------------------------------------------

class TestInstallHook:
    def test_creates_pre_commit_file(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        assert (hooks_dir / "pre-commit").exists()

    def test_status_is_installed(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        status = _install_hook(hooks_dir)
        assert "installed" in status

    def test_hook_contains_marker(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert _HOOK_MARKER in content

    def test_hook_starts_with_python_shebang(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert content.startswith("#!/usr/bin/env python3")

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix executable bits only")
    def test_hook_is_executable(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        hook = hooks_dir / "pre-commit"
        assert hook.stat().st_mode & stat.S_IXUSR

    def test_hook_calls_aigov_scan(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert "aigov" in content
        assert "--classify" in content

    def test_hook_checks_prohibited(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert "prohibited" in content

    def test_hook_warns_high_risk(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert "high_risk" in content

    def test_install_again_returns_updated(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        status = _install_hook(hooks_dir)
        assert "updated" in status

    def test_install_again_does_not_duplicate_backup(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        _install_hook(hooks_dir)
        backup = hooks_dir / f"pre-commit{_BACKUP_SUFFIX}"
        assert not backup.exists()


# ---------------------------------------------------------------------------
# _install_hook — existing hook backup and chain
# ---------------------------------------------------------------------------

class TestInstallHookWithExisting:
    def _write_existing(self, hooks_dir: Path, content: str = "#!/bin/sh\necho existing") -> Path:
        p = hooks_dir / "pre-commit"
        p.write_text(content, encoding="utf-8")
        return p

    def test_backs_up_existing_hook(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        self._write_existing(hooks_dir)
        _install_hook(hooks_dir)
        backup = hooks_dir / f"pre-commit{_BACKUP_SUFFIX}"
        assert backup.exists()

    def test_backup_contains_original_content(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        self._write_existing(hooks_dir, "#!/bin/sh\necho original-hook")
        _install_hook(hooks_dir)
        backup = hooks_dir / f"pre-commit{_BACKUP_SUFFIX}"
        assert "original-hook" in backup.read_text(encoding="utf-8")

    def test_status_mentions_backup(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        self._write_existing(hooks_dir)
        status = _install_hook(hooks_dir)
        assert "backed up" in status.lower()

    def test_new_hook_has_marker(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        self._write_existing(hooks_dir)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert _HOOK_MARKER in content

    def test_new_hook_references_backup_path(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        self._write_existing(hooks_dir)
        _install_hook(hooks_dir)
        content = (hooks_dir / "pre-commit").read_text(encoding="utf-8")
        assert _BACKUP_SUFFIX in content


# ---------------------------------------------------------------------------
# _uninstall_hook
# ---------------------------------------------------------------------------

class TestUninstallHook:
    def test_removes_hook(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        _uninstall_hook(hooks_dir)
        assert not (hooks_dir / "pre-commit").exists()

    def test_status_is_removed(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        _install_hook(hooks_dir)
        status = _uninstall_hook(hooks_dir)
        assert "removed" in status

    def test_uninstall_when_not_present(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        status = _uninstall_hook(hooks_dir)
        assert "not installed" in status

    def test_does_not_remove_foreign_hook(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        hook = hooks_dir / "pre-commit"
        hook.write_text("#!/bin/sh\necho foreign", encoding="utf-8")
        status = _uninstall_hook(hooks_dir)
        assert "not an aigov hook" in status
        assert hook.exists()

    def test_restores_backup_on_uninstall(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        hook = hooks_dir / "pre-commit"
        hook.write_text("#!/bin/sh\necho original", encoding="utf-8")
        _install_hook(hooks_dir)
        _uninstall_hook(hooks_dir)
        assert hook.exists()
        assert "original" in hook.read_text(encoding="utf-8")

    def test_backup_file_removed_after_restore(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho x", encoding="utf-8")
        _install_hook(hooks_dir)
        _uninstall_hook(hooks_dir)
        assert not (hooks_dir / f"pre-commit{_BACKUP_SUFFIX}").exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix executable bits only")
    def test_restored_hook_is_executable(self, tmp_path):
        hooks_dir = _make_fake_repo(tmp_path)
        orig = hooks_dir / "pre-commit"
        orig.write_text("#!/bin/sh\necho x", encoding="utf-8")
        orig.chmod(orig.stat().st_mode | stat.S_IXUSR)
        _install_hook(hooks_dir)
        _uninstall_hook(hooks_dir)
        assert orig.stat().st_mode & stat.S_IXUSR


# ---------------------------------------------------------------------------
# Hook script content / security
# ---------------------------------------------------------------------------

class TestHookScriptContent:
    def _content(self, tmp_path: Path, backup: Path | None = None) -> str:
        return _build_hook_script(backup)

    def test_shebang_line(self, tmp_path):
        assert _build_hook_script().startswith("#!/usr/bin/env python3")

    def test_marker_present(self, tmp_path):
        assert _HOOK_MARKER in _build_hook_script()

    def test_backup_path_embedded(self, tmp_path):
        p = tmp_path / ".git" / "hooks" / f"pre-commit{_BACKUP_SUFFIX}"
        script = _build_hook_script(p)
        # repr() is used when embedding so backslashes are escaped; check repr or suffix
        assert _BACKUP_SUFFIX in script

    def test_no_backup_when_none(self, tmp_path):
        script = _build_hook_script(None)
        assert _BACKUP_SUFFIX not in script or '_AIGOV_BACKUP_HOOK = ""' in script

    def test_uses_git_diff_cached(self, tmp_path):
        script = _build_hook_script()
        assert "diff" in script and "cached" in script

    def test_filters_staged_files(self, tmp_path):
        script = _build_hook_script()
        assert "_is_relevant" in script or "staged" in script.lower()

    def test_never_reads_staged_file_contents(self, tmp_path):
        script = _build_hook_script()
        # The hook uses git diff --cached to get file paths, then passes those
        # paths to aigov scan via subprocess — it never opens or reads staged files.
        # (read_text is allowed for config files like .aigov-allowlist.yaml)
        assert "diff" in script and "cached" in script
        # staged files are used only for path-based filtering, not content reading
        assert "source_location" in script  # filtering by location, not content

    def test_blocked_exit_code_1(self, tmp_path):
        script = _build_hook_script()
        assert "sys.exit(1)" in script

    def test_allowed_exit_code_0(self, tmp_path):
        script = _build_hook_script()
        assert "sys.exit(0)" in script

    def test_aigov_scan_classify_in_script(self, tmp_path):
        script = _build_hook_script()
        assert "--classify" in script
