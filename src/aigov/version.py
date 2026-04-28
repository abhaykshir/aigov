"""Single source of truth for the aigov package version.

Bump this string when cutting a release. ``pyproject.toml`` reads this
attribute via ``[tool.setuptools.dynamic]`` so the build system stays in
sync without a second edit.
"""

__version__ = "0.5.2"
