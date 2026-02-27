"""Sphinx configuration for BinaryAnalysis-MCP documentation."""

import os
import sys

# -- Path setup ---------------------------------------------------------------
# Add project root so autodoc can import the source modules.
sys.path.insert(0, os.path.abspath(".."))

# -- Project information ------------------------------------------------------
project = "BinaryAnalysis-MCP"
copyright = "2025, Ap3x"
author = "Ap3x"

# -- General configuration ----------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "myst_parser",
]

# Markdown support
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output --------------------------------------------------
html_theme = "furo"
html_static_path = []
html_title = "BinaryAnalysis-MCP"

# -- autodoc settings ---------------------------------------------------------
autodoc_member_order = "bysource"
autodoc_typehints = "description"
