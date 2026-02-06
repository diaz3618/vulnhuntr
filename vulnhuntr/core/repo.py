"""
Repository Operations
=====================

Handles repository scanning, file discovery, and content extraction.

The RepoOps class provides methods for:
- Finding Python files in a repository
- Detecting network-related files (potential entry points)
- Reading README content
- Filtering out test files, documentation, etc.
"""

import re
from pathlib import Path
from typing import Generator, List, Optional


class RepoOps:
    """Repository operations for vulnerability scanning.

    Handles file discovery and content extraction for Python projects.
    Automatically filters out test files, examples, documentation,
    and virtual environments.

    Attributes:
        repo_path: Root path of the repository to scan
        to_exclude: Set of path patterns to exclude
        file_names_to_exclude: List of filename patterns to exclude
        compiled_patterns: Compiled regex patterns for network detection

    Example:
        >>> repo = RepoOps("/path/to/project")
        >>> files = list(repo.get_relevant_py_files())
        >>> network_files = list(repo.get_network_related_files(files))
    """

    # Path patterns to exclude from scanning
    DEFAULT_EXCLUDE_PATHS = {
        "/setup.py",
        "/test",
        "/example",
        "/docs",
        "/site-packages",
        ".venv",
        "virtualenv",
        "/dist",
    }

    # Filename patterns to exclude
    DEFAULT_EXCLUDE_FILENAMES = ["test_", "conftest", "_test.py"]

    # Regex patterns for detecting network-related code
    NETWORK_PATTERNS = [
        # Async
        r"async\sdef\s\w+\(.*?request",
        # Gradio
        r"gr.Interface\(.*?\)",
        r"gr.Interface\.launch\(.*?\)",
        # Flask
        r"@app\.route\(.*?\)",
        r"@blueprint\.route\(.*?\)",
        r"class\s+\w+\(MethodView\):",
        r"@(?:app|blueprint)\.add_url_rule\(.*?\)",
        # FastAPI
        r"@app\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)",
        r"@router\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)",
        # Django
        r"url\(.*?\)",
        r"re_path\(.*?\)",
        r"@channel_layer\.group_add",
        r"@database_sync_to_async",
        # Pyramid
        r"@view_config\(.*?\)",
        # Bottle
        r"@(?:route|get|post|put|delete|patch)\(.*?\)",
        # Tornado
        r"class\s+\w+\((?:RequestHandler|WebSocketHandler)\):",
        r"@tornado\.gen\.coroutine",
        r"@tornado\.web\.asynchronous",
        # WebSockets
        r"websockets\.serve\(.*?\)",
        r"@websocket\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
        # aiohttp
        r"app\.router\.add_(?:get|post|put|delete|patch|head|options)\(.*?\)",
        r"@routes\.(?:get|post|put|delete|patch|head|options)\(.*?\)",
        # Sanic
        r"@app\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
        r"@blueprint\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
        # Falcon
        r"app\.add_route\(.*?\)",
        # CherryPy
        r"@cherrypy\.expose",
        # web2py
        r"def\s+\w+\(\):\s*return\s+dict\(",
        # Quart (ASGI version of Flask)
        r"@app\.route\(.*?\)",
        r"@blueprint\.route\(.*?\)",
        # Starlette (which FastAPI is based on)
        r"@app\.route\(.*?\)",
        r"Route\(.*?\)",
        # Responder
        r"@api\.route\(.*?\)",
        # Hug
        r"@hug\.(?:get|post|put|delete|patch|options|head)\(.*?\)",
        # Dash (for analytical web applications)
        r"@app\.callback\(.*?\)",
        # GraphQL entry points
        r"class\s+\w+\(graphene\.ObjectType\):",
        r"@strawberry\.type",
        # Generic decorators that might indicate custom routing
        r"@route\(.*?\)",
        r"@endpoint\(.*?\)",
        r"@api\.\w+\(.*?\)",
        # AWS Lambda handlers
        r"def\s+lambda_handler\(event,\s*context\):",
        r"def\s+handler\(event,\s*context\):",
        # Azure Functions
        r"def\s+\w+\(req:\s*func\.HttpRequest\)\s*->",
        # Google Cloud Functions
        r"def\s+\w+\(request\):",
        # Server startup code
        r"app\.run\(.*?\)",
        r"serve\(app,.*?\)",
        r"uvicorn\.run\(.*?\)",
        r"application\.listen\(.*?\)",
        r"run_server\(.*?\)",
        r"server\.start\(.*?\)",
        r"app\.listen\(.*?\)",
        r"httpd\.serve_forever\(.*?\)",
        r"tornado\.ioloop\.IOLoop\.current\(\)\.start\(\)",
        r"asyncio\.run\(.*?\.serve\(.*?\)\)",
        r"web\.run_app\(.*?\)",
        r"WSGIServer\(.*?\)\.serve_forever\(\)",
        r"make_server\(.*?\)\.serve_forever\(\)",
        r"cherrypy\.quickstart\(.*?\)",
        r"execute_from_command_line\(.*?\)",
        r"gunicorn\.app\.wsgiapp\.run\(\)",
        r"waitress\.serve\(.*?\)",
        r"hypercorn\.run\(.*?\)",
        r"daphne\.run\(.*?\)",
        r"werkzeug\.serving\.run_simple\(.*?\)",
        r"gevent\.pywsgi\.WSGIServer\(.*?\)\.serve_forever\(\)",
        r"grpc\.server\(.*?\)\.start\(\)",
        r"app\.start_server\(.*?\)",
        r"Server\(.*?\)\.run\(\)",
    ]

    def __init__(
        self,
        repo_path: Path | str,
        exclude_paths: Optional[set] = None,
        exclude_filenames: Optional[List[str]] = None,
    ) -> None:
        """Initialize repository operations.

        Args:
            repo_path: Path to the repository root
            exclude_paths: Custom path patterns to exclude (optional)
            exclude_filenames: Custom filename patterns to exclude (optional)
        """
        self.repo_path = Path(repo_path)
        self.to_exclude = exclude_paths or self.DEFAULT_EXCLUDE_PATHS
        self.file_names_to_exclude = exclude_filenames or self.DEFAULT_EXCLUDE_FILENAMES

        # Compile patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern) for pattern in self.NETWORK_PATTERNS
        ]

    def get_readme_content(self) -> Optional[str]:
        """Get README content from the repository.

        Searches for README files in common formats (md, rst) with
        case-insensitive matching.

        Returns:
            README content as string, or None if not found
        """
        # Prioritized patterns for README files
        prioritized_patterns = [
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]",
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]",
        ]

        # First, look for README.md or README.rst in the root directory
        for pattern in prioritized_patterns:
            for readme in self.repo_path.glob(pattern):
                try:
                    with readme.open(encoding="utf-8") as f:
                        return f.read()
                except (OSError, UnicodeDecodeError):
                    continue

        # If no README.md or README.rst is found, try other extensions
        for readme in self.repo_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
            try:
                with readme.open(encoding="utf-8") as f:
                    return f.read()
            except (OSError, UnicodeDecodeError):
                continue

        return None

    def get_relevant_py_files(self) -> Generator[Path, None, None]:
        """Get all Python files excluding tests, examples, docs, etc.

        Yields:
            Path objects for each relevant Python file
        """
        for f in self.repo_path.rglob("*.py"):
            # Convert RELATIVE path to string with forward slashes, lowercase
            # This ensures exclusion patterns work regardless of the repo's location
            try:
                rel_path = f.relative_to(self.repo_path)
                f_str = "/" + str(rel_path).replace("\\", "/").lower()
            except ValueError:
                # If relative_to fails, skip this file
                continue

            # Check if any exclusion pattern matches
            if any(exclude in f_str for exclude in self.to_exclude):
                continue

            # Check if the filename should be excluded
            if any(fn in f.name for fn in self.file_names_to_exclude):
                continue

            yield f

    def get_network_related_files(
        self, files: List[Path]
    ) -> Generator[Path, None, None]:
        """Filter files to only those containing network-related code.

        Identifies files that likely contain web endpoints, API handlers,
        or other network-facing code that could be vulnerable.

        Args:
            files: List of Python file paths to check

        Yields:
            Path objects for files containing network-related patterns
        """
        for py_f in files:
            try:
                with py_f.open(encoding="utf-8") as f:
                    content = f.read()
                if any(
                    re.search(pattern, content) for pattern in self.compiled_patterns
                ):
                    yield py_f
            except (OSError, UnicodeDecodeError):
                continue

    def get_files_to_analyze(self, analyze_path: Optional[Path] = None) -> List[Path]:
        """Get list of files to analyze based on optional path filter.

        Args:
            analyze_path: Specific file or directory to analyze (optional).
                         If None, analyzes the entire repository.

        Returns:
            List of Path objects for files to analyze

        Raises:
            FileNotFoundError: If specified analyze_path doesn't exist
        """
        path_to_analyze = analyze_path or self.repo_path

        if path_to_analyze.is_file():
            return [path_to_analyze]
        elif path_to_analyze.is_dir():
            return list(path_to_analyze.rglob("*.py"))
        else:
            raise FileNotFoundError(
                f"Specified analyze path does not exist: {path_to_analyze}"
            )
