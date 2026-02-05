import json
import os
import re
import argparse
import structlog
from vulnhuntr.symbol_finder import SymbolExtractor
from vulnhuntr.LLMs import Claude, ChatGPT, Ollama, CostCallback
from vulnhuntr.prompts import *
from vulnhuntr.cost_tracker import (
    CostTracker, 
    BudgetEnforcer, 
    estimate_analysis_cost, 
    print_dry_run_report,
)
from vulnhuntr.checkpoint import (
    AnalysisCheckpoint,
    print_resume_info,
)
from vulnhuntr.config import (
    VulnhuntrConfig,
    load_config,
    merge_config_with_args,
)
from rich import print
from rich.console import Console
from typing import List, Generator, Optional
from enum import Enum
from pathlib import Path
from pydantic_xml import BaseXmlModel, element
from pydantic import BaseModel, Field
import dotenv

dotenv.load_dotenv()

structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.WriteLoggerFactory(
        file=Path('vulnhuntr').with_suffix(".log").open("wt")
    )
)

import faulthandler
faulthandler.enable()

log = structlog.get_logger("vulnhuntr")

class VulnType(str, Enum):
    LFI = "LFI"
    RCE = "RCE"
    SSRF = "SSRF"
    AFO = "AFO"
    SQLI = "SQLI"
    XSS = "XSS"
    IDOR = "IDOR"

class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")

class Response(BaseModel):
    scratchpad: str = Field(description="Your step-by-step analysis process. Output in plaintext with no line breaks.")
    analysis: str = Field(description="Your final analysis. Output in plaintext with no line breaks.")
    poc: str = Field(description="Proof-of-concept exploit, if applicable.")
    confidence_score: int = Field(description="0-10, where 0 is no confidence and 10 is absolute certainty because you have the entire user input to server output code path.")
    vulnerability_types: List[VulnType] = Field(description="The types of identified vulnerabilities")
    context_code: List[ContextCode] = Field(description="List of context code items requested for analysis, one function or class name per item. No standard library or third-party package code.")

class ReadmeContent(BaseXmlModel, tag="readme_content"):
    content: str

class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    readme_summary: str

class Instructions(BaseXmlModel, tag="instructions"):
    instructions: str

class ResponseFormat(BaseXmlModel, tag="response_format"):
    response_format: str

class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    analysis_approach: str

class Guidelines(BaseXmlModel, tag="guidelines"):
    guidelines: str

class FileCode(BaseXmlModel, tag="file_code"):
    file_path: str = element()
    file_source: str = element()

class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    previous_analysis: str

class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    example_bypasses: str

class CodeDefinition(BaseXmlModel, tag="code"):
    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()

class CodeDefinitions(BaseXmlModel, tag="context_code"):
    definitions: List[CodeDefinition] = []

class RepoOps:
    def __init__(self, repo_path: Path | str ) -> None:
        self.repo_path = Path(repo_path)
        self.to_exclude = {'/setup.py', '/test', '/example', '/docs', '/site-packages', '.venv', 'virtualenv', '/dist'}
        self.file_names_to_exclude = ['test_', 'conftest', '_test.py']

        patterns = [
            #Async
            r'async\sdef\s\w+\(.*?request',

            # Gradio
            r'gr.Interface\(.*?\)',
            r'gr.Interface\.launch\(.*?\)',

            # Flask
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',
            r'class\s+\w+\(MethodView\):',
            r'@(?:app|blueprint)\.add_url_rule\(.*?\)',

            # FastAPI
            r'@app\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',
            r'@router\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',

            # Django
            r'url\(.*?\)', #Too broad?
            r're_path\(.*?\)',
            r'@channel_layer\.group_add',
            r'@database_sync_to_async',

            # Pyramid
            r'@view_config\(.*?\)',

            # Bottle
            r'@(?:route|get|post|put|delete|patch)\(.*?\)',

            # Tornado
            r'class\s+\w+\((?:RequestHandler|WebSocketHandler)\):',
            r'@tornado\.gen\.coroutine',
            r'@tornado\.web\.asynchronous',

            #WebSockets
            r'websockets\.serve\(.*?\)',
            r'@websocket\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # aiohttp
            r'app\.router\.add_(?:get|post|put|delete|patch|head|options)\(.*?\)',
            r'@routes\.(?:get|post|put|delete|patch|head|options)\(.*?\)',

            # Sanic
            r'@app\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',
            r'@blueprint\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # Falcon
            r'app\.add_route\(.*?\)',

            # CherryPy
            r'@cherrypy\.expose',

            # web2py
            r'def\s+\w+\(\):\s*return\s+dict\(',

            # Quart (ASGI version of Flask)
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',

            # Starlette (which FastAPI is based on)
            r'@app\.route\(.*?\)',
            r'Route\(.*?\)',

            # Responder
            r'@api\.route\(.*?\)',

            # Hug
            r'@hug\.(?:get|post|put|delete|patch|options|head)\(.*?\)',

            # Dash (for analytical web applications)
            r'@app\.callback\(.*?\)',

            # GraphQL entry points
            r'class\s+\w+\(graphene\.ObjectType\):',
            r'@strawberry\.type',

            # Generic decorators that might indicate custom routing
            r'@route\(.*?\)',
            r'@endpoint\(.*?\)',
            r'@api\.\w+\(.*?\)',

            # AWS Lambda handlers (which could be used with API Gateway)
            r'def\s+lambda_handler\(event,\s*context\):',
            r'def\s+handler\(event,\s*context\):',

            # Azure Functions
            r'def\s+\w+\(req:\s*func\.HttpRequest\)\s*->',

            # Google Cloud Functions
            r'def\s+\w+\(request\):'

            # Server startup code
            r'app\.run\(.*?\)',
            r'serve\(app,.*?\)',
            r'uvicorn\.run\(.*?\)',
            r'application\.listen\(.*?\)',
            r'run_server\(.*?\)',
            r'server\.start\(.*?\)',
            r'app\.listen\(.*?\)',
            r'httpd\.serve_forever\(.*?\)',
            r'tornado\.ioloop\.IOLoop\.current\(\)\.start\(\)',
            r'asyncio\.run\(.*?\.serve\(.*?\)\)',
            r'web\.run_app\(.*?\)',
            r'WSGIServer\(.*?\)\.serve_forever\(\)',
            r'make_server\(.*?\)\.serve_forever\(\)',
            r'cherrypy\.quickstart\(.*?\)',
            r'execute_from_command_line\(.*?\)',  # Django's manage.py
            r'gunicorn\.app\.wsgiapp\.run\(\)',
            r'waitress\.serve\(.*?\)',
            r'hypercorn\.run\(.*?\)',
            r'daphne\.run\(.*?\)',
            r'werkzeug\.serving\.run_simple\(.*?\)',
            r'gevent\.pywsgi\.WSGIServer\(.*?\)\.serve_forever\(\)',
            r'grpc\.server\(.*?\)\.start\(\)',
            r'app\.start_server\(.*?\)',  # Sanic
            r'Server\(.*?\)\.run\(\)',    # Bottle
        ]

        # Compile the patterns for efficiency
        self.compiled_patterns = [re.compile(pattern) for pattern in patterns]

    def get_readme_content(self) -> str:
        # Use glob to find README.md or README.rst in a case-insensitive manner in the root directory
        prioritized_patterns = ["[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]", "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]"]
        
        # First, look for README.md or README.rst in the root directory with case insensitivity
        for pattern in prioritized_patterns:
            for readme in self.repo_path.glob(pattern):
                with readme.open(encoding='utf-8') as f:
                    return f.read()
                
        # If no README.md or README.rst is found, look for any README file with supported extensions
        for readme in self.repo_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
            with readme.open(encoding='utf-8') as f:
                return f.read()
        
        return

    def get_relevant_py_files(self) -> Generator[Path, None, None]:
        """Gets all Python files in a repo minus the ones in the exclude list (test, example, doc, docs)"""
        files = []
        for f in self.repo_path.rglob("*.py"):
            # Convert the path to a string with forward slashes
            f_str = str(f).replace('\\', '/')
            
            # Lowercase the string for case-insensitive matching
            f_str = f_str.lower()

            # Check if any exclusion pattern matches a substring of the full path
            if any(exclude in f_str for exclude in self.to_exclude):
                continue

            # Check if the file name should be excluded
            if any(fn in f.name for fn in self.file_names_to_exclude):
                continue
            
            files.append(f)

        return files

    def get_network_related_files(self, files: List) -> Generator[Path, None, None]:
        for py_f in files:
            with py_f.open(encoding='utf-8') as f:
                content = f.read()
            if any(re.search(pattern, content) for pattern in self.compiled_patterns):
                yield py_f

    def get_files_to_analyze(self, analyze_path: Path | None = None) -> List[Path]:
        path_to_analyze = analyze_path or self.repo_path
        if path_to_analyze.is_file():
            return [ path_to_analyze ]
        elif path_to_analyze.is_dir():
            return path_to_analyze.rglob('*.py')
        else:
            raise FileNotFoundError(f"Specified analyze path does not exist: {path_to_analyze}")

def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    """
    https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
    """
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list

def initialize_llm(
    llm_arg: str, 
    system_prompt: str = "",
    cost_callback: Optional[CostCallback] = None,
) -> Claude | ChatGPT | Ollama:
    """Initialize LLM client with optional cost tracking callback.
    
    Args:
        llm_arg: LLM provider ('claude', 'gpt', 'ollama')
        system_prompt: System prompt to use
        cost_callback: Optional callback for cost tracking
        
    Returns:
        Initialized LLM client
    """
    llm_arg = llm_arg.lower()
    if llm_arg == 'claude':
        anth_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        anth_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        llm = Claude(anth_model, anth_base_url, system_prompt, cost_callback)
    elif llm_arg == 'gpt':
        openai_model = os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        llm = ChatGPT(openai_model, openai_base_url, system_prompt, cost_callback)
    elif llm_arg == 'ollama':
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
        ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate")
        llm = Ollama(ollama_model, ollama_base_url, system_prompt, cost_callback)
    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama")
    return llm

def get_model_name(llm_arg: str) -> str:
    """Get the model name for the given LLM provider from environment."""
    llm_arg = llm_arg.lower()
    if llm_arg == 'claude':
        return os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    elif llm_arg == 'gpt':
        return os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
    elif llm_arg == 'ollama':
        return os.getenv("OLLAMA_MODEL", "llama3")
    return "unknown"

def print_readable(report: Response) -> None:
    for attr, value in vars(report).items():
        print(f"{attr}:")
        if isinstance(value, str):
            # For multiline strings, add indentation
            lines = value.split('\n')
            for line in lines:
                print(f"  {line}")
        elif isinstance(value, list):
            # For lists, print each item on a new line
            for item in value:
                print(f"  - {item}")
        else:
            # For other types, just print the value
            print(f"  {value}")
        print('-' * 40)
        print()  # Add an empty line between attributes

def run():
    parser = argparse.ArgumentParser(description='Analyze a GitHub project for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.')
    parser.add_argument('-r', '--root', type=str, required=True, help='Path to the root directory of the project')
    parser.add_argument('-a', '--analyze', type=str, help='Specific path or file within the project to analyze')
    parser.add_argument('-l', '--llm', type=str, choices=['claude', 'gpt', 'ollama'], default='claude', help='LLM client to use (default: claude)')
    parser.add_argument('-v', '--verbosity', action='count', default=0, help='Increase output verbosity (-v for INFO, -vv for DEBUG)')
    
    # Cost management arguments
    parser.add_argument('--dry-run', action='store_true', help='Estimate costs without running analysis')
    parser.add_argument('--budget', type=float, help='Maximum budget in USD (stops analysis when exceeded)')
    parser.add_argument('--resume', type=str, nargs='?', const='.vulnhuntr_checkpoint', help='Resume from checkpoint (default: .vulnhuntr_checkpoint)')
    parser.add_argument('--no-checkpoint', action='store_true', help='Disable checkpointing')
    
    args = parser.parse_args()
    
    console = Console()
    
    # Load configuration from .vulnhuntr.yaml (if present)
    config = load_config(start_dir=Path(args.root))
    config = merge_config_with_args(config, args)
    
    # Apply config to args where config provides defaults
    if config.budget and args.budget is None:
        args.budget = config.budget
    if config.provider and not args.llm:
        args.llm = config.provider
    if config.dry_run and not args.dry_run:
        args.dry_run = config.dry_run

    repo = RepoOps(args.root)
    code_extractor = SymbolExtractor(args.root)
    # Get repo files that don't include stuff like tests and documentation
    files = list(repo.get_relevant_py_files())

    # User specified --analyze flag
    if args.analyze:
        # Determine the path to analyze
        analyze_path = Path(args.analyze)

        # If the path is absolute, use it as is, otherwise join it with the root path so user can specify relative paths
        if analyze_path.is_absolute():
            files_to_analyze = list(repo.get_files_to_analyze(analyze_path))
        else:
            files_to_analyze = list(repo.get_files_to_analyze(Path(args.root) / analyze_path))

    # Analyze the entire project for network-related files
    else:
        files_to_analyze = list(repo.get_network_related_files(files))
    
    # Get model name for cost estimation
    model_name = get_model_name(args.llm)
    
    # Handle --dry-run: Estimate costs and exit
    if args.dry_run:
        console.print("\n[bold cyan]Running cost estimation (dry-run mode)...[/bold cyan]")
        estimate = estimate_analysis_cost(files_to_analyze, model_name)
        print_dry_run_report(estimate)
        return
    
    # Initialize cost tracker
    cost_tracker = CostTracker()
    
    # Initialize budget enforcer if budget specified
    budget_enforcer = BudgetEnforcer(
        max_budget_usd=args.budget,
        warning_threshold=0.8,
    ) if args.budget else None
    
    # Create cost callback for LLM
    def cost_callback(
        input_tokens: int,
        output_tokens: int,
        model: str,
        file_path: Optional[str],
        call_type: str,
    ) -> None:
        cost_tracker.track_call(input_tokens, output_tokens, model, file_path, call_type)
    
    # Initialize checkpoint
    checkpoint = AnalysisCheckpoint(
        checkpoint_dir=Path(args.resume) if args.resume else Path(".vulnhuntr_checkpoint"),
        save_frequency=5,
        enabled=not args.no_checkpoint,
    )
    
    # Handle --resume: Check for existing checkpoint
    if args.resume:
        if checkpoint.can_resume():
            print_resume_info(checkpoint)
            console.print("\n[bold green]Resuming from checkpoint...[/bold green]\n")
            checkpoint_data = checkpoint.resume(cost_tracker)
            
            # Filter out already completed files
            completed_set = set(checkpoint_data.completed_files)
            files_to_analyze = [f for f in files_to_analyze if str(f) not in completed_set]
            
            console.print(f"[dim]Skipping {len(completed_set)} already completed files[/dim]")
            console.print(f"[dim]Remaining files to analyze: {len(files_to_analyze)}[/dim]\n")
        else:
            console.print("[yellow]No checkpoint found to resume. Starting fresh analysis.[/yellow]\n")
    
    # Start checkpoint tracking (if not resuming)
    if not args.resume or not checkpoint.can_resume():
        checkpoint.start(
            repo_path=Path(args.root),
            files_to_analyze=files_to_analyze,
            model=model_name,
            cost_tracker=cost_tracker,
        )
    
    llm = initialize_llm(args.llm, cost_callback=cost_callback)

    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        llm.set_context(file_path=None, call_type="readme")
        summary = llm.chat(
            (ReadmeContent(content=readme_content).to_xml() + b'\n' +
            Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE).to_xml()
            ).decode()
        )
        summary = extract_between_tags("summary", summary)[0]
        log.info("README summary complete", summary=summary)
    else:
        log.warning("No README summary found")
        summary = ''
    
    # Initialize the system prompt with the README summary
    system_prompt = (Instructions(instructions=SYS_PROMPT_TEMPLATE).to_xml() + b'\n' +
                ReadmeSummary(readme_summary=summary).to_xml()
                ).decode()
    
    llm = initialize_llm(args.llm, system_prompt, cost_callback)
    
    # Track analysis success for checkpoint finalization
    analysis_success = True

    # files_to_analyze is either a list of all network-related files or a list containing a single file/dir to analyze
    for py_f in files_to_analyze:
        # Check budget before starting file analysis
        if budget_enforcer and not budget_enforcer.check(cost_tracker.total_cost):
            console.print(f"\n[bold red]Budget limit reached (${args.budget:.2f}). Stopping analysis.[/bold red]")
            console.print(f"[dim]Progress saved to checkpoint. Use --resume to continue with higher budget.[/dim]")
            analysis_success = False
            break
        
        # Set checkpoint current file
        checkpoint.set_current_file(py_f)
        
        log.info(f"Performing initial analysis", file=str(py_f))
        
        # Set LLM context for cost tracking
        llm.set_context(file_path=str(py_f), call_type="initial")

        # This is the Initial analysis
        with py_f.open(encoding='utf-8') as f:
            content = f.read()
            if not len(content):
                continue

            print(f"\nAnalyzing {py_f}")
            print('-' * 40 +'\n')

            user_prompt =(
                    FileCode(file_path=str(py_f), file_source=content).to_xml() + b'\n' +
                    Instructions(instructions=INITIAL_ANALYSIS_PROMPT_TEMPLATE).to_xml() + b'\n' +
                    AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml() + b'\n' +
                    PreviousAnalysis(previous_analysis='').to_xml() + b'\n' +
                    Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml() + b'\n' +
                    ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4
                    )
                ).to_xml()
            ).decode()

            initial_analysis_report: Response = llm.chat(user_prompt, response_model=Response, max_tokens=8192)
            log.info("Initial analysis complete", report=initial_analysis_report.model_dump())

            print_readable(initial_analysis_report)

            # Secondary analysis
            if initial_analysis_report.confidence_score > 0 and len(initial_analysis_report.vulnerability_types):

                for vuln_type in initial_analysis_report.vulnerability_types:

                    # Do not fetch the context code on the first pass of the secondary analysis because the context will be from the general analysis
                    stored_code_definitions = {}
                    definitions = CodeDefinitions(definitions=[])
                    same_context = False

                    # Don't include the initial analysis or the first iteration of the secondary analysis in the user_prompt
                    previous_analysis = ''
                    previous_context_amount = 0

                    for i in range(7):
                        # Check budget during iterations
                        if budget_enforcer and not budget_enforcer.check(
                            cost_tracker.total_cost,
                            cost_tracker.get_file_cost(str(py_f))
                        ):
                            console.print(f"\n[bold yellow]Budget limit reached during secondary analysis.[/bold yellow]")
                            break
                        
                        log.info(f"Performing vuln-specific analysis", iteration=i, vuln_type=vuln_type, file=py_f)
                        
                        # Set LLM context for secondary analysis
                        llm.set_context(file_path=str(py_f), call_type="secondary")

                        # Only lookup context code and previous analysis on second pass and onwards
                        if i > 0:
                            previous_context_amount = len(stored_code_definitions)
                            previous_analysis = secondary_analysis_report.analysis

                            for context_item in secondary_analysis_report.context_code:
                                # Make sure bot isn't requesting the same code multiple times
                                if context_item.name not in stored_code_definitions:
                                    name = context_item.name
                                    code_line = context_item.code_line
                                    match = code_extractor.extract(name, code_line, files)
                                    if match:
                                        stored_code_definitions[name] = match

                            code_definitions = list(stored_code_definitions.values())
                            definitions = CodeDefinitions(definitions=code_definitions)
                            
                            if args.verbosity > 1:
                                for definition in definitions.definitions:
                                    if '\n' in definition.source:
                                        lines = definition.source.split('\n')
                                        snippet = lines[0] + '\n' + lines[1]
                                    else:
                                        snippet = definition.source[:75]
                                    
                                    print(f"Name: {definition.name}")
                                    print(f"Context search: {definition.context_name_requested}")
                                    print(f"File Path: {definition.file_path}")
                                    print(f"First two lines from source: {snippet}\n")

                        vuln_specific_user_prompt = (
                            FileCode(file_path=str(py_f), file_source=content).to_xml() + b'\n' +
                            definitions.to_xml() + b'\n' +  # These are all the requested context functions and classes
                            ExampleBypasses(
                                example_bypasses='\n'.join(VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['bypasses'])
                            ).to_xml() + b'\n' +
                            Instructions(instructions=VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['prompt']).to_xml() + b'\n' +
                            AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml() + b'\n' +
                            PreviousAnalysis(previous_analysis=previous_analysis).to_xml() + b'\n' +
                            Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml() + b'\n' +
                            ResponseFormat(
                                response_format=json.dumps(
                                    Response.model_json_schema(), indent=4
                                )
                            ).to_xml()
                        ).decode()

                        secondary_analysis_report: Response = llm.chat(vuln_specific_user_prompt, response_model=Response, max_tokens=8192)
                        log.info("Secondary analysis complete", secondary_analysis_report=secondary_analysis_report.model_dump())

                        if args.verbosity > 0:
                            print_readable(secondary_analysis_report)

                        if not len(secondary_analysis_report.context_code):
                            log.debug("No new context functions or classes found")
                            if args.verbosity == 0:
                                print_readable(secondary_analysis_report)
                            break
                        
                        # Check if any new context code is requested
                        if previous_context_amount >= len(stored_code_definitions) and i > 0:
                            # Let it request the same context once, then on the second time it requests the same context, break
                            if same_context:
                                log.debug("No new context functions or classes requested")
                                if args.verbosity == 0:
                                    print_readable(secondary_analysis_report)
                                break
                            same_context = True
                            log.debug("No new context functions or classes requested")
                    pass
        
        # Mark file as complete in checkpoint
        checkpoint.mark_file_complete(py_f, initial_analysis_report.model_dump() if initial_analysis_report else None)
    
    # Finalize checkpoint
    checkpoint.finalize(success=analysis_success and len(files_to_analyze) > 0)
    
    # Print cost summary
    console.print(cost_tracker.get_detailed_report())
    
    # Log final cost summary
    log.info("Analysis complete", cost_summary=cost_tracker.get_summary())

if __name__ == '__main__':
    run()
