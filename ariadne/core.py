from typing import Dict, List, Tuple, Optional
from multiprocessing.pool import ThreadPool
from pathlib import Path
import socket
import time
import networkx as nx

from binaryninja import BinaryView, Function, BackgroundTaskThread, get_choice_input

from .analysis.ariadne_function import AriadneFunction, get_analyzed_function
from .util_funcs import short_name, log_info, log_warn, log_error, func_name, get_repo_dir
from .target import AriadneTarget
from .server import AriadneServer

try:
    import bncov
    coverage_enabled = True
except ImportError:
    try:
        import ForAllSecure_bncov as bncov
        coverage_enabled = True
    except ImportError:
        coverage_enabled = False


class BackgroundAnalysis(BackgroundTaskThread):
    """Worker thread that actually does the analysis via AriadneTarget"""
    def __init__(self, bv, core, num_workers=4):
        super().__init__(initial_progress_text='Running function analysis', can_cancel=True)
        self.bv = bv
        self.core = core
        self.num_workers = num_workers

    def run(self):
        analysis_start_time = time.time()
        target = AriadneTarget(self.bv, self.core)

        # Multithreaded version of target.do_analysis
        function_list = list(self.bv.functions)
        target.function_list = function_list
        num_funcs = len(function_list)

        # Function level analysis
        self.progress = f'ARIADNE: Analyzing functions... {0}/{num_funcs}'
        start_time = time.time()
        with ThreadPool(self.num_workers) as pool:
            for i, ariadne_function in enumerate(pool.imap(get_analyzed_function, function_list, 8)):
                self.progress = f'ARIADNE: Analyzing functions... {i+1}/{num_funcs}'
                target.function_dict[ariadne_function.function] = ariadne_function
                if self.cancelled:
                    break
        duration = time.time() - start_time
        log_info(f'Function analysis ({self.num_workers} threads) took {duration:.2f} seconds')

        # Target-level analysis
        if not self.cancelled:
            self.progress = f'ARIADNE: Generating Callgraph...'
            start_time = time.time()
            target.generate_callgraph()
            duration = time.time() - start_time
            log_info(f'Generating callgraph took {duration:.2f} seconds')
        if not self.cancelled:
            self.progress = f'ARIADNE: Graph analysis...'
            start_time = time.time()
            target.do_graph_analysis()
            duration = time.time() - start_time
            log_info(f'Graph analysis took {duration:.2f} seconds')
        if not self.cancelled and coverage_enabled:
            covdb = bncov.get_covdb(self.bv)
            num_files = len(covdb.coverage_files)
            if num_files:
                self.progress = f'ARIADNE: Coverage analysis...'
                start_time = time.time()
                target.init_coverage_analysis(covdb)

                # Wrapper function to do a parallel mapping over function list
                def coverage_analysis_wrapper(bn_func):
                    target.do_function_coverage_analysis(bn_func)

                with ThreadPool(self.num_workers) as pool:
                    for i, _ in enumerate(pool.imap(coverage_analysis_wrapper, function_list, 8)):
                        self.progress = f'ARIADNE: Function coverage analysis... {i+1}/{num_funcs}'
                        if self.cancelled:
                            break

                target.mark_coverage_analysis_finished()
                duration = time.time() - start_time
                log_info(f'Coverage analysis took {duration:.2f} seconds')

        # If we make it here without canceling, we're done
        if not self.cancelled:
            self.progress = f'ARIADNE: Finishing analysis...'

            # Avoid race: add result to core, then pop history and add to it
            self.core.add_analysis_result(self.bv, target)
            visited_funcs = set(self.core.pop_history_cache(self.bv))
            # Currently only setting "is_visited bit", only need to visit each once
            target.mark_visited_set(visited_funcs)

            duration = time.time() - analysis_start_time
            log_info(f'Analysis for "{short_name(self.bv)}" complete in {duration:.2f} seconds')
        else:
            duration = time.time() - start_time
            log_info(f'Analysis for "{short_name(self.bv)}" cancelled after {duration:.2f} seconds')


class AriadneCore():
    def __init__(self, ip='127.0.0.1', http_port=8800, websocket_port=7890):
        self.ip = ip
        self.http_port = self.find_next_open_port(http_port)
        self.websocket_port = self.find_next_open_port(websocket_port)
        self.bvs = []
        self.analysis_tasks: Dict[BinaryView, BackgroundAnalysis] = {}
        self.current_function_map: Dict[BinaryView, Function] = {}
        self.targets: Dict[BinaryView, AriadneTarget] = {}
        self.history_cache: Dict[BinaryView, List[Function]] = {}
        self.server = AriadneServer(self, ip, self.http_port, self.websocket_port)
        self.graph_frozen = False
        self.cache_dir = get_repo_dir().joinpath('cache')
        self.current_bv: Optional[BinaryView] = None
        self.force_load_from_cache = False
        self.force_cache_overwrite = False
        # FUTURE: expose these as plugin settings
        self.neighborhood_hops = 3
        self.max_nodes_to_show = 50
        log_info(f'Instantiated AriadneCore')
        if not coverage_enabled:
            log_info(f'Download the bncov plugin in order to enable coverage analysis')

    def find_next_open_port(self, port: int) -> int:
        """Find the next best port for the server.

        NOTE: There will only be one server per process, but could be more than
        one window, each with its own separate Python interpreter
        """
        MAX_PORT = 65535
        orig_port = port

        while port <= MAX_PORT:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('localhost', port)) != 0:
                    break
            port += 1

        if port > MAX_PORT:
            raise Exception(f'No open ports between {orig_port} and {MAX_PORT}')

        return port

    def start_server(self):
        self.server.start_webserver()
        self.server.start_websocket_server()

    def get_cache_target(self, bv: BinaryView):
        return self.cache_dir / f'{short_name(bv)}.ariadne'

    def save_analysis_to_file(self, bv: BinaryView):
        if bv not in self.bvs:
            log_error(f'No analysis for {short_name(bv)}')
            return
        if bv not in self.targets:
            log_error(f'Analysis not finished for {short_name(bv)}')
            return

        target_json = self.targets[bv].serialize()

        if not self.cache_dir.exists():
            self.cache_dir.mkdir()

        cache_file = self.get_cache_target(bv)
        if cache_file.exists() and self.force_cache_overwrite is False:
            user_choice = get_choice_input(
                f'Existing analysis file for {short_name(bv)} found, overwrite it?',
                'Overwrite Saved Analysis?',
                ['No', 'Yes']
            )
            if isinstance(user_choice, int) and user_choice == 0:
                return

        with open(cache_file, 'w') as f:
            f.write(target_json)

        if not cache_file.exists():
            log_error(f'Failed to write analysis to {cache_file}')
        else:
            filesize = cache_file.stat().st_size
            log_info(f'Wrote analysis to {cache_file} ({filesize} bytes)')

    def load_analysis_from_file(self, bv: BinaryView) -> bool:
        cached_analysis_file = self.get_cache_target(bv)
        if not cached_analysis_file.exists():
            log_error(f'Expected cache analysis path not found ({cached_analysis_file})')
            return False

        load_start = time.time()
        log_info(f'loading analysis from "{cached_analysis_file}"...')
        with open(cached_analysis_file) as f:
            analysis_json = f.read()

        new_target = AriadneTarget.deserialize(bv, self, analysis_json)
        if new_target is None:
            return False

        if bv not in self.bvs:
            self.bvs.append(bv)

        visited_funcs = set(self.pop_history_cache(bv))
        new_target.mark_visited_set(visited_funcs)

        self.add_analysis_result(bv, new_target)

        duration = time.time() - load_start
        log_info(f'Loaded analysis from file in {duration:.02f} seconds')

        return True

    def queue_analysis(self, bv: BinaryView):
        """Queue a BinaryView for analysis which Binary Ninja may still be working"""
        # New analysis target
        if bv not in self.bvs:
            self.bvs.append(bv)
            log_info(f'Queueing analysis for "{short_name(bv)}"')
        else:
            # Analysis is either queued or finish
            if bv in self.targets:
                # Analysis is finished, we must want to re-do it
                log_info(f'Redoing analysis for {short_name(bv)}')
                self.targets.pop(bv)
            else:
                # Analysis is queued, bail
                log_warn(f'Analysis for "{short_name(bv.file)}" queued but not finished')
                log_warn(f'  Use "ariadne -> Cancel Analysis" to cancel')
                return

        def analysis_callback():
            self.launch_analysis(bv)

        bv.add_analysis_completion_event(analysis_callback)
        bv.update_analysis()

    def cancel_analysis(self, bv: BinaryView):
        if bv in self.bvs:
            self.bvs.remove(bv)
        else:
            log_info(f'No analysis for {short_name(bv)}')
            return

        if bv in self.targets:
            self.targets.pop(bv)
        # Analysis task may be finishing/removing asynchronously
        cur_analysis_task = self.analysis_tasks.get(bv)
        if cur_analysis_task:
            cur_analysis_task.cancel()
            try:
                self.analysis_tasks.pop(bv)
            except Exception as e:
                pass

        log_info(f'Analysis cancelled/removed for {short_name(bv)}')

    def launch_analysis(self, bv: BinaryView):
        """Callback to start our own analysis after BN's finishes"""

        cached_analysis_file = self.get_cache_target(bv)
        if cached_analysis_file.exists():
            # set core.load_from_cache = True to avoid prompts
            load_from_cache = self.force_load_from_cache
            if not load_from_cache:
                user_choice = get_choice_input(
                    f'Cached analysis for {short_name(bv)} found, load from file?',
                    'Load Saved Analysis?',
                    ['Yes', 'No']
                )
                if isinstance(user_choice, int) and user_choice == 0:
                    load_from_cache = True

            if load_from_cache:
                if self.load_analysis_from_file(bv):
                    return
                else:
                    log_info('Failed to load cached analysis; continuing with analysis from scratch.')

        log_info(f'Starting analysis for "{short_name(bv)}"...')
        cur_analysis_task = BackgroundAnalysis(bv, self)
        cur_analysis_task.start()
        self.analysis_tasks[bv] = cur_analysis_task

    def add_analysis_result(self, bv: BinaryView, analysis_result: AriadneTarget):
        """Add target to core after analysis finishes"""
        # Little bit of a race condition here, but acceptable
        if bv in self.analysis_tasks:
            self.analysis_tasks.pop(bv)

        self.targets[bv] = analysis_result
        # If no clicks, current_function_map[bv] may be unset
        if bv in self.current_function_map:
            current_function = self.current_function_map[bv]
        else:
            current_function = bv.entry_function
        analysis_result.set_current_function(current_function)
        # Set the initial graph
        callgraph = analysis_result.get_callgraph()
        num_nodes = len(callgraph.nodes())
        num_edges = len(callgraph.edges())

        neighborhood_graph = analysis_result.get_near_neighbors(current_function, self.neighborhood_hops, self.max_nodes_to_show)
        num_nodes = len(neighborhood_graph.nodes())
        num_edges = len(neighborhood_graph.edges())
        log_info(f'Initial func ({func_name(current_function)}) neighborhood: {num_nodes} nodes, {num_edges} edges')
        graph_title = f'Neighborhood of "{func_name(current_function)}"'

        cytoscape_obj = analysis_result.get_cytoscape(neighborhood_graph)
        self.server.set_graph_data(bv, cytoscape_obj, graph_title)

        log_info(f'Navigate to http://{self.ip}:{self.http_port} for interactive graph')

    def graph_new_neighborhood(self, bv_name: str, start: int):
        """Push the neighborhood of the specified function to the graph.

        Primarily to allow clients to drive the web UI."""

        if short_name(self.current_bv) == bv_name:
            bv = self.current_bv
        else:
            bv = None
            for iter_bv in self.targets:
                if short_name(iter_bv) == bv_name:
                    bv = iter_bv
                    break
            if bv is None:
                log_error(f'graph_new_neighborhood: Could not find bv_name "{bv_name}"')
                return
        cur_target = self.targets[bv]

        cur_func = bv.get_function_at(start)
        if cur_func is None:
            log_error(f'graph_new_neighborhood: Could not find function starting at "{hex(start)}"')
            return

        # Style the new function as the "current function" in the graph
        cur_target.set_current_function(cur_func, do_visit=False)

        neighborhood_graph = cur_target.get_near_neighbors(cur_func, self.neighborhood_hops, self.max_nodes_to_show)
        graph_title = f'Neighborhood of "{func_name(cur_func)}"'

        cytoscape_obj = cur_target.get_cytoscape(neighborhood_graph)
        self.server.set_graph_data(bv, cytoscape_obj, graph_title)


    def do_coverage_analysis(self, bv: BinaryView):
        """Import coverage data from bncov manually"""
        if coverage_enabled is False:
            log_error(f'Cannot do coverage analysis, bncov not available; please install it.')
            return

        if bv not in self.targets:
            if bv not in self.bvs:
                log_error(f'Cannot do coverage analysis without target analysis first')
            else:
                log_error(f'Cannot do coverage analysis until target analysis finishes')
            return

        covdb = bncov.get_covdb(bv)
        num_files = len(covdb.coverage_files)
        if num_files == 0:
            log_error('No coverage files in bncov, cannot do coverage analysis')
            return

        target = self.targets[bv]
        if target.coverage_available:
            log_info(f'Coverage data already available for "{bv.file.filename}", re-analyzing')

        target.do_coverage_analysis(covdb)

    def get_analysis_results(self, bv: BinaryView) -> Tuple[str, Optional[AriadneTarget]]:
        """Check if AriadneTarget analysis is complete, returning it if finished."""
        if bv not in self.bvs:
            return (
                f'Analysis NOT QUEUED for "{short_name(bv)}",\n' +
                 'Use the context menu to analyze,\n' +
                 'then click in the active view to update',
                None
            )
        elif bv not in self.targets:
            return (
                ('Waiting for analysis to finish...\n' +
                 'Watch the log and click a new address once complete'),
                None
            )
        else:
            return 'Done', self.targets[bv]

    def get_function_metadata(self, function: Function) -> str:
        """Return a string representing function metadata (or status if no metadata)"""
        bv = function.view
        status, analysis_result = self.get_analysis_results(bv)
        if status != 'Done' or analysis_result is None:
            return status
        if function not in analysis_result.function_dict:
            return f'{func_name(function)} @ {function.start} not in analysis results'
        function_result : AriadneFunction = analysis_result.function_dict[function]
        return function_result.get_metadata()

    def add_function_transition(self, function: Function):
        """Annotate that user changed the function they were viewing"""
        bv = function.view
        # Keep track of most recent bv and function the user has viewed
        self.current_bv = bv
        self.current_function_map[bv] = function
        # If analysis is still happening, we need to save this off
        if bv not in self.targets:
            self.history_cache.setdefault(bv, []).append(function)
        else:
            cur_target = self.targets[bv]
            cur_target.set_current_function(function)
            if self.graph_frozen is False:
                neighborhood_graph = cur_target.get_near_neighbors(function, self.neighborhood_hops, self.max_nodes_to_show)
                num_nodes = len(neighborhood_graph.nodes())
                num_edges = len(neighborhood_graph.edges())
                log_info(f'Current ({func_name(function)}) func neighborhood: {num_nodes} nodes, {num_edges} edges')
                graph_title = f'Neighborhood of {func_name(function)}'
                cytoscape_obj_str = cur_target.get_cytoscape(neighborhood_graph)
                self.server.set_graph_data(bv, cytoscape_obj_str, graph_title)

    def push_new_graph(self, graph: nx.DiGraph, graph_name: Optional[str] = None):
        current_target = self.get_current_target()
        if current_target:
            cytoscape_obj_str = current_target.get_cytoscape(graph)
            if graph_name:
                cur_graph_name = graph_name
            else:
                cur_graph_name = f'Custom Graph ({current_target.target_name})'
            self.server.set_graph_data(current_target.bv, cytoscape_obj_str, cur_graph_name)

    def pop_history_cache(self, bv: BinaryView) -> list:
        if bv not in self.history_cache:
            return []
        else:
            history_cache = self.history_cache.pop(bv)
            return history_cache

    def get_ariadne_function(self, function: Function) -> AriadneFunction:
        """Helper to go straight to AriadneFunction, raise Exception on errors"""
        bv = function.view
        if bv not in self.targets:
            if bv not in self.bvs:
                raise KeyError(f'BinaryView for {func_name(function)} never queued for analysis')
            else:
                raise KeyError(f'Analysis incomplete for BinaryView of {func_name(function)}')
        target = self.targets[bv]
        if function not in target.function_dict:
            raise KeyError(f'Function {func_name(function)} @ 0x{function.start} not in corresponding AriadneTarget')
        return target.function_dict[function]

    def freeze_graph(self):
        self.graph_frozen = True

    def unfreeze_graph(self):
        self.graph_frozen = False

    def get_current_target(self) -> Optional[AriadneTarget]:
        current_bv = self.current_bv
        if current_bv and current_bv in self.targets:
            return self.targets[self.current_bv]
        else:
            return None
