'''
Target-level analysis and metadata
'''

from __future__ import annotations
from typing import Dict, Iterable, Optional, Set, Any, List

import json
from pathlib import Path
import networkx as nx
import time

from binaryninja import Function, BinaryView, ReferenceSource
from .analysis.ariadne_function import AriadneFunction
from .py2cytoscape import graph_to_cytoscape
from .util_funcs import log_info, log_warn, log_error, func_name


class AriadneTarget():
    def __init__(self, bv, core):
        self.bv = bv
        self.target_name = Path(bv.file.original_filename).name
        self.core = core
        self.function_dict: Dict[Function, AriadneFunction] = {}
        self.function_list: List[Function] = []
        self.g: Optional[nx.DiGraph]= None
        self.undirected: Optional[nx.Graph] = None
        self.current_function: Optional[Function] = None
        self.banned_functions: Set[Function] = set()
        self.coverage_available = False
        self.update_notification: Optional[BinaryDataNotification] = None
        self.update_thread: Optional[BackgroundTargetUpdate] = None
        self.warned_missing_funcs = False
        # Optional bncov data
        self.coverage_stats: Optional[dict] = None
        self.covdb = None

    def serialize(self):
        first_ariadne_func = next(iter(self.function_dict.values()))
        analysis_functions_run = first_ariadne_func.analysis_functions_run

        target_dict = {
            'target_name': self.target_name,
            'ariadne_functions': [f.serialize() for f in self.function_dict.values()],
            'analysis_functions_run': analysis_functions_run,
        }
        if self.coverage_stats:
            target_dict['coverage_stats'] = self.coverage_stats

        return json.dumps(target_dict)

    @staticmethod
    def deserialize(
        bv: BinaryView,
        core,
        serialized_dict: str
    ) -> Optional[AriadneTarget]:
        new_target = AriadneTarget(bv, core)
        saved_dict = json.loads(serialized_dict)

        saved_name = Path(saved_dict['target_name'])
        cur_name = Path(new_target.target_name)
        if saved_name.stem != cur_name.stem:
            log_error(f'ERROR: saved target_name ({saved_name}) does not match current: ({cur_name})')
            return None

        analysis_funcs = saved_dict['analysis_functions_run']
        saved_ariadne_funcs = saved_dict['ariadne_functions']
        function_list = list(bv.functions)

        num_funcs = len(function_list)
        num_saved_funcs = len(saved_ariadne_funcs)
        if num_funcs != num_saved_funcs:
            log_warn(f'Encountered mismatch between number of functions in current BinaryView ({num_funcs}) and saved analysis ({num_saved_funcs})')
            log_warn('If the binary has not changed, you must save the result of new analysis.')
            return None
        new_target.function_list = function_list

        for af_dict in saved_dict['ariadne_functions']:
            cur_ariadne_function = AriadneFunction.deserialize(bv, af_dict, analysis_funcs)
            cur_function = cur_ariadne_function.function
            new_target.function_dict[cur_function] = cur_ariadne_function

        if 'coverage_stats' in saved_dict:
            new_target.coverage_stats = saved_dict['coverage_stats']
            new_target.coverage_available = True

        new_target.generate_callgraph()
        return new_target

    def generate_callgraph(self):
        self.g = nx.DiGraph()
        for bn_func, ariadne_func in self.function_dict.items():
            self.g.add_node(bn_func)
            # AriadneFunc has callers precomputed and uniq'd
            for caller in ariadne_func.callers:
                self.g.add_edge(caller, bn_func)
        self.undirected = nx.Graph(self.g)

    def get_callgraph(self) -> nx.DiGraph:
        if self.g is None:
            raise Exception(f'generate_callgraph() must be called before get_callgraph()')
        return self.g.copy()

    def get_undirected_callgraph(self) -> nx.Graph:
        if self.undirected is None:
            raise Exception(f'generate_callgraph() must be called before get_undirected_callgraph()')
        return self.undirected.copy()

    def get_cytoscape(self, graph: nx.DiGraph=None) -> Dict[str, Any]:
        """Return a cytoscape data object for given nx graph"""

        if graph is None:
            graph = self.get_callgraph()

        nodes_to_keep = [n for n in graph.nodes if n not in self.banned_functions]
        graph = graph.subgraph(nodes_to_keep)

        # Metadata used for info display and node styling
        node_metadata: Dict[Function, Dict[str, Any]] = {
            cur_func: {
                # Metadata shown in this order
                'start': cur_func.start,
                'args': self.function_dict[cur_func].metadata['args'],
                'return_type': self.function_dict[cur_func].metadata['return_type'],
                'blocks': self.function_dict[cur_func].metadata['blocks'],
                'instructions': self.function_dict[cur_func].metadata['instructions'],
                'complexity': self.function_dict[cur_func].metadata['complexity'],
                'num_descendants': self.function_dict[cur_func].metadata['num_descendants'],
                'descendent_complexity': self.function_dict[cur_func].metadata.get('descendent_complexity'),
                'callers': self.function_dict[cur_func].metadata['callers'],
                'local_callees': self.function_dict[cur_func].metadata['local_callees'],
                'imported_callees': self.function_dict[cur_func].metadata['imported_callees'],
                'global_refs': self.function_dict[cur_func].metadata['global_refs'],
                'stack_frame_size': self.function_dict[cur_func].metadata['stack_frame_size'],
                # Used for styling, not shown in metadata
                'visited': self.function_dict[cur_func].get_visited(),
                'import': self.function_dict[cur_func].metadata['is_import'],
                # Coverage analysis may not be available
                'coverage_percent': self.function_dict[cur_func].metadata.get('coverage_percent'),
                'blocks_covered': self.function_dict[cur_func].metadata.get('blocks_covered'),
                'blocks_total': self.function_dict[cur_func].metadata.get('blocks_total'),
                'callsite_coverage': self.function_dict[cur_func].metadata.get('callsite_coverage'),
                'uncovered_descendent_complexity': self.function_dict[cur_func].metadata.get('uncovered_descendent_complexity'),
                # Hint for the user that there's more to see from this node
                'edges_not_shown': abs(graph.degree(cur_func) - self.g.degree(cur_func)),
            }
            for cur_func in graph.nodes
        }

        # Edge metadata, keyed off of source function
        if not self.coverage_available:
            edge_metadata = None
        else:
            edge_metadata = {
                cur_func: {
                    'covered_edges': self.function_dict[cur_func].metadata.get('covered_edges')
                }
                for cur_func in graph.nodes
            }

        bn_active_function = self.current_function
        if bn_active_function and bn_active_function in graph:
            node_metadata[bn_active_function]['current_function'] = 1

        cyto_json = graph_to_cytoscape(graph, node_metadata, edge_metadata)
        return cyto_json

    def get_near_neighbors(self, origin_func: Function, num_levels: int=3, max_nodes: Optional[int]=None) -> nx.DiGraph:
        """Return n-hop neighborhood, with optional limit on number of nodes.

        If max_nodes is specified, each hop after the first will be checked to
        see if it would go over the limit and will stop before it exceeds
        max_nodes."""

        if not self.g:
            log_error(f'Callgraph required for get_near_neighbors()')
            return
        neighbors = set([origin_func, ])
        to_add: Set[Function] = set()
        cur_level = set()
        for i in range(num_levels):
            to_check = set(neighbors)
            for cur_node_func in to_check:
                if cur_node_func not in to_add:
                    # don't add callers of imported functions as neighbors
                    # unless they are the origin node
                    if cur_node_func == origin_func or not self.function_dict[cur_node_func].is_import():
                        new_neighbors = nx.neighbors(self.undirected, cur_node_func)
                        neighbors.update(new_neighbors)
                    cur_level.add(cur_node_func)
            # Enforce max_nodes check on levels beyond the first
            if max_nodes is None or i <= 1 or len(to_add) + len(cur_level) < max_nodes:
                to_add.update(cur_level)
            else:
                break

        near_neighbor_graph: nx.Graph = self.g.subgraph(to_add)
        return near_neighbor_graph

    def get_n_hops_out(self, source: Function, dist: int) -> nx.DiGraph:
        graph = self.get_callgraph()
        return nx.bfs_tree(graph, source, False, dist)

    def get_source_sink(self, source: Function, sink: Function) -> nx.DiGraph:
        """Show graph between source and sink, if any"""
        if not self.g:
            log_error(f'Callgraph required for get_source_sink()')
            return
        source_descendants = nx.descendants(self.g, source)
        sink_ancestors = nx.ancestors(self.g, sink)
        subgraph_nodes = source_descendants.intersection(sink_ancestors)
        subgraph_nodes.update([source, sink])

        source_sink_graph = self.g.subgraph(subgraph_nodes)
        return source_sink_graph

    def do_analysis(self):
        """This is a single-threaded implementation; see core.BackgroundAnalysis.run() instead"""
        self.function_list = list(self.bv.functions)
        num_funcs = len(self.function_list)
        for i, f in enumerate(self.function_list):
            cur_function_obj = AriadneFunction(f)
            cur_function_obj.collect_function_data()
            cur_function_obj.init_visited()
            self.function_dict[f] = cur_function_obj
        # Cross-function analysis
        self.generate_callgraph()
        self.do_graph_analysis()

    def do_graph_analysis(self):
        for bn_func, ariadne_func in self.function_dict.items():
            ariadne_func.metadata['num_descendants'] = len(nx.descendants(self.g, bn_func))

            func_descendents = nx.descendants(self.g, bn_func)
            # complexity is always computed in core analysis
            descendent_complexity = sum(self.function_dict[f].metadata['complexity'] for f in func_descendents)
            ariadne_func.metadata['descendent_complexity'] = descendent_complexity

    def do_coverage_analysis(self, covdb) -> bool:
        """Single-threaded all-in-one coverage analysis

        Note that core.BackgroundAnalysis does this automatically if coverage
        data is present and does it multithreaded."""
        start_time = time.time()
        if not self.init_coverage_analysis(covdb):
            return False

        coverage_files = len(self.covdb.coverage_files)
        log_info(f'Starting coverage analysis ({coverage_files} coverage files,' +
                 f'{len(self.function_list)} functions)' )

        for bn_func in self.function_list:
            self.do_function_coverage_analysis(bn_func)

        self.mark_coverage_analysis_finished()
        duration = time.time() - start_time
        log_info(f'Finished coverage analysis for "{self.target_name}" in {duration:.02f} seconds')

        return True

    def init_coverage_analysis(self, covdb) -> bool:
        """Do any target-level coverage analysis tasks"""
        if len(covdb.coverage_files) == 0:
            log_warn(f'Stopping coverage analysis: No coverage files in covdb.')
            return False

        self.covdb = covdb
        self.coverage_stats = covdb.collect_function_coverage()

        return True

    def get_callsite_dest(self, callsite: ReferenceSource) -> Optional[Function]:
        """Use MLIL to find destinations... slower but more thorough"""
        try:
            call_llil = callsite.llil
            if call_llil is None:
                return None
            call_dest_addr = call_llil.dest.value.value
            if call_dest_addr is None:
                return None
            return self.bv.get_function_at(call_dest_addr)
        except:
            return None

    def do_function_coverage_analysis(self, bn_func):
        """Execute function-level coverage analysis"""
        bv = bn_func.view
        ariadne_func = self.function_dict[bn_func]
        cur_func_stats = self.coverage_stats[bn_func.start]

        ariadne_func.metadata['coverage_percent'] = cur_func_stats.coverage_percent
        ariadne_func.metadata['blocks_covered'] = cur_func_stats.blocks_covered
        ariadne_func.metadata['blocks_total'] = cur_func_stats.blocks_total

        total_descendents = nx.descendants(self.g, bn_func)
        # complexity for strictly zero-coverage descendents
        uncovered_descendent_complexity = sum(
            self.coverage_stats[f.start].complexity for f in total_descendents
            if self.coverage_stats[f.start].blocks_covered == 0
        )
        ariadne_func.metadata['uncovered_descendent_complexity'] = uncovered_descendent_complexity

        num_callsites = 0
        num_covered_callsites = 0
        covered_edges: List[int] = []  # Record callgraph edge coverage by dest start addr
        coverage = self.covdb.total_coverage
        for callsite in bn_func.call_sites:
            call_addr = callsite.address
            # Will "double-count" in the case of overlapping blocks
            for block in bv.get_basic_blocks_at(call_addr):
                if block.start in coverage:
                    num_covered_callsites += 1
                    call_dest_func = self.get_callsite_dest(callsite)
                    if call_dest_func:
                        call_dest = call_dest_func.start
                        if call_dest not in covered_edges:
                            covered_edges.append(call_dest)
                num_callsites += 1

        ariadne_func.metadata['callsite_coverage'] = f'{num_covered_callsites}/{num_callsites}'
        ariadne_func.metadata['covered_edges'] = covered_edges

        self.function_dict[bn_func] = ariadne_func

    def mark_coverage_analysis_finished(self):
        self.coverage_available = True

    def set_current_function(self, function: Function, do_visit: bool = True) -> bool:
        if function not in self.function_dict:
            log_warn(f'Function "{function.name}" @ {hex(function.start)} not found in Ariadne target analysis')
            if not self.warned_missing_funcs:
                log_info('If analysis is not currently underway, you can add it manually with:')
                log_info('  ariadne.core.targets[bv].add_new_function(current_function)')
                log_info('Or you can redo analysis via context menu: Ariadne -> Analyze Target')
                self.warned_missing_funcs = True
            return False
        self.current_function = function
        if do_visit:
            self.mark_visited(function)
        return True

    def mark_visited(self, function: Function):
        if function not in self.function_dict:
            log_error(f'Function "{function.name}" @ {hex(function.start)} not found in Ariadne target analysis')
        ariadne_function = self.function_dict[function]
        ariadne_function.set_visited()

    def mark_visited_set(self, func_list: Iterable[Function]):
        for cur_func in func_list:
            self.mark_visited(cur_func)

    def remove_imports_from_graph(self, graph: nx.Graph) -> Optional[nx.Graph]:
        to_remove = []
        for function in graph.nodes:
            if function not in self.function_dict:
                log_error(f'Function {func_name(function)} @ 0x{function.start:x} not in function dict, stopping')
                return graph
            if self.function_dict[function].metadata.get('is_import', 0):
                to_remove.append(function)
        graph.remove_nodes_from(to_remove)
        return graph

    def remove_islands_from_graph(self, graph: nx.Graph) -> Optional[nx.Graph]:
        """Remove nodes with no edges"""
        to_remove = list(nx.isolates(graph))
        graph.remove_nodes_from(to_remove)
        return graph

    def get_largest_component(self, graph: nx.Graph) -> Optional[nx.Graph]:
        undirected = nx.Graph(graph)
        # connected_components generates components, largest first
        largest_component = next(nx.connected_components(undirected))
        return graph.subgraph(largest_component)

    def ban_function_from_graph(self, function: Function):
        """Never show the supplied function again"""
        if function not in self.function_dict:
            log_error(f'Function {func_name(function)} @ 0x{function.start:x} not in function dict')
            return
        self.banned_functions.add(function)

    def ban_set_from_graph(self, function_set: Iterable[Function]):
        """Never show any of the supplied functions in graphing"""
        self.banned_functions.update(function_set)

    def unban_function(self, function: Function):
        if function in self.banned_functions:
            self.banned_functions.remove(function)
