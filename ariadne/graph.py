from typing import Dict, Optional
import networkx as nx

from binaryninja import show_message_box
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function, InstructionTextToken, DisassemblyTextLine
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import BranchType, InstructionTextTokenType, MessageBoxIcon, SymbolType

from .core import AriadneCore
from .util_funcs import func_name


def get_callgraph(core: AriadneCore, bv: BinaryView) -> Optional[nx.DiGraph]:
    """Get the underlying nx graph from core or None"""
    if bv not in core.targets:
        return None

    return core.targets[bv].g


def get_source_sink(g: nx.DiGraph, source: Function, sink: Function) -> Optional[nx.DiGraph]:
    """Get graph for source/sink paths between two functions"""
    source_descendants = nx.descendants(g, source)
    sink_ancestors = nx.ancestors(g, sink)
    subgraph_nodes = source_descendants.intersection(sink_ancestors)
    subgraph_nodes.update([source, sink])

    if len(subgraph_nodes) == 0:
        show_message_box(
            'No path from source to sink',
            f'No paths found from {func_name(source)} to {func_name(sink)}',
            icon=MessageBoxIcon.ErrorIcon,
        )
        return None

    return g.subgraph(subgraph_nodes)


def render_flowgraph(bv: BinaryView, g: nx.DiGraph, title: str=''):
    """Render arbitrary networkx graph"""
    flowgraph = FlowGraph()
    flowgraph_nodes: Dict[Function, FlowGraphNode] = {}

    # encapsulate check/add with a helper func for clarity
    def add_node(node_func: Function):
        if node_func not in flowgraph_nodes:
            new_node = FlowGraphNode(flowgraph)
            # h/t @joshwatson on how to distinguish imports, your implementation was better
            if node_func.symbol.type == SymbolType.ImportedFunctionSymbol:
                token_type = InstructionTextTokenType.ImportToken
            else:
                token_type = InstructionTextTokenType.CodeSymbolToken
            cur_func_name = func_name(node_func)
            func_token = InstructionTextToken(token_type, cur_func_name, node_func.start)
            new_node.lines = [DisassemblyTextLine([func_token])]

            flowgraph.append(new_node)
            flowgraph_nodes[node_func] = new_node
            return new_node
        return flowgraph_nodes[node_func]

    # one traversal that adds islands and nodes with edges
    for node_func in g.nodes:
        src_flowgraph_node = add_node(node_func)
        for src, dst in g.out_edges(node_func):
            dst_flowgraph_node = add_node(dst)
            src_flowgraph_node.add_outgoing_edge(BranchType.CallDestination, dst_flowgraph_node)

    bv.show_graph_report(title, flowgraph)
