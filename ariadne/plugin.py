from typing import Optional, Any, Tuple

from binaryninja import (
    core_ui_enabled, show_message_box, get_form_input,
    ChoiceField, TextLineField, MessageBoxIcon,
    PluginCommand, BinaryView, Function,
)

from .core import AriadneCore, coverage_enabled
from .graph import get_callgraph, get_source_sink
from .util_funcs import short_name, log_info, log_error, graph_size, func_name, filename


core = AriadneCore()


if core_ui_enabled():
    from . import docking
    from .func_widget import AriadneFuncWidget

    # Start serving graph visualization over HTTP
    core.start_server()

    from PySide6.QtCore import Qt
    docking.register_widget(
        AriadneFuncWidget, "Ariadne Function Pane", Qt.RightDockWidgetArea, Qt.Vertical, True, core
    )


def analyze_current_target(bv: BinaryView):
    core.queue_analysis(bv)


def cancel_analysis(bv: BinaryView):
    core.cancel_analysis(bv)


def save_target_analysis(bv: BinaryView):
    core.save_analysis_to_file(bv)


def load_target_analysis(bv: BinaryView):
    if core.load_analysis_from_file(bv):
        log_info(f'Navigate to http://{core.ip}:{core.http_port} for interactive graph')
    else:
        show_message_box(
            f'No Saved Analysis Found',
            f'No analysis for "{short_name(bv)}" was found',
            icon=MessageBoxIcon.ErrorIcon,
        )


def do_coverage_analysis(bv: BinaryView):
    core.do_coverage_analysis(bv)


def toggle_graph_freeze(bv: BinaryView):
    if core.graph_frozen:
        core.unfreeze_graph()
        log_info('Graph unfrozen')
    else:
        core.freeze_graph()
        log_info('Graph frozen')


PluginCommand.register(
    "Ariadne\\Analyze Target",
    "Start analysis of current target",
    analyze_current_target,
)

PluginCommand.register(
    "Ariadne\\Cancel Analysis",
    "Cancel/remove analysis of current target",
    cancel_analysis,
)

PluginCommand.register(
    "Ariadne\\File: Save to file",
    "Save current target analysis to file",
    save_target_analysis,
)

PluginCommand.register(
    "Ariadne\\File: Load from file",
    "Load target analysis from file",
    load_target_analysis,
)

PluginCommand.register(
    "Ariadne\\Web UI: Freeze/Unfreeze Graph",
    "Toggle freezing/unfreezing interactive graph",
    toggle_graph_freeze,
)

if coverage_enabled:
    PluginCommand.register(
        "Ariadne\\Coverage: Load bncov data",
        "Import coverage analysis from bncov",
        do_coverage_analysis,
    )


## GRAPH FUNCTIONS: a little bit more complex


def check_callgraph(maybe_graph: Optional[Any], bv: BinaryView) -> bool:
    """Show warning and return False if no callgraph, True otherwise"""
    if maybe_graph is None:
        show_message_box(
            f'Callgraph Not Found',
            f'No callgraph for {short_name(bv)}, please ensure analysis has started and completed',
            icon=MessageBoxIcon.ErrorIcon,
        )
        return False
    else:
        return True


def show_full_callgraph(bv: BinaryView):
    """Build up and render the whole callgraph for a BinaryView"""
    cur_callgraph = get_callgraph(core, bv)
    if check_callgraph(cur_callgraph, bv):
        log_info(f'Serving full callgraph {graph_size(cur_callgraph)}')

        graph_name = f'Full Callgraph of "{filename(bv.file.filename)}"'
        core.push_new_graph(cur_callgraph, graph_name)


def show_func_callgraph(bv: BinaryView, function: Function):
    """Show full callgraph for current function"""
    cur_callgraph = get_callgraph(core, bv)
    if check_callgraph(cur_callgraph, bv):
        func_neighborhood = core.targets[bv].get_near_neighbors(function, 9999, None)
        log_info(f'Serving callgraph for {func_name(function)} {graph_size(func_neighborhood)}')
        graph_name = f'Callgraph for "{func_name(function)}"'
        core.push_new_graph(func_neighborhood, graph_name)


def show_source_sink(bv: BinaryView, function: Function):
    """Show full callgraph for current function"""
    cur_callgraph = get_callgraph(core, bv)
    if check_callgraph(cur_callgraph, bv):
        source_sink = prompt_source_sink_settings(bv, function)
        if not source_sink:
            return
        source, sink = source_sink
        source_sink_graph = get_source_sink(cur_callgraph, source, sink)
        log_info(f'Serving source/sink for {func_name(source)} -> {func_name(sink)} {graph_size(source_sink_graph)}')
        graph_name = f'Source/Sink "{func_name(source)}" -> "{func_name(sink)}"'
        core.push_new_graph(source_sink_graph, graph_name)


def prompt_source_sink_settings(bv: BinaryView, function: Function) -> Optional[Tuple[Function, Function]]:
    """Use BN's interaction helper to get user to specify source/sink"""
    form_fields = []
    form_fields.append(f'Source/Sink analysis for: {function.symbol.short_name}')

    source_sink_field = ChoiceField("Use current function as:", ["Source", "Sink"])
    form_fields.append(source_sink_field)

    target_field = TextLineField("Other function/address:")
    form_fields.append(target_field)

    if not get_form_input(form_fields, "Source/Sink Analysis") or not TextLineField.result:
        return None

    target = parse_target_str(bv, target_field.result)
    if target is None:
        return None

    # Current function as 'source' is first choice (0), otherwise its the sink
    if source_sink_field.result == 0:
        return function, target
    else:
        return target, function


def parse_target_str(bv: BinaryView, target_str: str) -> Optional[Function]:
    """Helper to match string to function, by its name or address it contains"""
    # Check function name first
    try:
        target = next(f for f in bv.functions if f.name == target_str or f.symbol.short_name == target_str)
        if target:
            return target
    except StopIteration:
        pass

    # Check as int
    try:
        if target_str.startswith('0x'):
            target_int = int(target_str, 16)
        else:
            target_int = int(target_str, 10)
    except ValueError:
        return None

    # Check if the int is the start of a function, then if it's _in_ a function
    if bv.get_function_at(target_int):
        target = bv.get_function_at(target_int)
        return target
    else:
        containing_funcs = bv.get_functions_containing(target_int)
        if len(containing_funcs == 0):
            log_error(f'No functions contain target address 0x{target_int:x}')
            return None
        else:
            target = containing_funcs[0]
            if len(containing_funcs) > 1:
                log_info(f'NOTE: More than one function contains target address 0x{target_int:x}')
                for func_name in containing_funcs:
                    log_info(func_name)
                log_info(f'Going with first match {target.symbol.short_name}; use start address or name for precision')
            return target


PluginCommand.register(
    "Ariadne\\Graph: All functions",
    "Generate callgraph for all function",
    show_full_callgraph,
)

PluginCommand.register_for_function(
    "Ariadne\\Graph: Current function callgraph",
    "Generate callgraph for current function",
    show_func_callgraph,
)

PluginCommand.register_for_function(
    "Ariadne\\Graph: Source/Sink w/Current function",
    "Graph the current function as a source or sink",
    show_source_sink,
)
