from typing import List, Dict, Callable, Any, Set, Union
import re

from binaryninja import Function, LowLevelILOperation, LowLevelILInstruction, SymbolType

from ..util_funcs import func_name

# Analysis functions defined at the bottom of this file
# That's the only place a function needs to be added
def get_analysis_functions() -> Dict[str, Callable]:
    return analysis_functions


def get_cyclomatic_complexity(bv, function) -> Dict[str, Any]:
    num_blocks = len(function.basic_blocks)
    num_edges = sum(len(bb.outgoing_edges) for bb in function.basic_blocks)
    return {
        "blocks": num_blocks,
        "edges": num_edges,
        "complexity": num_edges - num_blocks + 2
    }

def get_basic_attributes(bv, function) -> Dict[str, Any]:
    f = function
    results: Dict[str, Union[str, int]] = {}
    results['instructions'] = len(list(f.instructions))
    results['bytes'] = f.total_bytes
    results['num_args'] = len(f.parameter_vars)
    results['args'] = ", ".join(f'{v.type} {v.name}' for v in f.parameter_vars)
    results['return_type'] = str(f.return_type)
    results['function_type'] = str(f.symbol.type.name.replace('Symbol', ''))
    results['is_import'] = 1 if f.symbol.type == SymbolType.ImportedFunctionSymbol else 0
    return results

def get_variable_refs(bv, function) -> Dict[str, Any]:
    global_vars = set()
    string_refs = set()

    def get_pointers(llil_inst):
        for i, operand in enumerate(llil_inst.operands):
            if isinstance(operand, LowLevelILInstruction):
                if operand.operation == LowLevelILOperation.LLIL_CONST_PTR:
                    address = operand.value.value
                    var = bv.get_data_var_at(address)
                    if var:
                        yield var
                else:
                    get_pointers(operand)

    if function.llil is not None:
        for llil_inst in function.llil_instructions:
            for var in get_pointers(llil_inst):
                var_sym =  bv.get_symbol_at(var.address)
                if var_sym:
                    var_name = var_sym.name
                else:
                    var_name = f'data_{var.address:x}'
                if re.search(r'char.*[\[0-9a-fx]\]', str(var.type)):
                    str_pointed_at = bv.get_ascii_string_at(var.address, min_length=1)
                    if str_pointed_at is not None:
                        real_str = f'"{str_pointed_at.value}"'
                    else:
                        real_str = '<Failed to get string>'
                    string_refs.add(f'{var_name}: {real_str}')
                else:
                    global_vars.add(var_name)

    return {
        'string_refs': sorted(string_refs),
        'global_refs': sorted(global_vars)
    }

def get_neighbors(bv, function) -> Dict[str, Any]:
    # Save to class member for graph
    # FUTURE: test bv.get_code_refs against of callers?
    #         Same in AriadneFunction constructor
    callers: Set[str] = set(function.callers)
    callees: Set[str] = set()
    imports: Set[str] = set()
    for callee in function.callees:
        sym_type = callee.symbol.type
        if sym_type in [SymbolType.ImportedFunctionSymbol, SymbolType.ImportAddressSymbol]:
            imports.add(func_name(callee))
        else:
            callees.add(func_name(callee))
    return {
        'callers': sorted(set(func_name(f) for f in callers)),
        'local_callees': sorted(callees),
        'imported_callees': sorted(imports),
    }

def get_stack_layout(bv, function) -> Dict[str, Any]:
    stack_vars: List[str] = []
    frame_size = 0
    prev_offset = None
    cur_offset = 0
    for cur_var in function.stack_layout:
        cur_offset = cur_var.storage
        # only want stack vars, presuming negative offsets
        if cur_offset < 0:
            # convert to positive offsets for convenience
            cur_offset *= -1
            if cur_offset > frame_size:
                frame_size = cur_offset
            if prev_offset is not None:
                prev_size = prev_offset - cur_offset
                if not prev_name.startswith('__'):
                    stack_vars.append(f'{prev_name} (0x{prev_size:x})')
            prev_offset = cur_offset
            prev_name = cur_var.name
    # not worrying about functions whose last variable isn't a saved reg
    return {
        'stack_frame_size': hex(frame_size),
        'stack_vars': stack_vars,
    }


analysis_functions: Dict[str, Callable]= {
    "get_cyclomatic_complexity": get_cyclomatic_complexity,
    "get_basic_attributes": get_basic_attributes,
    "get_neighbors": get_neighbors,
    "get_variable_refs": get_variable_refs,
    "get_stack_layout": get_stack_layout,
}