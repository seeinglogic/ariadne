from __future__ import annotations
from inspect import trace
from typing import Dict, Any, Set, List

import sys
import time
import json
import traceback
from pprint import pformat

from binaryninja import Function, BinaryView, log_info, log_error

from .analysis_functions import get_analysis_functions
from ..util_funcs import log_info, log_error, func_name

class AriadneFunction():
    def __init__(self, function: Function):
        self.address: int = function.start
        self.name: str = func_name(function)
        self.function: Function = function
        self.bv = function.view
        # FUTURE: test bv.get_code_refs against of callers?
        #         Same in analysis functions' get_neighbors
        self.callers: Set[Function] = set(self.function.callers)
        self.metadata: Dict[str, Any] = {}
        self.analysis_functions_run: List[str] = []

    def serialize(self) -> str:
        # Keep analysis_functions_run on the target level
        # Otherwise save everything not linked to the BN objects
        serialized_data = {
            'address': self.address,
            'name': self.name,
            'metadata': self.metadata,
        }
        return json.dumps(serialized_data)

    @staticmethod
    def deserialize(
        bv: BinaryView,
        serialized_dict: str,
        analysis_function_names: List[str]
    ) -> AriadneFunction:

        saved_dict = json.loads(serialized_dict)

        func_start = saved_dict['address']
        saved_name = saved_dict['name']

        bn_func = bv.get_function_at(func_start)
        if bn_func is None:
            log_error(f'Failed to load func {saved_name} @ {func_start}?!')

        cur_name = bn_func.symbol.short_name
        if cur_name != saved_name:
            log_error(f'Cur_name ({cur_name}) does NOT match saved ({saved_name})')

        new_ariadne_function = AriadneFunction(bn_func)
        new_ariadne_function.metadata = saved_dict['metadata']
        new_ariadne_function.analysis_functions_run = analysis_function_names

        return new_ariadne_function

    def is_import(self) -> bool:
        if 'is_import' not in self.metadata:
            raise Exception(f'[!] is_import metadata not present for {self.name} ({hex(self.address)}')
        if self.metadata['is_import'] is None:
            raise Exception(f'[!] is_import for {self.name} ({hex(self.address)} is None ?!')

        return bool(self.metadata['is_import'])

    def get_metadata(self) -> str:
        metadata_str = f'{self.name} @ 0x{self.address:x}\n'
        # Show particular values in order
        ordered_keys = [
            'function_type',
            'is_import',
            'callers',
            'local_callees',
            'imported_callees',
            'num_descendants',
            'args',
            'num_args',
            'return_type',
            'global_refs',
            'stack_frame_size',
            'stack_vars',
            'string_refs',
            'complexity',
            'blocks',
            'edges',
            'bytes',
            'instructions',
        ]
        keys_included = []
        for name in ordered_keys:
            if name in self.metadata:
                value = self.metadata[name]
                metadata_str += f'{name}: {pformat(value)}\n'
                keys_included.append(name)
        # Include any remaining
        for name, value in self.metadata.items():
            if name not in keys_included:
                metadata_str += f'{name}: {pformat(value)}\n'
        return metadata_str

    def collect_function_data(self):
        errored_funcs = []
        for function_name, analysis_function in get_analysis_functions().items():
            try:
                results = analysis_function(self.bv, self.function)
                self.metadata.update(results)
                self.analysis_functions_run.append(function_name)
            except:
                if function_name not in errored_funcs:
                    log_error(
                        f'Ariadne analysis function "{function_name}" threw an exception ' +
                        f'on target function "{self.name}" @ {hex(self.address)}:'
                    )
                    exception_str = traceback.format_exc()
                    for line in exception_str.split('\n'):
                        if line.strip():
                            log_error("  " + line)
                    errored_funcs.append(function_name)

    def init_visited(self):
        if 'visited' not in self.metadata:
            self.metadata['visited'] = 0

    def set_visited(self):
        self.metadata['visited'] = 1

    def get_visited(self) -> int:
        return self.metadata.get('visited', 0)


def get_analyzed_function(f: Function) -> AriadneFunction:
    """Get a populated AriadneFunction from a BN function"""
    ariadne_function = AriadneFunction(f)
    ariadne_function.collect_function_data()
    ariadne_function.init_visited()
    return ariadne_function


if __name__ == '__main__':

    from binaryninja import *
    import pprint
    import binaryninja
    bv = binaryninja.BinaryViewType.get_view_of_file(sys.argv[1])
    start = time.time()
    for f in bv.functions:
        a = AriadneFunction(f)
        a.collect_function_data()
        #metadata_str = pprint.pformat(a.metadata)
        #print(a.name, hex(a.address), metadata_str)
    duration = time.time() - start
    print(f'Finished function analysis in {duration:.2f} seconds')
