#!/usr/bin/python3

'''
Handle generating Python dictionary objects in the format cytoscape expects.

Cytoscape expects:
{
    'elements': [
        'nodes': [
            'data': {
                'key': val, # 'id' is only required key
                ...
            },
            ...
        ]
        'edges': [
            'data': {
                'id': val, # 'id', 'source', and 'target' required
                'source': val,
                'target': val,
                ...
            },
            ...
        ]
    ]
}
'nodes' and 'edges' can be combined into single list if structure is inferable
'''

from typing import Dict, Any, Optional, List
from pathlib import Path
import os
import json
import sys
import networkx as nx
from binaryninja import Function

from ..ariadne.util_funcs import func_name

def get_json_from_file(input_file: str) -> dict:
    with open(input_file) as f:
        json_obj = json.load(f)
    return json_obj


def graph_to_cytoscape(
    graph: nx.DiGraph,
    node_metadata: Optional[Dict[Function, Dict[str, Any]]]=None,
    edge_metadata: Optional[Dict[Function, Dict[str, Any]]]=None,
) -> Dict[str, list]:
    """Convert graph of BN Functions to cytoscape data dict.

    Metadata to be passed into nodes included in the dictionary.
    """
    func_names = []
    elements: List[Dict[str, Any]] = []
    for i, cur_func in enumerate(graph.nodes):
        name = func_name(cur_func)
        # Strictly required metadata
        node_data = {
            "id": str(i),
            "label": str(name),
        }
        # Pass optional metadata in
        if node_metadata is not None:
            extra_metadata = node_metadata.get(cur_func, None)
            if extra_metadata:
                node_data.update(extra_metadata)

        elements.append({"data": node_data})
        func_names.append(name)

    # map names to their index in the nodes list
    name_map = {n:i for i, n in enumerate(func_names)}

    for source_func, target_func in graph.edges:
        source = str(name_map[func_name(source_func)])
        target = str(name_map[func_name(target_func)])

        edge_covered = 0
        if edge_metadata is not None:
            if target_func.start in edge_metadata[source_func]['covered_edges']:
                edge_covered = 1

        elements.append({
            "data": {
                "id": f'{source}-{target}',
                "source": source,
                "target": target,
                "covered": edge_covered,
            },
        })

    cytoscape_model = {
        "elements": elements,
    }

    return cytoscape_model

def json_to_cytoscape(json_obj: dict) -> dict:
    callee_dict = json_obj
    func_names = list(callee_dict.keys())
    elements = [{
        "data": {
            "id": str(i),
            "label": str(n),
        },
    } for i, n in enumerate(func_names)]

    # map names to their index in the nodes list
    name_map = {n:i for i, n in enumerate(func_names)}

    for cur_func, callees in callee_dict.items():
        for called_func in callees:
            source = str(name_map[cur_func])
            target = str(name_map[called_func])
            elements.append({
                "data": {
                    "id": f'{source}-{target}',
                    "source": source,
                    "target": target,
                },
            })

    cytoscape_model = {
        "elements": elements,
    }

    return cytoscape_model


def write_model_to_file(output_file: str, model: dict):
    with open(output_file, 'w') as f:
        json.dump(model, f)

    out_str = output_file.as_posix()
    if os.path.exists(out_str):
        print(f'[+] Wrote {os.path.getsize(out_str)} bytes to "{out_str}"')
    else:
        raise Exception(f'output file {out_str} not found')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'USAGE: {sys.argv[0]} JSON_FILE')
        exit(2)

    input_file = Path(sys.argv[1])
    output_dir = Path('js/graphs')
    output_file = output_dir.joinpath(func_name(input_file))

    json_obj = get_json_from_file(input_file)
    model = json_to_cytoscape(json_obj)
    write_model_to_file(output_file, model)
