
import networkx as nx
from pathlib import Path

from binaryninja import BinaryView, Function
from binaryninja import (
    log_info as bn_log_info,
    log_warn as bn_log_warn,
    log_error as bn_log_error,
)


def short_name(bv: BinaryView) -> str:
    """Return the short name for a BinaryView"""
    return Path(bv.file.original_filename).stem

def filename(filepath: str) -> str:
    return Path(filepath).name

def func_name(f: Function) -> str:
    """Standardized way to get function name"""
    return f.symbol.short_name


def graph_size(g: nx.Graph) -> str:
    """Return formatted size str "(# nodes, # edges)" for graph"""
    num_nodes = len(g.nodes())
    num_edges = len(g.edges())
    return f'({num_nodes} nodes, {num_edges} edges)'


def log_info(msg: str, tag: str='ARIADNE'):
    bn_log_info(msg, tag)

def log_warn(msg: str, tag: str='ARIADNE'):
    bn_log_warn(msg, tag)

def log_error(msg: str, tag: str='ARIADNE'):
    bn_log_error(msg, tag)


def get_repo_dir() -> Path:
    cur_file = Path(__file__)
    return cur_file.parent.parent.absolute()

def get_web_dir() -> str:
    return get_repo_dir().joinpath('web')
