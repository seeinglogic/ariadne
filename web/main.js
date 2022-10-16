//
//
// Main JS
//
//

//
// globals
//
var json_contents;
var container;
var websock;
var cy;
var focusedNode; // The node currently clicked on
var sidebarExpanded = false;
var hiddenImportNodes; // For restoring removed imports
var hiddenImportEdges;
var removedNodes = null; // Keeping track of user-removed nodes
var coverageAvailable = false;
var coverageStylingOn = false;

//
// constants
//
var server_addr = "127.0.0.1";
var server_port = 7890;
var websock_url = `ws://${server_addr}:${server_port}/`;
log_status("Websocket url: " + websock_url);

// colors
var blue = '#80C6E7';
var dark_blue = '#5180c2';
var light_green = '#A2D9AF';
var green = '#368448';
var dark_green = '#1b4325';
var orange = '#EDBD80';
var light_grey = '#909090';
var subtle_grey = '#707070';
var grey = '#4a4a4a';
var dark_grey = '#2a2a2a';
var white = '#e0e0e0';
var yellow = '#eddfb3';
var bright_purple = '#cc00af';
var bright_yellow = '#d0c766';
var red = '#de8f97';
var bright_red = '#fb4141';
// variable colors referenced in styling
var selected_color = bright_purple;
var to_color = red;
var from_color = blue;
// want coverage color to look recognizably different
var dark_green_alt = '#008631';
var green_alt = '#1fd655';
var covered_color = green_alt;
var covered_border_color = dark_green_alt;

// sizing
var complexity_tiny   = 5;
var complexity_small  = 10;
var complexity_medium = 20;
var complexity_large  = 100;
//var complexity_jumbo  = 101; // just compare > large
var size_tiny   = 20;
var size_small  = 30;
var size_medium = 45;
var size_large  = 60;
var size_jumbo  = 80;

// layout options
// more options at: https://github.com/cytoscape/cytoscape.js-klay
var klay_layout = {
    name: 'klay',
    nodeDimensionsIncludeLabels: true,
    klay: {
    'direction': 'DOWN'
    },
    padding: 50, // padding pixels around edge to avoid colliding with controls
}
var default_layout = klay_layout;


//
// utility functions
//

// In case we need to avoid console.log
function log_status(message) {
  console.log(message);
  /*
  var status_elem = document.getElementById("status");
  if (status_elem) {
    let current_status = status_elem.innerHTML;
    current_status += message;
    status_elem.innerHTML = current_status;
  }
  */
}
function log_collection(c) {
    console.log(`${c.edges().length} edges, ${c.nodes().length} nodes:`)
    for (let e of c) {
        console.log(`  ${e.group()}: ${e.data().id} (label: ${e.data().label})`);
    }
}

function update_status() {
    var status_element_name = "status_display"
    status_elem = document.getElementById(status_element_name);
    if (status_elem) {
        var status = 'Inactive';
        if (typeof(websock) == 'object') {
            if      (websock.readyState == 0) { status = 'Connecting...'; }
            else if (websock.readyState == 1) { status = 'Connected'; }
            else if (websock.readyState == 2) { status = 'Closing'; }
            else if (websock.readyState == 3) { status = 'Closed'; }
        }
        status_elem.innerHTML = `Websocket ${status}`;
    }
    else {
        console.log(`WARNING: update_status(): getElementById("${status_element_name}") failed`);
    }
}

//
// onload callback (entrypoint); opens websocket
//
function js_init() {
  container = document.getElementById("graph_container");
  document.getElementById("remove_node_btn").addEventListener("click", handleRemoveNode);
  document.getElementById("remove_descendents_btn").addEventListener("click", handleRemoveNodeAndDescendents);
  document.getElementById("reset_graph_btn").addEventListener("click", handleResetGraph);
  document.getElementById("hide_imports_btn").addEventListener("click", handleToggleImports);
  document.getElementById("toggle_coverage_btn").addEventListener("click", handleToggleCoverage);
  document.getElementById("redo_layout_btn").addEventListener("click", handleRedoLayout);

  document.getElementById("func_search_input").addEventListener("input", handleSearchInputChange);

  // Just poll websocket status in background
  setInterval(update_status, 1000);

  websock = new WebSocket(websock_url);


  websock.onmessage = function(event) {
    log_status(' Receiving websocket message.');
    var title_elem = document.getElementById("title");
    title_elem.innerHTML = "Loading graph...";

    let parse_start_time = performance.now()
    var model = JSON.parse(event.data);

    //log_status(`DBG: JSON model: ${JSON.stringify(model)}`);
    if (model.elements) {
        log_status(`JSON model has ${model.elements.length} elements`);
    }

    let parse_duration = performance.now() - parse_start_time;
    json_contents = model;
    log_status(`JSON parsed in ${parse_duration} milliseconds`);

    let render_start_time = performance.now()
    renderCytoscape(model);

    let render_duration = performance.now() - render_start_time;
    log_status(`Render function completed in ${render_duration} milliseconds`);

    if (model.title) {
      if (title_elem) {
        title_elem.innerHTML = model.title;
      }
    }
  };

  websock.onclose = function(event) {
    if (event.wasClean) {
      log_status(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
    } else {
      log_status(`[close] Connection died, reason: ${event.reason}`);
    }
  };

  websock.onerror = function(error) {
    log_status(`[error] ${error.message}`);
  };

  $(window).on('beforeunload', function(){
    websock.close();
  });

  log_status(" js_init() finished.")
}

//
// event handling
//
function handleNodeClick( event ) {

    let clickedNode = event.target;

    // if there was a focus node, we either change focus or deselect it
    if (focusedNode) {
        removeFocus();
    }
    // selecting focus node deselects it
    if (clickedNode == focusedNode) {
        focusedNode = null;
        hideSidebarMetadata();
        sidebarHeaderClickable(false);
    }
    else { // selecting other node changes focus
        focusedNode = clickedNode;
        addFocus(clickedNode);
        showSidebarMetadata();
        sidebarHeaderClickable(true);
    }
}

function addFocus(focusNode) {
  focusNode.addClass('focused');

  let neighborhood = cy.collection().union(focusNode);

  let in_edges = focusNode.incomers().addClass('from');
  let in_nodes = in_edges.sources().addClass('from');
  neighborhood = neighborhood.union(in_edges).union(in_nodes);

  let out_edges = focusNode.outgoers().addClass('to');
  let out_nodes = out_edges.targets().addClass('to');
  neighborhood = neighborhood.union(out_edges).union(out_nodes);

  cy.elements().difference(neighborhood).addClass('background');
}

function removeFocus() {
  cy.elements().removeClass('focused')
               .removeClass('to')
               .removeClass('from')
               .removeClass('background');
}

function hideSidebarMetadata() {
    if (focusedNode == null) {
        document.getElementById("sidebar_title").innerHTML = "No function selected";
    } else {
        focusedFuncName = focusedNode.data().label;
        let sidebarLabel = `Info for "<b>${focusedFuncName}</b>" hidden`;
        document.getElementById("sidebar_title").innerHTML = sidebarLabel;
    }

    document.getElementById("sidebar_title").style.fontWeight = "";
    // just hide the table, we'll delete rows when we show it again
    document.getElementById("sidebar_table").style.display = "none";

    sidebarExpanded = false;
}

function showSidebarMetadata() {
    // deepcopy the data via spread operator
    let function_metadata = {...focusedNode.data()};

    document.getElementById("sidebar_title").innerHTML = function_metadata.label;
    document.getElementById("sidebar_title").style.fontWeight = "bold";
    document.getElementById("sidebar_table").style.display = "block";

    // delete any existing rows in table
    let table_body = document.getElementById("sidebar_table_body");
    while (table_body.rows.length) {
        table_body.deleteRow(0);
    }

    // remove metadata we don't want in the table
    delete function_metadata.label;
    delete function_metadata.id;
    delete function_metadata.current_function;
    delete function_metadata.visited;
    delete function_metadata.import;
    delete function_metadata.global_refs;

    for (const kv of Object.entries(function_metadata)) {
        let key_name = kv[0]
        let val = kv[1]

        if (val === null) {
            continue;
        }

        row = table_body.insertRow();
        row.insertCell().innerHTML = key_name;

        // put spaces in between comma-separated lists
        let value_str = val.toString();
        if (value_str.match(',[^ ]')) {
            value_str = val.join(', ')
        }
        // format floats to only show a few decimal points of precision
        else if (typeof(val) == 'number' && !Number.isInteger(val)) {
            value_str = val.toFixed(4);
        }

        row.insertCell().innerHTML = value_str;
    }

    sidebarExpanded = true;
}

function toggleSidebarExpansion(event) {
    console.log(`toggleSidebarExpansion called w/expanded=${sidebarExpanded}`)
    let metadata_header = document.getElementById("sidebar_header");

    if (sidebarExpanded == true) {
        hideSidebarMetadata();
        metadata_header.innerHTML = 'METADATA SIDEBAR [+]';
    } else {
        showSidebarMetadata();
        metadata_header.innerHTML = 'METADATA SIDEBAR [-]';
    }
}

function sidebarHeaderClickable(clickable) {
    let metadata_header = document.getElementById("sidebar_header");
    if (clickable) {
        metadata_header.addEventListener('click', toggleSidebarExpansion);
        metadata_header.innerHTML = 'METADATA SIDEBAR [-]';
    } else {
        metadata_header.removeEventListener('click', toggleSidebarExpansion);
        metadata_header.innerHTML = 'METADATA SIDEBAR';
    }
}

function handleRemoveNode( event ) {
    if (focusedNode) {
        removeNode(focusedNode);
    }
}

function removeNode(node_to_remove) {
    if (focusedNode == node_to_remove) {
        removeFocus();
        focusedNode = null;
    }

    if (removedNodes == null) {
        removedNodes = cy.collection();
    }
    removedNodes = removedNodes.union(node_to_remove);

    return cy.remove(node_to_remove);
}

function restoreNode(node_to_restore) {
    if (removedNodes != null) {
        removedNodes.subtract(node_to_restore);
    }
    cy.add(node_to_restore);
}

function handleRemoveNodeAndDescendents( event ) {

    if (focusedNode) {

        let successors = focusedNode.successors().nodes();

        // temporarily remove focusedNode to enable the predecessor check below
        let originalFocusedNode = removeNode(focusedNode);

        function inSuccessors(node) {
            return successors.contains(node);
        }

        // strict descendents only:
        //   only remove descendents for whom all predecessors are ALSO in the
        //   successor group.
        // This keeps nodes that have incoming edges from nodes that are not
        // successors of the focusedNode
        for (let curNode of successors) {
            if (curNode.predecessors().nodes().every(inSuccessors)) {
                removeNode(curNode);
            }
        }

        // restore focusedNode so the net effect is only removing descendents
        //restoreNode(originalFocusedNode);
    }
}

function handleRemoveAncestors( event ) {

    if (focusedNode) {

        let predecessors = focusedNode.predecessors().nodes();

        // temporarily remove focusedNode to enable the predecessor check below
        let originalFocusedNode = removeNode(focusedNode);

        function inPredecessors(node) {
            return predecessors.contains(node);
        }

        // strict ancestors only:
        //   only remove ancestors for whom all successors are ALSO in the
        //   predecessor group.
        // This keeps nodes that have outgoing edges to nodes that are not
        // predecessors of the focusedNode
        for (let curNode of predecessors) {
            if (curNode.predecessors().nodes().every(inPredecessors)) {
                // FUTURE: check if any successors of this node are now isolated?
                removeNode(curNode);
            }
        }

        // restore focusedNode so the net effect is only removing ancestors
        restoreNode(originalFocusedNode);
    }
}

function handleToggleImports( event ) {
    let hideImportsButton = document.getElementById("hide_imports_btn");

    if (hiddenImportNodes) {

        cy.add(hiddenImportNodes);

        // we might be attempting to add edges to nodes that are gone
        // so add one at a time and catch exceptions instead of cy.add()
        // FUTURE: find a better way to filter edges to nodes that are gone
        for (let curEdge of hiddenImportEdges) {
            try {
                cy.add(curEdge);
            } catch (error) {
                if (error.message.match("Can not create edge `.*` with nonexistant") == null) {
                    console.log('Unexpected error');
                    console.dir(error);
                }
            }
        }

        hiddenImportNodes = null;
        hiddenImportEdges = null;

        // redo focus styling to include newly-added imports
        removeFocus();
        if (focusedNode) {
            addFocus(focusedNode);
        }

        hideImportsButton.innerHTML = "Hide Imports";
        hideImportsButton.classList.remove('pressed');
    }
    else {
        hiddenImportNodes = cy.$('node[import = 1]');
        hiddenImportEdges = hiddenImportNodes.connectedEdges();

        if (hiddenImportNodes.contains(focusedNode)) {
            focusedNode = null;
            removeFocus();
        }

        cy.remove(hiddenImportNodes); // removes edges too

        hideImportsButton.innerHTML = "Show Imports";
        hideImportsButton.classList.add('pressed');
    }
}

function handleRedoLayout( event ) {
    cy.layout(default_layout).run();
}

function handleFuncSearch( event ) {
    let search_input = document.getElementById("func_search_input");
    let search_text = search_input.value;
    //console.log(`Function search was triggered: ${search_text}`);

    // Test exact matches and then try prefix matching
    let exact_matches = cy.nodes(`[label = "${search_text}"]`);
    // Do nothing on more than one match or none
    if (exact_matches.length == 1) {
        cy.center(exact_matches);
        return;
    }

    let prefix_matches = cy.filter( function(element, i) {
        return element.isNode() && element.data('label').startsWith(search_text);
    });
    // NOTE: the text color will indicate whether this was a good idea
    if (prefix_matches.length == 1) {
        cy.center(prefix_matches);
    }
}

function handleSearchInputChange( event ) {
    let input_element = event.target;
    let search_text = event.target.value
    //console.log(`Search input change: "${search_text}"`)

    if (search_text.length >= 3) {
        let exact_match = cy.nodes(`[label = "${search_text}"]`);
        if (exact_match.length > 0) {
            input_element.style.color = "green";
        }
        // shouldn't be collisions on label
        if (exact_match.length > 1) {
            input_element.style.color = "purple";
            console.log(`WARNING: Multiple (${exact_match.length}) exact matches for "${search_text}"!?`);
            return;
        }

        let prefix_matches = cy.filter( function(element, i) {
            return element.isNode() && element.data('label').startsWith(search_text);
        });
        if (prefix_matches.length == 1) {
            input_element.style.color = "green";
        }
        else if (prefix_matches.length == 0) {
            input_element.style.color = "red";
        }
        else {  // prefix_matches.length > 1
            input_element.style.color = "orange";
        }
    }
    // else text isn't long enought to start color indication (search still works though)
    else {
        input_element.style.color = "black";
    }
}

function getCoverageGradient( ele ) {
    let stop_position = parseInt(ele.data('coverage_percent'));
    let stop_pos_str = `0% ${stop_position}% ${stop_position}%`
    return stop_pos_str
}

// Add and remove coverage styling
function handleToggleCoverage( event ) {
    let toggleCoverageButton = document.getElementById('toggle_coverage_btn')
    if (coverageStylingOn) {
        // remove styling for classes
        cy.nodes('node[blocks_covered = 0]').removeClass('uncovered');
        cy.nodes('node[blocks_covered > 0]').removeClass('covered');
        cy.edges('edge[covered > 0]').removeClass('covered');

        toggleCoverageButton.classList.remove('pressed');
    } else {
        // add styling for classes
        cy.nodes('node[blocks_covered = 0]').addClass('uncovered');
        cy.nodes('node[blocks_covered > 0]').addClass('covered');
        cy.edges('edge[covered > 0]').addClass('covered');

        toggleCoverageButton.classList.add('pressed');
    }

    coverageStylingOn = !coverageStylingOn;
}

function handleResetGraph( event ) {
    if (json_contents) {
        renderCytoscape(json_contents);
    }
}

//
// callback to start cytoscape once page is loaded
//
function renderCytoscape(model){


    // Instantiate cytoscape graph
    cy = cytoscape({
        container: container,
        elements: model.elements, // list of graph elements (nodes and edges)
        layout: default_layout,
        wheelSensitivity: 0.45,
        /* minZoom: 0.1, */
        /* maxZoom: 5, */

        // default style located at: cy.style()._private.defaultProperties
        style: [
            {
                selector: 'node',
                style: {
                'background-color': light_green,
                'label': 'data(label)',
                'border-color': grey,
                'border-width': 3,
                'width': size_jumbo,
                'height': size_jumbo,
                }
            },
            {
                selector: 'edge',
                style: {
                'line-color': subtle_grey,
                'target-arrow-color': subtle_grey,
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                }
            },
            {
                selector: 'node[label]',
                style: {
                'color': white,
                }
            },
            {
                selector: `node[complexity < ${complexity_large}]`,
                style: { 'width': size_large, 'height': size_large }
            },
            {
                selector: `node[complexity < ${complexity_medium}]`,
                style: { 'width': size_medium, 'height': size_medium }
            },
            {
                selector: `node[complexity < ${complexity_small}]`,
                style: { 'width': size_small, 'height': size_small }
            },
            {
                selector: `node[complexity < ${complexity_tiny}]`,
                style: { 'width': size_tiny, 'height': size_tiny }
            },
            {
                selector: 'node[import = 1]',
                style: {
                'background-color': orange,
                'shape': 'diamond',
                'width': size_small,
                'height': size_small,
                }
            },
            {
                selector: 'node[visited = 1]',
                style: {
                'border-color': dark_blue,
                }
            },
            {
                selector: 'node[current_function]',
                style: {
                'background-color': bright_red,
                }
            },
            {
                selector: 'node.covered',
                style: {
                    //'background-color': red,
                    //'background-color': 'mapData(coverage_percent, 0, 100, red, blue)',
                    'background-fill': 'linear-gradient',
                    'background-gradient-direction': 'to-top',
                    // NOTE: backtick format strings are not accepted in the line below
                    'background-gradient-stop-colors': covered_color + ' ' + covered_color + ' black',
                    'border-color': covered_border_color,
                    'background-gradient-stop-positions': getCoverageGradient,
                }
            },
            {
                selector: 'edge.covered',
                style: {
                    'line-color': covered_border_color,
                    'target-arrow-color': covered_border_color,
                }
            },
            {
                selector: '.uncovered',
                style: {
                    'background-color': subtle_grey,
                    'border-color': grey,
                }
            },
            {
                selector: '.background',
                style: {
                'opacity': '0.5',
                }
            },
            {
                selector: '.from',
                style: {
                'background-color': from_color,
                'line-color': from_color,
                'target-arrow-color': from_color,
                }
            },
            {
                selector: '.to',
                style: {
                'background-color': to_color,
                'line-color': to_color,
                'target-arrow-color': to_color,
                }
            },
            {
                selector: '.focused',
                style: {
                'background-color': selected_color,
                }
            },
        ]
    });

    cy.$('node').on('click', handleNodeClick);

    let coverageAvailable = !(cy.nodes().data('coverage_percent') === null);
    if (!coverageAvailable) {
        document.getElementById("toggle_coverage_btn").disabled = true;
    } else {
        document.getElementById("toggle_coverage_btn").disabled = false;
    }

    // reset focus state on graph redraw
    if (focusedNode) {
        focusedNode = null;
    }
    removeFocus();
    hideSidebarMetadata();
    sidebarHeaderClickable(false);

    // Make "Hide Imports" stay toggled on if it's on via clear/redo
    if (hiddenImportNodes) {
        hiddenImportNodes = null;
        hiddenImportEdges = null;
        document.getElementById("hide_imports_btn").innerHTML = "Hide Imports";
        handleToggleImports(null);
    }
    // Persist coverage styling if toggled on
    if (coverageStylingOn) {
        handleToggleCoverage(null); // turn it off to reset
        handleToggleCoverage(null); // turn it back on
    }

}
