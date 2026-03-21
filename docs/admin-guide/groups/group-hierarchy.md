# Group Hierarchy

WeftId groups support a directed acyclic graph (DAG) model. Unlike a simple tree, groups can have multiple parents.

## Parent-child relationships

Any group can be added as a child of another group. The only constraint is that a group cannot be both an ancestor and a descendant of the same group (no cycles).

For example:

- Groups A and B can both be children of C
- A can also become a child of B (creating multiple paths to A)
- But if A is already an ancestor of B, then A cannot become B's child

## Managing relationships

From a group's detail page, the **Relationships** tab shows the group's parents and children.

- **Add parent** -- Attach this group under another group
- **Add child** -- Attach another group under this one
- **Remove relationship** -- Detach a parent-child link without deleting either group

## Graph visualization

The group list and detail pages include an interactive graph view. The graph shows the full hierarchy with parent-child connections.

**Rearranging nodes.** Drag any node to reposition it. Hold **Shift** while dragging to move the node and all its descendants together, preserving relative positions. Your arrangement is saved automatically.

**Tooltips.** Hover over a node to see group details. Tooltips reposition automatically to avoid overlapping connected nodes and edges.
