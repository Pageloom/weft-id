# Group Hierarchy

WeftID groups support a directed acyclic graph (DAG) model. Unlike a simple tree, groups can have multiple parents.

## Parent-child relationships

Any group can be added as a child of another group. The only constraint is that a group cannot be both an ancestor and a descendant of the same group (no cycles).

For example:

- Groups A and B can both be children of C
- A can also become a child of B (creating multiple paths to A)
- But if A is already an ancestor of B, then A cannot become B's child

## Managing relationships

From a group's detail page, the **Relationships** tab lists the group's parents and children next to a graph of its neighborhood.

- **Parent Groups**: Select a group and click **Add** to attach this group under it
- **Child Groups**: Select a group and click **Add** to attach it under this group
- **Remove**: Detach a parent-child link without deleting either group

Members of a child group are inherited members of every ancestor. See [Membership Management](membership-management.md#inherited-membership).

Groups synced from an identity provider are attached under that provider's umbrella group automatically.

## Graph view

Click **Graph** on **Directory > Groups** to see the full hierarchy. Click a group to highlight its parent and child edges. Double-click to open it.

The toolbar edits the hierarchy directly:

- **Add relationship**: Click a group and drag it to its new parent
- **Cut relationship**: Click a relationship line to remove it
- **Add group**: Create a group without leaving the graph
- **Edit layout**: Drag groups to reposition them. Hold **Shift** to move a group with its children. Click **Save layout** to keep the arrangement, or **Reset layout** to start over
