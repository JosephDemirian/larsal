//! Groups: the tree that holds the entries (MOD-02; file form FMT-11.6).

use crate::custom_data::CustomData;
use crate::entry::Entry;
use crate::icon::{GROUP_DEFAULT, Icon};
use crate::times::{Time, Times};
use crate::unknown::UnknownElement;
use crate::uuid::Uuid;

/// A group switch: inherit from the parent, on or off (FMT-11.9, MOD-02.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Switch {
    /// `null` in the file.
    #[default]
    Inherit,
    /// `true`.
    On,
    /// `false`.
    Off,
}

/// One group with its entries and child groups.
///
/// Guarantees: the tree is owned, so one root and no cycles hold by
/// construction (MOD-02.1); id rules are in `invariants.rs`.
#[derive(PartialEq, Eq)]
pub struct Group {
    /// Never the zero id; unique among groups.
    pub uuid: Uuid,
    /// Name, any text.
    pub name: String,
    /// Notes, kept exactly.
    pub notes: String,
    /// Tags text, kept raw: not split, not sorted (FMT-11.27).
    pub tags: String,
    /// Standard icon number or custom icon.
    pub icon: Icon,
    /// The times block.
    pub times: Times,
    /// Whether the sidebar shows the children.
    pub expanded: bool,
    /// Default auto-type sequence; empty means inherit.
    pub default_sequence: String,
    /// Auto-type switch.
    pub auto_type: Switch,
    /// Search switch.
    pub searching: Switch,
    /// Carried only (MOD-02.11).
    pub last_top_visible_entry: Option<Uuid>,
    /// Plug-in data.
    pub custom_data: CustomData,
    /// Group it sat in before its last move, when set.
    pub previous_parent: Option<Uuid>,
    /// Live entries in stored order.
    pub entries: Vec<Entry>,
    /// Child groups in stored order.
    pub groups: Vec<Group>,
    /// Kept unknown children of `Group` (FMT-11.45).
    pub unknown: Vec<UnknownElement>,
}

impl Group {
    /// A deep copy of the group, its entries (with history) and its whole
    /// subtree, ids and times included (MOD-02.22 starts from this).
    #[must_use]
    pub fn duplicate(&self) -> Group {
        Group {
            uuid: self.uuid,
            name: self.name.clone(),
            notes: self.notes.clone(),
            tags: self.tags.clone(),
            icon: self.icon,
            times: self.times.clone(),
            expanded: self.expanded,
            default_sequence: self.default_sequence.clone(),
            auto_type: self.auto_type,
            searching: self.searching,
            last_top_visible_entry: self.last_top_visible_entry,
            custom_data: self.custom_data.clone(),
            previous_parent: self.previous_parent,
            entries: self.entries.iter().map(|e| e.duplicate(true)).collect(),
            groups: self.groups.iter().map(Group::duplicate).collect(),
            unknown: self.unknown.clone(),
        }
    }

    /// A new group with the defaults of the MOD-02 table: icon 48, expanded,
    /// both switches Inherit, every time `now`.
    #[must_use]
    pub fn new(uuid: Uuid, name: String, now: Time) -> Group {
        Group {
            uuid,
            name,
            notes: String::new(),
            tags: String::new(),
            icon: GROUP_DEFAULT,
            times: Times::all(now),
            expanded: true,
            default_sequence: String::new(),
            auto_type: Switch::Inherit,
            searching: Switch::Inherit,
            last_top_visible_entry: None,
            custom_data: CustomData::default(),
            previous_parent: None,
            entries: Vec::new(),
            groups: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// This group and every group below it, depth first, parents first.
    #[must_use]
    pub fn subtree(&self) -> Vec<&Group> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(g) = stack.pop() {
            out.push(g);
            stack.extend(g.groups.iter().rev());
        }
        out
    }

    /// The group with id `uuid` in this subtree.
    #[must_use]
    pub fn find_group(&self, uuid: Uuid) -> Option<&Group> {
        self.subtree().into_iter().find(|g| g.uuid == uuid)
    }

    /// Every live entry in this subtree, group by group in `subtree` order.
    pub fn all_entries(&self) -> impl Iterator<Item = &Entry> {
        self.subtree().into_iter().flat_map(|g| g.entries.iter())
    }
}

/// Ids, counts and flags only, never user text (LD-88).
impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Group")
            .field("uuid", &self.uuid)
            .field("groups", &self.groups.len())
            .field("entries", &self.entries.len())
            .field("icon", &self.icon)
            .field("expanded", &self.expanded)
            .field("auto_type", &self.auto_type)
            .field("searching", &self.searching)
            .field("custom_data", &self.custom_data.items.len())
            .field("unknown", &self.unknown.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtree_is_depth_first_in_stored_order() {
        let mut root = Group::new(Uuid([1; 16]), "R".into(), Time(0));
        let mut a = Group::new(Uuid([2; 16]), "A".into(), Time(0));
        a.groups
            .push(Group::new(Uuid([3; 16]), "A1".into(), Time(0)));
        root.groups.push(a);
        root.groups
            .push(Group::new(Uuid([4; 16]), "B".into(), Time(0)));
        let names: Vec<&str> = root.subtree().iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["R", "A", "A1", "B"]);
        assert_eq!(
            root.find_group(Uuid([3; 16])).map(|g| g.name.as_str()),
            Some("A1")
        );
        assert!(root.find_group(Uuid([9; 16])).is_none());
    }

    #[test]
    fn mod_02_new_group_defaults() {
        let g = Group::new(Uuid([1; 16]), "N".into(), Time(5));
        assert_eq!(g.icon, Icon::Standard(48));
        assert!(g.expanded);
        assert_eq!(
            (g.auto_type, g.searching),
            (Switch::Inherit, Switch::Inherit)
        );
        assert_eq!(g.times, Times::all(Time(5)));
    }
}
