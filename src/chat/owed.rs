//! What this device owes somebody else and has not managed to deliver.
//!
//! **Six queues with one shape.** Each is filled by a loop that deposits
//! something into other people's boxes on their behalf and catches its own
//! failure, because one unreachable person must not stop the rest — so each
//! needs somewhere to put what did not get out, and something that comes back
//! for it. A block that closes a channel at the mediator, a delivery receipt,
//! an unsend, a re-introduction carrying a new wake ticket or a fresh key
//! package, a published name and picture, a room address.
//!
//! ## Why this is here and not in the client
//!
//! The rule was learned one site at a time over four runs of the same audit,
//! and each run found the sibling the last repair had not visited: the queue
//! given to blocking was not given to declining, to taking back a request, to
//! leaving a room or to a rotated handle; the one given to contacts was not
//! given to rooms; the one given to one introduction loop was not given to the
//! other; the room's was the only one never written to disk. None of that is
//! about the network — it is bookkeeping, and bookkeeping written twice is
//! bookkeeping that disagrees with itself. The harness is a second client of
//! this protocol and had its own copy of some of these; now there is one.
//!
//! What stays outside: the deposits themselves, which need a network, and the
//! file the queue is stored in, which needs a disk. This decides *what* is
//! owed and *what has been paid*, and nothing else.
//!
//! ## The invariant that cost the most to learn
//!
//! **What is retired is exactly what went out, never "the key".** A deposit is
//! a whole network round trip, and the person can tap delete a second time
//! during it, or a second blob can arrive and append its id to the very list
//! being sent. Clearing the entry on success then erased ids that had never
//! travelled, and the drain that followed found the queue empty — so on this
//! device the message showed as taken back, and on theirs it stayed for good.
//! [`Owed::paid`] takes the ids that were actually sent, and keeps the rest.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Which queue an entry belongs to.
///
/// Named rather than numbered so a stored file from an older build says what it
/// meant, and so adding a seventh is a compile error everywhere it matters
/// rather than a silent gap — which is exactly how the first six went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owes {
    /// A box the mediator has not been told to destroy. Blocking, declining,
    /// taking back a request, leaving a room, rotating the handle.
    Destroy,
    /// A delivery receipt. Sent once, so it cannot be re-derived.
    Acknowledge,
    /// An unsend the far side has not been told about.
    Retract,
    /// A fresh introduction: a wake ticket that changed, or a key package the
    /// far side has spent and needs replaced.
    Reintroduce,
    /// A published name and picture — including the empty one that asks them to
    /// forget what they had.
    Reprofile,
    /// Our address inside a room, which is the only way anybody there learns
    /// where to write to us.
    Reannounce,
}

impl Owes {
    /// Every queue, for a caller that has to visit all of them.
    pub const ALL: [Owes; 6] = [
        Owes::Destroy,
        Owes::Acknowledge,
        Owes::Retract,
        Owes::Reintroduce,
        Owes::Reprofile,
        Owes::Reannounce,
    ];

    /// Whether entries carry ids of their own — a receipt and an unsend name
    /// messages; the rest name only who or what is owed.
    pub fn carries_ids(self) -> bool {
        matches!(self, Owes::Acknowledge | Owes::Retract)
    }
}

/// One thing to attempt: who it is owed to, and which ids it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Work {
    pub owes: Owes,
    /// A contact index, a room id or a handle rotation — whatever names the
    /// recipient for that queue. Opaque here on purpose: deriving an address
    /// needs the seed, and this is bookkeeping.
    pub target: String,
    /// Empty for the queues that carry none.
    pub ids: Vec<String>,
}

/// Everything owed, and nothing else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    /// Target → ids. The ids are empty for queues that do not carry them, which
    /// keeps one shape rather than six.
    #[serde(flatten)]
    entries: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

fn key(owes: Owes) -> &'static str {
    match owes {
        Owes::Destroy => "destroy",
        Owes::Acknowledge => "acknowledge",
        Owes::Retract => "retract",
        Owes::Reintroduce => "reintroduce",
        Owes::Reprofile => "reprofile",
        Owes::Reannounce => "reannounce",
    }
}

impl Owed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read back what was stored. An unreadable file is an empty queue rather
    /// than an error: what is lost is one retry, and refusing to open the chat
    /// because a queue file is corrupt would cost every conversation on the
    /// device.
    pub fn from_json(stored: &str) -> Self {
        serde_json::from_str(stored).unwrap_or_default()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.values().all(|q| q.is_empty())
    }

    /// Record a debt. Ids accumulate: two unsends to one person are one
    /// deposit carrying both, not two deposits racing each other.
    pub fn owe(&mut self, owes: Owes, target: &str, ids: &[String]) {
        let queue = self.entries.entry(key(owes).into()).or_default();
        let held = queue.entry(target.to_string()).or_default();
        held.extend(ids.iter().cloned());
    }

    /// Everything to attempt now, in a stable order so two runs of the same
    /// state do the same thing.
    pub fn work(&self) -> Vec<Work> {
        let mut out = Vec::new();
        for owes in Owes::ALL {
            let Some(queue) = self.entries.get(key(owes)) else {
                continue;
            };
            for (target, ids) in queue {
                out.push(Work {
                    owes,
                    target: target.clone(),
                    ids: ids.iter().cloned().collect(),
                });
            }
        }
        out
    }

    /// **Retire exactly what went out.** See the invariant at the top of this
    /// file: anything appended while the deposit was in flight is still owed,
    /// and dropping it is a message the far side never hears about.
    ///
    /// For a queue that carries no ids, the debt is the target itself and this
    /// clears it.
    pub fn paid(&mut self, owes: Owes, target: &str, ids: &[String]) {
        let Some(queue) = self.entries.get_mut(key(owes)) else {
            return;
        };
        if !owes.carries_ids() {
            queue.remove(target);
        } else if let Some(held) = queue.get_mut(target) {
            for id in ids {
                held.remove(id);
            }
            if held.is_empty() {
                queue.remove(target);
            }
        }
        if queue.is_empty() {
            self.entries.remove(key(owes));
        }
    }

    /// There is nobody to tell any more — blocked, declined, or a room walked
    /// out of. Distinct from [`Owed::paid`] because it is not payment, and the
    /// distinction is what stopped a queue holding an address that does not
    /// exist and retrying it on every collection for the life of the install.
    pub fn forget(&mut self, owes: Owes, target: &str) {
        if let Some(queue) = self.entries.get_mut(key(owes)) {
            queue.remove(target);
            if queue.is_empty() {
                self.entries.remove(key(owes));
            }
        }
    }

    /// Everything owed by an identity that is being replaced.
    ///
    /// **Starting over resets the contact-index counter to zero** while every
    /// address is derived from a seed that did not change — so a debt left here
    /// is aimed at whoever is added next. A queued block was the worst of them:
    /// the newcomer's box created by the join, then destroyed and tombstoned by
    /// the next collection, with their card naming a dead address and the row
    /// on this side looking perfectly healthy.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// **The one that cost the most.** A deposit is a round trip, and what
    /// arrives during it is still owed.
    #[test]
    fn what_arrives_while_we_are_sending_is_still_owed() {
        let mut owed = Owed::new();
        owed.owe(Owes::Retract, "7", &ids(&["a"]));

        // The deposit goes out carrying "a" — and while it is in flight the
        // person deletes a second message.
        let sending = ids(&["a"]);
        owed.owe(Owes::Retract, "7", &ids(&["b"]));

        owed.paid(Owes::Retract, "7", &sending);

        assert_eq!(
            owed.work(),
            vec![Work {
                owes: Owes::Retract,
                target: "7".into(),
                ids: ids(&["b"]),
            }],
            "the second unsend was retired by a send that never carried it"
        );
    }

    /// The same shape, in the queue where it means a tick that never comes.
    #[test]
    fn a_receipt_that_did_not_go_is_kept() {
        let mut owed = Owed::new();
        owed.owe(Owes::Acknowledge, "3", &ids(&["m1", "m2"]));
        owed.paid(Owes::Acknowledge, "3", &ids(&["m1"]));
        assert_eq!(owed.work()[0].ids, ids(&["m2"]));

        owed.paid(Owes::Acknowledge, "3", &ids(&["m2"]));
        assert!(owed.is_empty(), "a queue that paid everything is empty");
    }

    /// A queue that carries no ids is paid by naming the target.
    #[test]
    fn a_debt_without_ids_is_paid_whole() {
        let mut owed = Owed::new();
        owed.owe(Owes::Destroy, "c:4", &[]);
        owed.owe(Owes::Reannounce, "room-a", &[]);

        owed.paid(Owes::Destroy, "c:4", &[]);
        assert_eq!(owed.work().len(), 1);
        assert_eq!(owed.work()[0].owes, Owes::Reannounce);
    }

    /// Nobody to tell is not the same as told, and keeping them apart is what
    /// stops a queue that can never drain.
    #[test]
    fn a_debt_to_somebody_who_is_gone_is_forgotten_rather_than_retried() {
        let mut owed = Owed::new();
        owed.owe(Owes::Reprofile, "9", &[]);
        owed.forget(Owes::Reprofile, "9");
        assert!(owed.is_empty());
    }

    /// Two debts to one person are one deposit carrying both.
    #[test]
    fn ids_for_one_target_accumulate() {
        let mut owed = Owed::new();
        owed.owe(Owes::Retract, "1", &ids(&["a"]));
        owed.owe(Owes::Retract, "1", &ids(&["b"]));
        assert_eq!(owed.work().len(), 1);
        assert_eq!(owed.work()[0].ids, ids(&["a", "b"]));
    }

    /// It has to survive the process, or what could not be delivered is
    /// forgotten the next time the phone kills the app — and nothing tries
    /// again, because the event that filled the queue does not happen twice.
    #[test]
    fn it_survives_being_written_down_and_read_back() {
        let mut owed = Owed::new();
        owed.owe(Owes::Acknowledge, "2", &ids(&["x"]));
        owed.owe(Owes::Destroy, "k:3", &[]);
        owed.owe(Owes::Reannounce, "room-b", &[]);

        let back = Owed::from_json(&owed.to_json());
        assert_eq!(back, owed);
        assert_eq!(back.work().len(), 3);
    }

    /// A file we cannot read costs one retry, not the whole conversation.
    #[test]
    fn an_unreadable_file_is_an_empty_queue() {
        assert!(Owed::from_json("{ not json").is_empty());
    }

    /// Nothing is carried into the next life: the index counter goes back to
    /// zero while the addresses do not.
    #[test]
    fn starting_over_owes_nobody_anything() {
        let mut owed = Owed::new();
        owed.owe(Owes::Destroy, "c:0", &[]);
        owed.clear();
        assert!(owed.is_empty());
    }

    /// The order two runs attempt things in has to be the same, or a failure
    /// that depends on order is a failure nobody can reproduce.
    #[test]
    fn the_order_of_work_is_stable() {
        let mut a = Owed::new();
        a.owe(Owes::Reprofile, "2", &[]);
        a.owe(Owes::Destroy, "c:1", &[]);
        let mut b = Owed::new();
        b.owe(Owes::Destroy, "c:1", &[]);
        b.owe(Owes::Reprofile, "2", &[]);
        assert_eq!(a.work(), b.work());
    }
}
