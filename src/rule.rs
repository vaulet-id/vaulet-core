//! How an organisation says who is enough to act for it (ADR 0030).
//!
//! This lives in the core rather than in the issuer because **everybody who
//! verifies a credential evaluates it**: a bank, a border post, another
//! company's system. It is published in the organisation's identity document,
//! so its cost is paid by every reader for ever, and that is the reason it
//! stops where it does.
//!
//! ```text
//! alternative 1:   1 of [chair]
//! alternative 2:   1 of [executive]   and   2/3 of [non-executive]
//!
//! satisfied when every requirement of ANY ONE alternative is met
//! ```
//!
//! Two nested loops and one multiplication. It covers every board rule anybody
//! here could name, and a general expression language would mean defining a
//! language exactly and every verifier writing an interpreter that agrees with
//! ours — the trap that produced five bugs in one week, multiplied by everyone
//! who reads it.
//!
//! **A count and a fraction are both here, because neither can be written as
//! the other.** "Two-thirds of the directors" is how company law and articles
//! of association are written, and it adjusts itself when the board changes;
//! "two directors" stays two. Offering only whole numbers means a sixth
//! director silently weakens every rule, and offering only fractions means no
//! rule can say "any two of you".
//!
//! **A member may be an organisation.** Two companies opening a third is
//! ordinary. C's rule names A and B; A signs with A's key, and A's key was
//! usable only because A's own rule was satisfied. The nesting is in the
//! members, not in the language — which is also what the certificate says: it
//! names A and B, never A's directors, because A may replace them without
//! telling C. Resolving that chain is the caller's job and carries two
//! obligations it must not skip: **refuse a cycle, and bound the depth.**
//!
//! Limits — how much, until when — are deliberately not here. They belong to
//! the mandate's scope (ADR 0029). **A rule says who is enough. A mandate says
//! what they authorised.**

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// A named set of people (or organisations) the rule can talk about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// What the alternatives call it: `chair`, `executive`.
    pub id: String,
    /// Who is in it, as DIDs. A `did:jwk` is a person's device; a `did:web` is
    /// another organisation, which signs under its own rule.
    pub members: Vec<String>,
}

/// How much of one group an alternative needs.
///
/// **A count and a fraction are not the same thing, and neither can be written
/// as the other.** "Two directors" stays two when a sixth joins; "two-thirds"
/// becomes four. Collapsing them — writing a count as `2/1` — was tried here
/// and is wrong in the only way that matters: `2/1` of a group means twice
/// everybody in it, and the test for a plain count caught it immediately.
///
/// So both are spelled out, and which one an organisation meant is a decision
/// it makes rather than one the format makes for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HowMany {
    /// A fixed number of them, whatever the group grows to.
    Count { count: u32 },
    /// A share of the group **as it stands when this is checked**, which is how
    /// company law and articles of association are written. Checked by
    /// cross-multiplying — never as a decimal, and with no rounding rule:
    /// `0.667` is not `2/3`, and "round up" against "round up when it exceeds"
    /// is a disagreement waiting to happen between two implementations in two
    /// languages. There is nothing here to interpret.
    Fraction { num: u32, den: u32 },
}

/// How much of one group an alternative needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    /// Which [`Group::id`].
    pub group: String,
    #[serde(flatten)]
    pub how_many: HowMany,
}

impl Need {
    pub fn count(group: &str, n: u32) -> Self {
        Self { group: group.into(), how_many: HowMany::Count { count: n } }
    }

    pub fn fraction(group: &str, num: u32, den: u32) -> Self {
        Self { group: group.into(), how_many: HowMany::Fraction { num, den } }
    }

    /// Whether `signed` of a group of `size` is enough.
    ///
    /// A fraction is of the group as it stands **now**, not as it stood when
    /// the signatures were made. A mandate that was enough yesterday stops
    /// being enough the day the board grows, which is correct for a rule still
    /// in force and surprising enough to be worth saying out loud.
    fn met(&self, signed: u64, size: u64) -> bool {
        match self.how_many {
            HowMany::Count { count } => signed >= count as u64,
            HowMany::Fraction { num, den } => signed * den as u64 >= num as u64 * size,
        }
    }
}

/// One way to satisfy the rule: every requirement in it must be met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alternative {
    pub needs: Vec<Need>,
}

/// Who is enough to act for an organisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub groups: Vec<Group>,
    /// Satisfied when any one of these is.
    pub alternatives: Vec<Alternative>,
}

impl Rule {
    /// The rule an organisation has while it is still one person: whoever holds
    /// a key may act. What every organisation is created with.
    pub fn one_of(members: Vec<String>) -> Self {
        Self {
            groups: vec![Group { id: "all".into(), members }],
            alternatives: vec![Alternative { needs: vec![Need::count("all", 1)] }],
        }
    }

    /// Whether these signatures are enough.
    ///
    /// `signers` are DIDs that have **already been verified as having signed**;
    /// this decides only whether the set is enough. Duplicates count once — a
    /// director who signed twice is one director.
    pub fn satisfied_by(&self, signers: &[String]) -> bool {
        self.alternatives.iter().any(|alt| {
            alt.needs.iter().all(|need| {
                let Some(group) = self.groups.iter().find(|g| g.id == need.group) else {
                    // A requirement naming a group that does not exist cannot be
                    // met. `check` refuses such a rule at the door; if one is
                    // reached anyway, failing shut is the only safe reading.
                    return false;
                };
                let signed = group
                    .members
                    .iter()
                    .filter(|m| signers.contains(m))
                    .count() as u64;
                need.met(signed, group.members.len() as u64)
            })
        })
    }

    /// Whether this rule is one anybody could ever satisfy.
    ///
    /// **Checked when a rule is set, not when it is used.** A rule that cannot
    /// pass locks an organisation out of its own identity, and the moment to
    /// find that out is while somebody is still looking at the screen that set
    /// it — not at the end of a publish six weeks later.
    pub fn check(&self) -> Result<()> {
        let bad = |m: String| Err(CoreError::Credential(m));

        if self.alternatives.is_empty() {
            return bad("a rule with no alternatives can never be satisfied".into());
        }
        for group in &self.groups {
            if group.members.is_empty() {
                return bad(format!("group {} has nobody in it", group.id));
            }
            if self.groups.iter().filter(|g| g.id == group.id).count() > 1 {
                return bad(format!("there are two groups called {}", group.id));
            }
        }
        for alt in &self.alternatives {
            if alt.needs.is_empty() {
                // Not pedantry: an empty alternative is satisfied by nobody
                // signing anything, which makes the whole rule vacuous while
                // looking like it says something.
                return bad("an alternative with no requirements needs no signatures".into());
            }
            for need in &alt.needs {
                let Some(group) = self.groups.iter().find(|g| g.id == need.group) else {
                    return bad(format!("no group is called {}", need.group));
                };
                match need.how_many {
                    // Nobody is not a requirement; it is an alternative that
                    // passes on its own while looking like it says something.
                    HowMany::Count { count: 0 } => {
                        return bad(format!("{}: needing none of them is not a rule", need.group))
                    }
                    HowMany::Fraction { den: 0, .. } => {
                        return bad(format!("{}: a fraction cannot be out of zero", need.group))
                    }
                    _ => {}
                }
                // More than everybody. Expressible, never satisfiable, and the
                // likeliest way to write a rule that quietly cannot pass.
                let size = group.members.len() as u64;
                if !need.met(size, size) {
                    return bad(format!(
                        "{} needs more of {} than there are in it",
                        match need.how_many {
                            HowMany::Count { count } => format!("{count}"),
                            HowMany::Fraction { num, den } => format!("{num}/{den}"),
                        },
                        need.group
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(groups: &[(&str, &[&str])], alts: &[&[(&str, u32, u32)]]) -> Rule {
        Rule {
            groups: groups
                .iter()
                .map(|(id, m)| Group {
                    id: (*id).into(),
                    members: m.iter().map(|s| (*s).to_string()).collect(),
                })
                .collect(),
            alternatives: alts
                .iter()
                .map(|needs| Alternative {
                    // den 0 spells "a plain count", so a test reads the way
                    // the rule does: (group, 2, 0) is two of them, (group, 2, 3)
                    // is two-thirds of them.
                    needs: needs
                        .iter()
                        .map(|(g, num, den)| {
                            if *den == 0 {
                                Need::count(g, *num)
                            } else {
                                Need::fraction(g, *num, *den)
                            }
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn signed(who: &[&str]) -> Vec<String> {
        who.iter().map(|s| (*s).to_string()).collect()
    }

    /// The shape real boards use, and the one a plain count cannot express:
    /// one from each of two groups.
    #[test]
    fn an_alternative_needs_every_group_in_it() {
        let r = rule(
            &[("exec", &["a", "b", "c"]), ("non-exec", &["d", "e"])],
            &[&[("exec", 1, 0), ("non-exec", 1, 0)]],
        );
        assert!(r.check().is_ok());

        assert!(r.satisfied_by(&signed(&["a", "d"])));
        assert!(r.satisfied_by(&signed(&["c", "e"])));
        // Two from one group is not one from each, however many there are.
        assert!(!r.satisfied_by(&signed(&["a", "b"])));
        assert!(!r.satisfied_by(&signed(&["d", "e"])));
    }

    /// Any one alternative is enough — "the chairman alone, or any two others".
    #[test]
    fn any_one_alternative_is_enough() {
        let r = rule(
            &[("chair", &["x"]), ("rest", &["a", "b", "c"])],
            &[&[("chair", 1, 0)], &[("rest", 2, 0)]],
        );
        assert!(r.satisfied_by(&signed(&["x"])));
        assert!(r.satisfied_by(&signed(&["a", "b"])));
        assert!(!r.satisfied_by(&signed(&["a"])));
    }

    /// The whole reason fractions exist: the rule adjusts itself when the board
    /// changes, and nobody has to remember to come back and edit it.
    #[test]
    fn a_fraction_tightens_as_the_board_grows() {
        let three = rule(&[("board", &["a", "b", "c"])], &[&[("board", 2, 3)]]);
        assert!(three.satisfied_by(&signed(&["a", "b"])));

        let four = rule(&[("board", &["a", "b", "c", "d"])], &[&[("board", 2, 3)]]);
        // 2/3 of four is 2.67, so two is no longer enough — without anybody
        // touching the rule.
        assert!(!four.satisfied_by(&signed(&["a", "b"])));
        assert!(four.satisfied_by(&signed(&["a", "b", "c"])));
    }

    /// Pinned to a whole number instead, the same board change weakens the rule
    /// in silence. This is what the fraction is bought with.
    #[test]
    fn a_whole_number_does_not_tighten_and_that_is_the_point() {
        let four = rule(&[("board", &["a", "b", "c", "d"])], &[&[("board", 2, 0)]]);
        assert!(four.satisfied_by(&signed(&["a", "b"])));
    }

    /// Cross-multiplying, in the cases where a decimal and a rounding rule
    /// would be argued about. Pinned rather than derived: these are the answers
    /// Thai company law gives for "ไม่น้อยกว่าสองในสาม" of each size.
    #[test]
    fn two_thirds_needs_the_numbers_the_law_gives() {
        for (size, needed) in [(1, 1), (2, 2), (3, 2), (4, 3), (5, 4), (6, 4), (7, 5)] {
            let members: Vec<&str> = ["a", "b", "c", "d", "e", "f", "g"][..size].to_vec();
            let r = rule(&[("board", &members)], &[&[("board", 2, 3)]]);
            assert!(
                r.satisfied_by(&signed(&members[..needed])),
                "{needed} of {size} should be two-thirds"
            );
            if needed > 0 {
                assert!(
                    !r.satisfied_by(&signed(&members[..needed - 1])),
                    "{} of {size} should not be two-thirds",
                    needed - 1
                );
            }
        }
    }

    /// A director who signed twice is one director.
    #[test]
    fn the_same_signer_twice_is_one_signature() {
        let r = rule(&[("board", &["a", "b"])], &[&[("board", 2, 0)]]);
        assert!(!r.satisfied_by(&signed(&["a", "a"])));
    }

    /// What every organisation is created with, and it must let its one holder
    /// act — the alternative to this is an organisation locked out of itself on
    /// the day it is made.
    #[test]
    fn the_starting_rule_lets_the_one_holder_act() {
        let r = Rule::one_of(vec!["did:jwk:only".into()]);
        assert!(r.check().is_ok());
        assert!(r.satisfied_by(&signed(&["did:jwk:only"])));
        assert!(!r.satisfied_by(&[]));
    }

    /// A member may be an organisation: C is satisfied by A and B signing, and
    /// C's rule says nothing about how either of them decided.
    #[test]
    fn a_member_may_be_another_organisation() {
        let c = rule(
            &[("a", &["did:web:org.vaulet.id:a"]), ("b", &["did:web:org.vaulet.id:b"])],
            &[&[("a", 1, 1), ("b", 1, 1)]],
        );
        assert!(c.satisfied_by(&signed(&[
            "did:web:org.vaulet.id:a",
            "did:web:org.vaulet.id:b"
        ])));
        assert!(!c.satisfied_by(&signed(&["did:web:org.vaulet.id:a"])));
    }

    /// Every way of writing a rule that cannot pass is refused where somebody
    /// is still looking at the screen, not at the end of a publish weeks later.
    #[test]
    fn a_rule_nobody_could_satisfy_is_refused() {
        let cases = [
            rule(&[("board", &["a", "b"])], &[]),
            rule(&[("board", &["a", "b"])], &[&[]]),
            rule(&[("board", &["a", "b"])], &[&[("nobody", 1, 0)]]),
            // Written out rather than built, because the helper cannot spell
            // either of these — which is the point: they are shapes only a
            // hand-written document arrives with.
            Rule {
                groups: vec![Group { id: "board".into(), members: signed(&["a", "b"]) }],
                alternatives: vec![Alternative { needs: vec![Need::fraction("board", 1, 0)] }],
            },
            Rule {
                groups: vec![Group { id: "board".into(), members: signed(&["a", "b"]) }],
                alternatives: vec![Alternative { needs: vec![Need::count("board", 0)] }],
            },
            // Three of two.
            rule(&[("board", &["a", "b"])], &[&[("board", 3, 0)]]),
            // Five-quarters of everybody.
            rule(&[("board", &["a", "b", "c", "d"])], &[&[("board", 5, 4)]]),
        ];
        for r in cases {
            assert!(r.check().is_err(), "should be refused: {r:?}");
        }
        assert!(rule(&[("board", &[])], &[&[("board", 1, 0)]]).check().is_err());
    }

    /// Everybody is a rule, and a legitimate one.
    #[test]
    fn all_of_them_is_allowed() {
        let r = rule(&[("board", &["a", "b", "c"])], &[&[("board", 1, 1)]]);
        assert!(r.check().is_ok());
        assert!(r.satisfied_by(&signed(&["a", "b", "c"])));
        assert!(!r.satisfied_by(&signed(&["a", "b"])));
    }

    /// It travels in a public document, so it has to survive the trip.
    #[test]
    fn a_rule_round_trips_through_json() {
        let r = rule(
            &[("exec", &["a", "b", "c"]), ("non-exec", &["d", "e"])],
            &[&[("exec", 2, 3), ("non-exec", 1, 2)]],
        );
        let back: Rule = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
