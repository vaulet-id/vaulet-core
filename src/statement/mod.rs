//! Signing a statement about something other than yourself (ADR 0029).
//!
//! A guarantor backing an application, a director approving a resolution,
//! somebody authorising an agent to act for them. One primitive, because they
//! are one act: **a person putting their key behind a claim about the world**,
//! rather than behind a claim about themselves.
//!
//! Two representations of that claim travel together and they are not copies:
//!
//! ```text
//!   symbol   {"act":"guarantee","cap":"500000","ccy":"THB", …}
//!   text     "ข้าพเจ้าค้ำประกันวงเงินไม่เกิน 500,000 บาท"
//! ```
//!
//! The **symbol is for the app**: it decides what is rendered, what a rule can
//! check, what an agent is permitted to do. The **text is what binds the
//! person**, because it is what they read — nobody signs JSON, and no court
//! reads it.
//!
//! **Where the two disagree the statement is void.** Not "text wins", which
//! makes our rendering bug into somebody's real debt; not "symbol wins", which
//! tells a person that what they read is not what they agreed to. Refused, on
//! the day it happens, by anybody who verifies — see [`open`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{CoreError, Result};

/// The verb of a statement, and the shape it forces.
///
/// **Vaulet defines these; a request that uses one fills in its values.** Not a
/// free string: a statement nobody can parse is a statement no rule can be
/// applied to, and an act invented at a keyboard has no reviewed sentence to
/// render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Act {
    /// A decision that has been taken. Leave approved, resolution passed.
    Approve,
    /// Standing behind somebody else's obligation, for a stated term.
    Guarantee,
    /// Permission for somebody — or something — to act, within a scope and
    /// until a stated moment.
    Authorise,
    /// Taking back a decision, naming the statement it undoes.
    ///
    /// A separate statement rather than a flipped bit, because the bit says the
    /// decision never happened. "Approved on the 5th, rescinded on the 7th" is
    /// what occurred; "never approved" is what somebody would want the record
    /// to say during a dispute.
    Rescind,
    /// Taking back something still running, before it has been used.
    Withdraw,
}

/// Whether an act takes a term, which is a property of the act and never a
/// choice on a form.
///
/// "This approval expired" is a sentence nobody can answer, and a builder free
/// to tick that box will eventually tick it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Term {
    Required,
    Forbidden,
}

/// How a statement stops being in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undo {
    /// Still doing something, so it can be stopped: a status entry, on the
    /// register of whoever the statement was made out to.
    StatusList,
    /// Finished the moment it was made. Undone by a further statement, which
    /// keeps the history a flipped bit would erase.
    Counterstatement,
}

impl Act {
    pub fn as_str(self) -> &'static str {
        match self {
            Act::Approve => "approve",
            Act::Guarantee => "guarantee",
            Act::Authorise => "authorise",
            Act::Rescind => "rescind",
            Act::Withdraw => "withdraw",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "approve" => Act::Approve,
            "guarantee" => Act::Guarantee,
            "authorise" => Act::Authorise,
            "rescind" => Act::Rescind,
            "withdraw" => Act::Withdraw,
            _ => return None,
        })
    }

    pub fn term(self) -> Term {
        match self {
            // Decisions, and the undoing of things: each is complete when made.
            Act::Approve | Act::Rescind | Act::Withdraw => Term::Forbidden,
            Act::Guarantee | Act::Authorise => Term::Required,
        }
    }

    pub fn undo(self) -> Undo {
        match self {
            Act::Guarantee | Act::Authorise => Undo::StatusList,
            Act::Approve | Act::Rescind | Act::Withdraw => Undo::Counterstatement,
        }
    }

    /// Whether this act is undone by naming an earlier statement.
    pub fn names_another(self) -> bool {
        matches!(self, Act::Rescind | Act::Withdraw)
    }

    /// The fields the symbol must carry, beyond `until` which [`Term`] governs.
    ///
    /// Named here rather than left to the template, so a symbol that renders
    /// into a sentence with a blank in it is refused at signing instead of read
    /// by somebody at midnight.
    pub fn required_fields(self) -> &'static [&'static str] {
        match self {
            // `about` is in every sentence, because every one of these needs to
            // say what it is about and `subject` is an opaque id — "I guarantee
            // loan-9021" is not a sentence anybody can consent to.
            //
            // It is supplied by whoever asks for the statement, and that is not
            // the same as letting them write the wording: they name the thing,
            // we own the frame around it. A value is not a sentence.
            // `role` because an approval that does not say in what capacity it
            // was given is not evidence of anything — a manager approving leave
            // and a colleague saying "fine by me" would read identically.
            Act::Approve => &["about", "role"],
            Act::Guarantee => &["about", "cap", "ccy"],
            Act::Authorise => &["about", "scope", "limit"],
            Act::Rescind | Act::Withdraw => &["about"],
        }
    }
}

/// The sentence-maker: one act, one version, and the wording in every language
/// it has been written in.
///
/// **Vaulet writes these.** A tenant free to author the wording is a tenant free
/// to put something unlawful in front of a person, in our app, under our name.
///
/// It travels inside the statement rather than behind a URL, so a statement can
/// be checked offline, years later, by somebody who has never heard of us.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Template {
    /// Which act this renders.
    pub act: String,
    /// Bumped on every change. A template already signed against is never
    /// edited — a correction is a new version, and statements signed under the
    /// old wording stay bound to the words they were signed under.
    pub version: u32,
    /// Language tag -> the sentence, with `{field}` placeholders.
    pub wording: BTreeMap<String, String>,
}

impl Template {
    /// What the signature covers, so the wording cannot be swapped after the
    /// fact. Deterministic CBOR (RFC 8949 §4.2) via the encoder this project
    /// already uses for captures, rather than a second canonicalisation.
    pub fn hash(&self) -> Result<String> {
        let mut entries = vec![
            (
                crate::dcbor::Cbor::Text("act".into()),
                crate::dcbor::Cbor::Text(self.act.clone()),
            ),
            (
                crate::dcbor::Cbor::Text("version".into()),
                crate::dcbor::Cbor::Int(self.version as i64),
            ),
        ];
        let wording: Vec<(crate::dcbor::Cbor, crate::dcbor::Cbor)> = self
            .wording
            .iter()
            .map(|(k, v)| {
                (
                    crate::dcbor::Cbor::Text(k.clone()),
                    crate::dcbor::Cbor::Text(v.clone()),
                )
            })
            .collect();
        entries.push((
            crate::dcbor::Cbor::Text("wording".into()),
            crate::dcbor::Cbor::Map(wording),
        ));
        let bytes = crate::dcbor::encode(&crate::dcbor::Cbor::Map(entries))
            .map_err(|e| CoreError::Protocol(format!("template: {e}")))?;
        use sha2::Digest;
        Ok(crate::dcbor::to_hex(&sha2::Sha256::digest(&bytes)))
    }

    /// Turn a symbol into the sentence somebody reads.
    ///
    /// A placeholder with no value is an error rather than an empty space: the
    /// whole point of the text is that it says what the symbol says, and
    /// "ค้ำประกันวงเงินไม่เกิน  บาท" says something else.
    pub fn render(&self, lang: &str, fields: &BTreeMap<String, String>) -> Result<String> {
        let wording = self
            .wording
            .get(lang)
            .ok_or_else(|| CoreError::Protocol(format!("template has no {lang}")))?;
        let mut out = String::with_capacity(wording.len());
        let mut rest = wording.as_str();
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let end = after
                .find('}')
                .ok_or_else(|| CoreError::Protocol("template: unclosed placeholder".into()))?;
            let name = &after[..end];
            let value = fields
                .get(name)
                .ok_or_else(|| CoreError::Protocol(format!("template: no value for {name}")))?;
            out.push_str(value);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

/// One statement, before it is signed.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub act: Act,
    /// What it is about: the id of a request, a resolution, an earlier
    /// statement. Opaque here — only the two ends know what it names.
    pub subject: String,
    /// The act's values. `until` when the act takes a term.
    pub fields: BTreeMap<String, String>,
    pub template: Template,
    /// Which wording the signer actually read. Kept because a statement signed
    /// in Thai and one signed in English are not the same act of reading.
    pub lang: String,
}

/// A statement's claims, ready to be signed as a credential — and what comes
/// back out of one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedStatement {
    pub act: String,
    pub subject: String,
    pub fields: BTreeMap<String, String>,
    pub template: Template,
    pub template_hash: String,
    pub lang: String,
    /// **The sentence the signer read.** Signed alongside the symbol, and
    /// checked against it by everybody who verifies.
    pub text: String,
}

impl Statement {
    /// Check the act's own rules and render the sentence.
    ///
    /// Refused here rather than at the far end: everything below is a mistake
    /// somebody can still fix, and a statement that reaches a verifier before
    /// anybody notices has already been signed by a person who believed it.
    pub fn seal(self) -> Result<SignedStatement> {
        if self.template.act != self.act.as_str() {
            return Err(CoreError::Protocol(format!(
                "template is for {} and the statement is a {}",
                self.template.act,
                self.act.as_str()
            )));
        }
        match (self.act.term(), self.fields.contains_key("until")) {
            (Term::Required, false) => {
                return Err(CoreError::Protocol(format!(
                    "{} has to say until when",
                    self.act.as_str()
                )))
            }
            (Term::Forbidden, true) => {
                return Err(CoreError::Protocol(format!(
                    "{} is finished when it is made, so it takes no term",
                    self.act.as_str()
                )))
            }
            _ => {}
        }
        for field in self.act.required_fields() {
            if !self.fields.contains_key(*field) {
                return Err(CoreError::Protocol(format!(
                    "{} needs {field}",
                    self.act.as_str()
                )));
            }
        }
        // **One representation of the term, and it is the machine's.**
        //
        // A displayed date beside a timestamp would be two spellings of one
        // fact — the exact pair this whole design exists to refuse — so the
        // sentence renders whatever is in the field, verbatim, and the field is
        // a date anybody can compare. A sentence reading "ถึงวันที่ 2031-09-05"
        // is less graceful than one reading "5 กันยายน 2574"; a localised date
        // is a new template version, which is the mechanism already here for
        // changing wording, and not a change to the renderer.
        //
        // Changing how rendering works is the one thing that cannot be done
        // later: every statement already signed would re-render differently and
        // be void. The renderer substitutes and nothing else, for ever.
        if let Some(until) = self.fields.get("until") {
            if !is_iso_date(until) {
                return Err(CoreError::Protocol(format!(
                    "until has to be a YYYY-MM-DD date, not {until}"
                )));
            }
        }
        let text = self.template.render(&self.lang, &self.fields)?;
        Ok(SignedStatement {
            act: self.act.as_str().to_string(),
            subject: self.subject,
            template_hash: self.template.hash()?,
            fields: self.fields,
            template: self.template,
            lang: self.lang,
            text,
        })
    }
}

/// Read a statement back, and refuse it if the symbol and the sentence
/// disagree.
///
/// **This is the whole of the void rule.** The signature says both halves were
/// signed together; it cannot say they mean the same thing. Only re-rendering
/// can, and it costs one template evaluation.
///
/// The failure it catches is a template that puts a number in the wrong slot,
/// or a wording swapped after signing: either would leave a person bound to a
/// sentence the machine never agreed to, discovered years later in a dispute
/// rather than today.
pub fn open(signed: &SignedStatement) -> Result<Act> {
    let act = Act::parse(&signed.act)
        .ok_or_else(|| CoreError::Protocol(format!("unknown act {}", signed.act)))?;
    if signed.template.hash()? != signed.template_hash {
        return Err(CoreError::Protocol(
            "the wording is not the wording that was signed".into(),
        ));
    }
    let rendered = signed.template.render(&signed.lang, &signed.fields)?;
    if rendered != signed.text {
        return Err(CoreError::Protocol(
            "what was signed and what was read do not agree".into(),
        ));
    }
    Ok(act)
}

/// `YYYY-MM-DD`, checked by shape rather than parsed into a calendar.
///
/// The comparison this enables is string order, which for this format is date
/// order — so nothing here needs a date library, and a value that would need
/// one has already been refused.
fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                true
            } else {
                c.is_ascii_digit()
            }
        })
}

/// Sign a statement with the signer's own key, as a credential they issue.
///
/// `exp` is about the ARTEFACT and `until` is about the ACT, and they are not
/// the same thing: one says how long this document is treated as current, the
/// other says how long the person is bound. A credential that expires while the
/// guarantee it carries is still owed would be a statement nobody can verify
/// and everybody is still bound by, so that combination is refused here.
pub fn issue_statement(
    statement: Statement,
    vct: &str,
    signer_did: &str,
    holder_jwk: serde_json::Value,
    iat: i64,
    exp: i64,
    key: &dyn crate::credential::Es256Signer,
) -> Result<String> {
    let signed = statement.seal()?;
    if let Some(until) = signed.fields.get("until") {
        // Both are dates in the same order-comparable shape once `exp` is
        // rendered as one; comparing the day is enough, and a statement that
        // expires on the day it stops binding is fine.
        let expires_on = crate::statement::iso_day(exp);
        if expires_on.as_str() < until.as_str() {
            return Err(CoreError::Protocol(format!(
                "this would stop verifying on {expires_on} while it still binds until {until}"
            )));
        }
    }
    let visible = serde_json::to_value(&signed)
        .map_err(|e| CoreError::Protocol(format!("statement: {e}")))?;
    let visible = match visible {
        serde_json::Value::Object(map) => map,
        _ => return Err(CoreError::Protocol("statement is not an object".into())),
    };
    crate::credential::issue(
        crate::credential::IssueParams {
            vct: vct.to_string(),
            iss: signer_did.to_string(),
            iat,
            exp,
            holder_jwk,
            // Nothing selectively disclosable. A statement whose act or amount
            // could be withheld is one a verifier cannot read, and the point of
            // it is being read by somebody who was not there.
            disclosable: serde_json::Map::new(),
            visible,
        },
        key,
    )
}

/// The day a Unix timestamp falls on, as `YYYY-MM-DD` (UTC).
///
/// Civil-from-days, which is exact and needs no calendar crate — the same
/// arithmetic every date library performs, written out because pulling in a
/// dependency to format one date is not worth the supply chain.
fn iso_day(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    // Howard Hinnant's civil_from_days, shifted to an era starting 0000-03-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Read a statement out of a credential somebody signed, and refuse it if the
/// symbol and the sentence disagree.
///
/// Both checks, in the order a reader would want them: the signature first,
/// because an unsigned statement is not a statement, then the void rule.
pub fn verify_statement(
    sd_jwt: &str,
    signer_jwk: &serde_json::Value,
    now: i64,
) -> Result<(Act, SignedStatement)> {
    let verified = crate::credential::verify(sd_jwt, signer_jwk, now)?;
    let signed: SignedStatement =
        serde_json::from_value(serde_json::Value::Object(verified.claims))
            .map_err(|e| CoreError::Protocol(format!("not a statement: {e}")))?;
    let act = open(&signed)?;
    Ok((act, signed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording, written as a person would write it. Deliberately not
    /// generated from anything: it is the half a machine does not produce.
    fn guarantee_template() -> Template {
        Template {
            act: "guarantee".into(),
            version: 1,
            wording: BTreeMap::from([
                (
                    "th".to_string(),
                    "ข้าพเจ้าค้ำประกัน {about} ในวงเงินไม่เกิน {cap} {ccy} ถึงวันที่ {until}"
                        .to_string(),
                ),
                (
                    "en".to_string(),
                    "I guarantee {about} up to {cap} {ccy} until {until}".to_string(),
                ),
            ]),
        }
    }

    fn guarantee() -> Statement {
        Statement {
            act: Act::Guarantee,
            subject: "loan-9021".into(),
            fields: BTreeMap::from([
                ("about".to_string(), "สัญญาเงินกู้เลขที่ 9021".to_string()),
                ("cap".to_string(), "500,000".to_string()),
                ("ccy".to_string(), "THB".to_string()),
                ("until".to_string(), "2031-09-05".to_string()),
            ]),
            template: guarantee_template(),
            lang: "th".into(),
        }
    }

    /// The sentence is pinned by hand, because a test that renders it the same
    /// way the code does agrees with the code and checks nothing. This is what
    /// a person is meant to read.
    #[test]
    fn the_sentence_is_the_one_a_person_would_read() {
        let signed = guarantee().seal().unwrap();
        assert_eq!(
            signed.text,
            "ข้าพเจ้าค้ำประกัน สัญญาเงินกู้เลขที่ 9021 ในวงเงินไม่เกิน 500,000 THB ถึงวันที่ 2031-09-05"
        );
    }

    /// **The void rule.** A statement whose text no longer follows from its
    /// symbol is refused rather than resolved in either direction — our
    /// rendering bug must not become somebody's debt, and a person must not be
    /// told that what they read was not what they agreed to.
    #[test]
    fn a_text_that_does_not_follow_from_the_symbol_is_void() {
        let mut signed = guarantee().seal().unwrap();
        signed.text = "ข้าพเจ้าค้ำประกันวงเงินไม่เกิน 5,000,000 THB ถึงวันที่ 5 กันยายน 2574".into();
        assert!(open(&signed).is_err());
    }

    /// The other half of the same rule: changing the symbol under a text that
    /// was signed is caught by the same comparison.
    #[test]
    fn a_symbol_edited_under_its_own_sentence_is_void() {
        let mut signed = guarantee().seal().unwrap();
        signed
            .fields
            .insert("cap".to_string(), "5,000,000".to_string());
        assert!(open(&signed).is_err());
    }

    /// And swapping the wording itself, which the hash covers.
    #[test]
    fn wording_replaced_after_signing_is_void() {
        let mut signed = guarantee().seal().unwrap();
        signed.template.wording.insert(
            "th".to_string(),
            "ข้าพเจ้าไม่ได้ค้ำประกันสิ่งใด".to_string(),
        );
        assert!(open(&signed).is_err());
    }

    #[test]
    fn a_statement_that_agrees_with_itself_opens() {
        assert_eq!(open(&guarantee().seal().unwrap()).unwrap(), Act::Guarantee);
    }

    /// An approval is finished the moment it is made. A term on one is a
    /// sentence nobody can answer — "this approval expired" — so it is refused
    /// where somebody can still fix it.
    #[test]
    fn an_approval_cannot_be_given_a_term() {
        let mut s = Statement {
            act: Act::Approve,
            subject: "leave-441".into(),
            fields: BTreeMap::from([
                ("role".to_string(), "manager".to_string()),
                ("about".to_string(), "การลาพักร้อน 5-9 กันยายน".to_string()),
            ]),
            template: Template {
                act: "approve".into(),
                version: 1,
                wording: BTreeMap::from([("th".to_string(), "อนุมัติ {about} โดย {role}".to_string())]),
            },
            lang: "th".into(),
        };
        assert!(s.clone().seal().is_ok());

        s.fields
            .insert("until".to_string(), "2031-09-05".to_string());
        assert!(s.seal().is_err());
    }

    /// And the reverse: what stays in force has to say for how long.
    #[test]
    fn a_guarantee_without_a_term_is_refused() {
        let mut s = guarantee();
        s.fields.remove("until");
        assert!(s.seal().is_err());
    }

    #[test]
    fn a_guarantee_without_its_cap_is_refused() {
        let mut s = guarantee();
        s.fields.remove("cap");
        assert!(s.seal().is_err());
    }

    /// A template belonging to another act cannot be used to render this one —
    /// otherwise a guarantee could be signed under an approval's sentence.
    #[test]
    fn a_template_for_another_act_is_refused() {
        let mut s = guarantee();
        s.template.act = "approve".into();
        assert!(s.seal().is_err());
    }

    /// A placeholder with nothing to put in it must not render as a gap. The
    /// sentence is what binds somebody, and one with a hole in it says
    /// something other than what was meant.
    #[test]
    fn a_missing_value_is_an_error_not_a_blank() {
        let mut s = guarantee();
        s.template
            .wording
            .insert("th".to_string(), "ค้ำ {about} {cap} {ccy} ถึง {until} เงื่อนไข {extra}".to_string());
        assert!(s.seal().is_err());
    }

    /// Which act stops how, asserted rather than described — the difference
    /// between a flipped bit and a further statement is the difference between
    /// a record that says a decision never happened and one that says when it
    /// was undone.
    #[test]
    fn what_is_still_running_is_stopped_and_what_is_done_is_answered() {
        assert_eq!(Act::Guarantee.undo(), Undo::StatusList);
        assert_eq!(Act::Authorise.undo(), Undo::StatusList);
        assert_eq!(Act::Approve.undo(), Undo::Counterstatement);
        assert_eq!(Act::Rescind.undo(), Undo::Counterstatement);
    }

    /// The wording is signed, so the two languages of one template are one
    /// artefact: translating cannot be done quietly afterwards.
    #[test]
    fn the_hash_covers_every_language() {
        let a = guarantee_template().hash().unwrap();
        let mut other = guarantee_template();
        other
            .wording
            .insert("en".to_string(), "I guarantee everything".to_string());
        assert_ne!(a, other.hash().unwrap());
    }

    /// A term has one representation and it is the machine's. A displayed date
    /// beside a timestamp would be two spellings of one fact, which is the pair
    /// this whole design refuses.
    #[test]
    fn a_term_that_cannot_be_compared_is_refused() {
        let mut s = guarantee();
        s.fields
            .insert("until".to_string(), "5 กันยายน 2574".to_string());
        assert!(s.seal().is_err());
    }

    fn key() -> crate::keys::software::SoftwareKey {
        crate::keys::software::SoftwareKey::generate()
    }

    /// Signed by the person, verified by anybody, and the sentence still has to
    /// follow from the symbol at the far end.
    #[test]
    fn a_signed_statement_round_trips() {
        let k = key();
        let jwk = k.public_jwk().unwrap();
        let sd_jwt = issue_statement(
            guarantee(),
            "https://vaulet.id/credential/statement",
            "did:jwk:signer",
            jwk.clone(),
            1_700_000_000,
            2_000_000_000,
            &k,
        )
        .unwrap();

        let (act, signed) = verify_statement(&sd_jwt, &jwk, 1_700_000_100).unwrap();
        assert_eq!(act, Act::Guarantee);
        assert_eq!(signed.subject, "loan-9021");
        assert_eq!(
            signed.text,
            "ข้าพเจ้าค้ำประกัน สัญญาเงินกู้เลขที่ 9021 ในวงเงินไม่เกิน 500,000 THB ถึงวันที่ 2031-09-05"
        );
    }

    /// **A credential that dies while the guarantee is still owed** would be a
    /// statement nobody can verify and everybody is still bound by. `exp` is
    /// about the artefact and `until` is about the act, and this is the one
    /// place they have to be looked at together.
    #[test]
    fn a_statement_cannot_expire_before_it_stops_binding() {
        let k = key();
        let too_soon = issue_statement(
            guarantee(),
            "https://vaulet.id/credential/statement",
            "did:jwk:signer",
            k.public_jwk().unwrap(),
            1_700_000_000,
            // 2026, while the guarantee runs to 2031.
            1_760_000_000,
            &k,
        );
        assert!(too_soon.is_err(), "{too_soon:?}");
    }

    /// The arithmetic behind that comparison, pinned against dates worked out
    /// by hand — a leap day, a century boundary, and the epoch.
    #[test]
    fn the_day_a_timestamp_falls_on() {
        assert_eq!(iso_day(0), "1970-01-01");
        assert_eq!(iso_day(1_709_164_800), "2024-02-29");
        assert_eq!(iso_day(4_102_444_800), "2100-01-01");
        assert_eq!(iso_day(1_760_000_000), "2025-10-09");
    }

    /// Nothing in a statement is selectively disclosable. A verifier who
    /// receives one is somebody who was not there, and an amount that could be
    /// withheld is a statement they cannot read.
    #[test]
    fn every_part_of_a_statement_is_visible() {
        let k = key();
        let sd_jwt = issue_statement(
            guarantee(),
            "https://vaulet.id/credential/statement",
            "did:jwk:signer",
            k.public_jwk().unwrap(),
            1_700_000_000,
            2_000_000_000,
            &k,
        )
        .unwrap();
        assert!(!sd_jwt.trim_end_matches('~').contains('~'), "no disclosures");
    }

    /// Reading in Thai and reading in English are two different acts of
    /// reading, and the statement records which one happened.
    #[test]
    fn the_language_read_is_part_of_what_was_signed() {
        let mut english = guarantee();
        english.lang = "en".into();
        let signed = english.seal().unwrap();
        assert_eq!(
            signed.text,
            "I guarantee สัญญาเงินกู้เลขที่ 9021 up to 500,000 THB until 2031-09-05"
        );
        assert_eq!(signed.lang, "en");
    }
}
