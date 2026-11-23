//! The vault name mask over texts of any length (M7 Q4, ADR-033 record of
//! lane L40, Daniel 2026-11-23).
//!
//! The vault takes at most [`MASK_PIECES_PER_REQUEST`] texts of at most
//! [`MASK_PIECE_BYTES`] each per request, and that cap stays. A longer
//! text is split into pieces at paragraph, line or white space boundaries
//! ([`fstp_unorm::mask::mask_pieces`]), the pieces go to the vault in
//! order, and their spans are joined back
//! ([`fstp_unorm::mask::join_piece_spans`]). The joined spans equal the
//! mask of the whole text, so a name across a cut is still masked.
//!
//! - Any piece that cannot be cut, any failed request and any answer that
//!   does not fit its piece fails every text of the call closed, so no
//!   text leaves the cell.
//! - Short texts go in one request, as before.
//! - Submission text stays data. The pieces carry it to the vault only,
//!   and the masked text reaches the agent through the assessor's data
//!   channel as before (TH-60).

use std::future::Future;
use std::ops::Range;

use fstp_unorm::mask::{
    MASK_PIECE_BYTES, MASK_PIECES_PER_REQUEST, MAX_MASK_PIECES, MaskClass, MaskSpan,
    join_piece_spans, mask_pieces,
};

use crate::port::NameMaskSpan;

fn to_mask(s: NameMaskSpan) -> MaskSpan {
    MaskSpan {
        start: s.start,
        end: s.end,
        person: s.person,
        class: if s.birth_date {
            MaskClass::BirthDate
        } else {
            MaskClass::Name
        },
    }
}

fn from_mask(s: MaskSpan) -> NameMaskSpan {
    NameMaskSpan {
        start: s.start,
        end: s.end,
        person: s.person,
        birth_date: s.class == MaskClass::BirthDate,
    }
}

/// The mask of each of `texts`, asked of the vault through `ask` in
/// requests of at most [`MASK_PIECES_PER_REQUEST`] pieces of at most
/// [`MASK_PIECE_BYTES`] each. `ask` takes the pieces of one request and
/// answers one span list per piece, offsets into that piece. `Err` when a
/// text cannot be cut, has more than [`MAX_MASK_PIECES`] pieces, or any
/// request fails or answers out of shape. The caller then fails closed.
pub(crate) async fn mask_in_pieces<F, Fut>(
    texts: &[String],
    mut ask: F,
) -> Result<Vec<Vec<NameMaskSpan>>, ()>
where
    F: FnMut(Vec<String>) -> Fut,
    Fut: Future<Output = Result<Vec<Vec<NameMaskSpan>>, ()>>,
{
    let mut plan: Vec<Vec<Range<usize>>> = Vec::with_capacity(texts.len());
    for t in texts {
        let pieces = mask_pieces(t, MASK_PIECE_BYTES).ok_or(())?;
        if pieces.len() > MAX_MASK_PIECES {
            return Err(());
        }
        plan.push(pieces);
    }
    let all: Vec<(usize, Range<usize>)> = plan
        .iter()
        .enumerate()
        .flat_map(|(i, pieces)| pieces.iter().cloned().map(move |r| (i, r)))
        .collect();
    let mut answers: Vec<Vec<Vec<MaskSpan>>> =
        plan.iter().map(|p| Vec::with_capacity(p.len())).collect();
    for batch in all.chunks(MASK_PIECES_PER_REQUEST) {
        let sent = batch
            .iter()
            .map(|(i, r)| {
                texts
                    .get(*i)
                    .and_then(|t| t.get(r.clone()))
                    .map(str::to_owned)
            })
            .collect::<Option<Vec<String>>>()
            .ok_or(())?;
        let got = ask(sent).await?;
        if got.len() != batch.len() {
            return Err(());
        }
        for ((i, _), spans) in batch.iter().zip(got) {
            answers
                .get_mut(*i)
                .ok_or(())?
                .push(spans.into_iter().map(to_mask).collect());
        }
    }
    texts
        .iter()
        .zip(&plan)
        .zip(&answers)
        .map(|((t, pieces), spans)| {
            join_piece_spans(t, pieces, spans)
                .map(|v| v.into_iter().map(from_mask).collect())
                .ok_or(())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )]

    use std::cell::RefCell;

    use fstp_rt::future::block_on;
    use fstp_unorm::mask::{MaskPerson, mask_spans};

    use super::*;

    fn person() -> MaskPerson {
        MaskPerson::new("Velinorra-Quist", "Maradine", Some("1990-04-07"))
    }

    /// A synthetic vault that keeps the vault's request cap and masks as
    /// the vault does. `fail_at` fails that request, counted from zero.
    struct Vault {
        calls: RefCell<Vec<Vec<usize>>>,
        fail_at: Option<usize>,
    }

    impl Vault {
        fn new(fail_at: Option<usize>) -> Vault {
            Vault {
                calls: RefCell::new(Vec::new()),
                fail_at,
            }
        }

        fn ask(
            &self,
            texts: Vec<String>,
        ) -> std::future::Ready<Result<Vec<Vec<NameMaskSpan>>, ()>> {
            let n = self.calls.borrow().len();
            self.calls
                .borrow_mut()
                .push(texts.iter().map(String::len).collect());
            let lawful = (1..=MASK_PIECES_PER_REQUEST).contains(&texts.len())
                && texts.iter().all(|t| t.len() <= MASK_PIECE_BYTES);
            if !lawful || self.fail_at == Some(n) {
                return std::future::ready(Err(()));
            }
            let p = [person()];
            std::future::ready(Ok(texts
                .iter()
                .map(|t| mask_spans(t, &p).into_iter().map(from_mask).collect())
                .collect()))
        }
    }

    /// About 300 KiB of paragraphs, lines and full names, with names on
    /// every side of every cut.
    fn long_text() -> String {
        let mut s = String::new();
        let mut n = 0u32;
        while s.len() < 300 << 10 {
            n += 1;
            s.push_str("Lead: Maradine Velinorra-Quist, born 07.04.1990. ");
            s.push_str(&"word ".repeat((n % 97) as usize));
            s.push_str(if n.is_multiple_of(5) { "\n\n" } else { "\n" });
            s.push_str("MARADINE\nvelinorra quist ");
        }
        s
    }

    /// M7 Q4, I-17, ADR-033 (lane L40): a text over the vault's cap is
    /// masked in pieces. Every request keeps the cap, and the joined spans
    /// equal the mask of the whole text, names across a cut included.
    #[test]
    fn m7_q4_i17_a_long_text_is_masked_in_pieces_within_the_vault_cap() {
        let t = long_text();
        let vault = Vault::new(None);
        let got = block_on(mask_in_pieces(std::slice::from_ref(&t), |x| vault.ask(x))).unwrap();
        let whole: Vec<NameMaskSpan> = mask_spans(&t, &[person()])
            .into_iter()
            .map(from_mask)
            .collect();
        assert_eq!(got, vec![whole]);
        let calls = vault.calls.borrow();
        assert!(calls.len() >= 2, "{} requests", calls.len());
        for c in calls.iter() {
            assert!((1..=MASK_PIECES_PER_REQUEST).contains(&c.len()));
            assert!(c.iter().all(|l| *l <= MASK_PIECE_BYTES));
        }
        assert_eq!(calls.iter().flatten().sum::<usize>(), t.len());
    }

    /// M7 Q4, I-17, TH-60 (lane L40): a failure of any request, an answer
    /// of the wrong length or a span outside its piece fails every text of
    /// the call closed.
    #[test]
    fn m7_q4_i17_any_failed_piece_fails_the_whole_text_closed() {
        let texts = vec!["Maradine".to_owned(), long_text()];
        let requests = {
            let v = Vault::new(None);
            block_on(mask_in_pieces(&texts, |x| v.ask(x))).unwrap();
            v.calls.borrow().len()
        };
        assert!(requests >= 2);
        for k in 0..requests {
            let v = Vault::new(Some(k));
            assert!(
                block_on(mask_in_pieces(&texts, |x| v.ask(x))).is_err(),
                "request {k}"
            );
        }
        let short = block_on(mask_in_pieces(&texts, |x| {
            std::future::ready(Ok(vec![Vec::new(); x.len().saturating_sub(1)]))
        }));
        assert!(short.is_err(), "an answer short of a piece");
        let outside = block_on(mask_in_pieces(&texts, |x| {
            let spans = x
                .iter()
                .map(|t| {
                    let end = u32::try_from(t.len()).unwrap();
                    vec![NameMaskSpan {
                        start: end,
                        end: end + 1,
                        person: 0,
                        birth_date: false,
                    }]
                })
                .collect();
            std::future::ready(Ok(spans))
        }));
        assert!(outside.is_err(), "a span outside its piece");
    }

    /// M7 Q4 (lane L40): texts within the cap go in one request, as before
    /// the pieces existed.
    #[test]
    fn m7_q4_short_texts_go_in_one_request() {
        let texts = vec![
            "Title by Maradine".to_owned(),
            "Narrative of Velinorra-Quist.".to_owned(),
        ];
        let v = Vault::new(None);
        let got = block_on(mask_in_pieces(&texts, |x| v.ask(x))).unwrap();
        assert_eq!(
            *v.calls.borrow(),
            vec![vec![texts[0].len(), texts[1].len()]]
        );
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].len(), 1);
        assert_eq!(got[1].len(), 1);
    }

    /// M7 Q4, I-17 (lane L40): a text with a window that cannot be cut,
    /// or with more than `MAX_MASK_PIECES` pieces, fails closed before any
    /// request.
    #[test]
    fn m7_q4_i17_an_uncuttable_or_too_long_text_fails_closed() {
        let word = "a".repeat(MASK_PIECE_BYTES + 1);
        let huge = "word ".repeat((MASK_PIECE_BYTES * (MAX_MASK_PIECES + 1)) / 5 + 1);
        for t in [word, huge] {
            let v = Vault::new(None);
            assert!(block_on(mask_in_pieces(&[t], |x| v.ask(x))).is_err());
            assert!(v.calls.borrow().is_empty(), "no request");
        }
    }
}
