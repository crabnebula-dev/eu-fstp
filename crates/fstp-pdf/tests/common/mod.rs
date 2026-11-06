//! Shared test harness: synthetic contracts and an increment builder that
//! can place one fault at a time (ADR-016 threats, I-30).

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use fstp_pdf::object::{Dict, Object, Ref};
use fstp_pdf::{Block, BlockKind, Document, PdfFile, SignatureField};
use fstp_prop::Gen;

/// The party fields of the synthetic contract.
pub const PARTIES: [&str; 3] = ["lead", "member-1", "signatory"];

/// A synthetic contract with the three party fields.
pub fn contract(paragraphs: usize) -> Document {
    let mut blocks = vec![Block {
        kind: BlockKind::Heading1,
        text: "Sub-grant agreement SYN-0001".into(),
    }];
    for i in 0..paragraphs {
        blocks.push(Block {
            kind: if i % 5 == 0 { BlockKind::Heading2 } else { BlockKind::Paragraph },
            text: format!(
                "Clause {i}. The synthetic recipient Ada Example delivers milestone {i} of the synthetic plan. Amounts are stated in euro cent. Zażółć gęślą jaźń, Größe, café."
            ),
        });
    }
    Document {
        title: "Sub-grant agreement SYN-0001, version 1".into(),
        lang: "en".into(),
        blocks,
        signature_fields: PARTIES
            .iter()
            .map(|p| SignatureField {
                name: (*p).into(),
                label: format!("Signature of {p}"),
            })
            .collect(),
    }
}

/// Characters the generator draws text from: ASCII letters, digits,
/// punctuation and some Latin letters the font covers.
const CHARSET: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'M', 'Z', '0', '1', '9', ' ', ' ', ' ', '.', ',', '(',
    ')', '\\', '%', '<', '>', '/', '#', '€', 'ä', 'ß', 'é', 'ł', 'ż', 'Ω', '-', '–',
];

fn text(g: &mut Gen, max: usize) -> String {
    let mut s: String = g.vec(1..=max, |g| *g.pick(CHARSET)).into_iter().collect();
    if s.trim().is_empty() {
        s.push('x');
    }
    s
}

/// A random synthetic document the font can render.
pub fn random_document(g: &mut Gen) -> Document {
    let blocks = g.vec(1..=12, |g| Block {
        kind: *g.pick(&[
            BlockKind::Heading1,
            BlockKind::Heading2,
            BlockKind::Paragraph,
        ]),
        text: text(g, 400),
    });
    let n_fields = g.usize_in(0..=4);
    let signature_fields = (0..n_fields)
        .map(|i| SignatureField {
            name: format!("party-{i}"),
            label: text(g, 20),
        })
        .collect();
    Document {
        title: text(g, 40),
        lang: g.pick(&["en", "de-AT", "fr"]).to_string(),
        blocks,
        signature_fields,
    }
}

/// What the builder needs from the stored revision.
pub struct Ctx {
    pub base: Vec<u8>,
    pub root: Ref,
    pub prev: usize,
    pub sig_num: u32,
    pub info: Option<Ref>,
    pub id: String,
    pub fields: Vec<(String, Ref, Dict)>,
    pub other_objects: Vec<u32>,
}

impl Ctx {
    pub fn new(base: Vec<u8>) -> Ctx {
        let file = PdfFile::open(&base).unwrap();
        let root = file.root().unwrap();
        let catalog = file.dict(root).unwrap();
        let acro = file.dict(catalog.reference(b"AcroForm").unwrap()).unwrap();
        let Some(Object::Array(list)) = acro.get(b"Fields") else {
            panic!("no fields")
        };
        let mut fields = Vec::new();
        for f in list {
            let Object::Ref(r) = f else { panic!() };
            let d = file.dict(*r).unwrap();
            let Some(Object::String(t)) = d.get(b"T") else {
                panic!()
            };
            fields.push((String::from_utf8(t.bytes.clone()).unwrap(), *r, d));
        }
        let mut id = Vec::new();
        if let Some(i) = file.trailer().get(b"ID") {
            i.write_to(&mut id);
        }
        let field_nums: Vec<u32> = fields.iter().map(|f| f.1.num).collect();
        let other_objects = file
            .xref()
            .iter()
            .filter(|(n, e)| e.in_use && !field_nums.contains(n))
            .map(|(n, _)| *n)
            .collect();
        Ctx {
            root,
            prev: file.startxref(),
            sig_num: file.size(),
            info: file.trailer().reference(b"Info"),
            id: String::from_utf8(id).unwrap(),
            fields,
            other_objects,
            base,
        }
    }

    pub fn field(&self, party: &str) -> (Ref, Dict) {
        let f = self.fields.iter().find(|f| f.0 == party).unwrap();
        (f.1, f.2.clone())
    }

    /// The field dictionary with `/V` set to `v`.
    pub fn field_body(&self, party: &str, v: Ref) -> String {
        let (_, mut d) = self.field(party);
        d.set(b"V", Object::Ref(v));
        let mut out = Vec::new();
        assert!(Object::Dict(d).write_to(&mut out));
        String::from_utf8(out).unwrap()
    }

    pub fn sig_ref(&self) -> Ref {
        Ref {
            num: self.sig_num,
            generation: 0,
        }
    }

    pub fn default_trailer(&self) -> String {
        let mut t = format!(
            "<< /Size {} /Root {} {} R /Prev {}",
            self.sig_num + 1,
            self.root.num,
            self.root.generation,
            self.prev
        );
        if let Some(i) = self.info {
            t.push_str(&format!(" /Info {} {} R", i.num, i.generation));
        }
        if !self.id.is_empty() {
            t.push_str(&format!(" /ID {}", self.id));
        }
        t.push_str(" >>");
        t
    }
}

/// The marker of a 43-byte slot in a signature body that the builder fills with the
/// `/ByteRange` values.
pub const BR: &str = "@BR@";

/// A signature dictionary body with a zero placeholder of `cap` bytes.
pub fn sig_body(cap: usize) -> String {
    format!(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [{BR:<43}] /Contents <{}> >>",
        "0".repeat(cap * 2)
    )
}

/// One increment, part by part.
pub struct Parts {
    /// Before the first object.
    pub lead: String,
    /// `(number, generation, body)` in order.
    pub objects: Vec<(u32, u16, String)>,
    /// Between objects and `xref`.
    pub between: String,
    /// Xref entries `(number, offset delta, generation)`; `None` lists
    /// every object at its true offset.
    pub xref: Option<Vec<(u32, i64, u16)>>,
    /// The trailer dictionary.
    pub trailer: String,
    /// Added to the true `startxref` value.
    pub startxref_delta: i64,
    /// Bytes after `%%EOF\n`.
    pub after: Vec<u8>,
    /// Changes the true `/ByteRange` before it is written.
    pub byte_range: fn([i64; 4]) -> [i64; 4],
}

impl Parts {
    /// The canonical increment for `party`.
    pub fn canonical(ctx: &Ctx, party: &str) -> Parts {
        let (fr, _) = ctx.field(party);
        Parts {
            lead: String::new(),
            objects: vec![
                (fr.num, fr.generation, ctx.field_body(party, ctx.sig_ref())),
                (ctx.sig_num, 0, sig_body(4096)),
            ],
            between: String::new(),
            xref: None,
            trailer: ctx.default_trailer(),
            startxref_delta: 0,
            after: Vec::new(),
            byte_range: |b| b,
        }
    }

    pub fn build(&self, base: &[u8]) -> Vec<u8> {
        let mut inc = self.lead.clone().into_bytes();
        let mut offsets = Vec::new();
        for (num, generation, body) in &self.objects {
            offsets.push((*num, base.len() + inc.len(), *generation));
            inc.extend_from_slice(format!("{num} {generation} obj\n{body}\nendobj\n").as_bytes());
        }
        inc.extend_from_slice(self.between.as_bytes());
        let xref_off = base.len() + inc.len();
        let entries: Vec<(u32, usize, u16)> = match &self.xref {
            None => {
                let mut e = offsets.clone();
                e.sort_by_key(|x| x.0);
                e
            }
            Some(list) => list
                .iter()
                .map(|(n, delta, g)| {
                    let off = offsets.iter().find(|o| o.0 == *n).map_or(0, |o| o.1);
                    (*n, (off as i64 + delta) as usize, *g)
                })
                .collect(),
        };
        inc.extend_from_slice(b"xref\n");
        for (n, off, g) in entries {
            inc.extend_from_slice(format!("{n} 1\n{off:010} {g:05} n \n").as_bytes());
        }
        inc.extend_from_slice(
            format!(
                "trailer\n{}\nstartxref\n{}\n%%EOF\n",
                self.trailer,
                xref_off as i64 + self.startxref_delta
            )
            .as_bytes(),
        );
        inc.extend_from_slice(&self.after);
        // Fill the /ByteRange slot.
        // The slot is 43 bytes wide from the start, so no offset moves.
        if let Some(slot) = find(&inc, BR.as_bytes()) {
            let slot_len = 43;
            let c_at = find(&inc, b"/Contents <").map(|i| i + 10);
            let total = (base.len() + inc.len()) as i64;
            let br = match c_at {
                Some(c) => {
                    let close = inc[c..].iter().position(|&b| b == b'>').unwrap() + c + 1;
                    let start = (base.len() + c) as i64;
                    let end = (base.len() + close) as i64;
                    [0, start, end, total - end]
                }
                None => [0, 0, 0, 0],
            };
            let br = (self.byte_range)(br);
            let s = format!("{} {} {} {}", br[0], br[1], br[2], br[3]);
            let s = format!("{s:<slot_len$}");
            assert_eq!(s.len(), slot_len);
            inc[slot..slot + slot_len].copy_from_slice(s.as_bytes());
            return inc;
        }
        inc
    }
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
