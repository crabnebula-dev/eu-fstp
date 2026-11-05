//! The shipped deadline zone table (ADR-015 "Rendering home and zones",
//! `SPEC/12-journey-ui.md` section 11 `deadline_zone`).
//!
//! A journey row stores the zone of a related deadline as an index into
//! [`ZONES`], never as text, so the row holds no free text (I-97). The
//! table holds UTC and the IANA zones of every EU and EEA country. It
//! only ever grows at its end, so a stored index never changes meaning.
//!
//! A zone the table does not hold is stored as no zone. The diary then
//! shows the deadline in UTC only.
//!
//! Interim, pending Daniel (`docs/handoff/m4-design.md` section 15.0,
//! lane j2): the table ships in this crate. ADR-015 adds a zone by a
//! forward-only migration that only appends. No migration holds a copy
//! of the table yet, so the append-only rule is a test on this list.

/// The shipped zones. Index 0 is UTC. Append only.
pub const ZONES: [&str; 40] = [
    "UTC",
    // EU member states, in the order of their English short names.
    "Europe/Vienna",
    "Europe/Brussels",
    "Europe/Sofia",
    "Europe/Zagreb",
    "Asia/Nicosia",
    "Asia/Famagusta",
    "Europe/Prague",
    "Europe/Copenhagen",
    "Europe/Tallinn",
    "Europe/Helsinki",
    "Europe/Mariehamn",
    "Europe/Paris",
    "Europe/Berlin",
    "Europe/Busingen",
    "Europe/Athens",
    "Europe/Budapest",
    "Europe/Dublin",
    "Europe/Rome",
    "Europe/Riga",
    "Europe/Vilnius",
    "Europe/Luxembourg",
    "Europe/Malta",
    "Europe/Amsterdam",
    "Europe/Warsaw",
    "Europe/Lisbon",
    "Atlantic/Madeira",
    "Atlantic/Azores",
    "Europe/Bucharest",
    "Europe/Bratislava",
    "Europe/Ljubljana",
    "Europe/Madrid",
    "Africa/Ceuta",
    "Atlantic/Canary",
    "Europe/Stockholm",
    // The EEA countries outside the EU.
    "Atlantic/Reykjavik",
    "Europe/Vaduz",
    "Europe/Oslo",
    // Zones of the EU outermost regions with their own IANA name.
    "America/Cayenne",
    "Indian/Reunion",
];

/// The index of `zone` in [`ZONES`], or `None` for a zone the table does
/// not hold.
pub fn index_of(zone: &str) -> Option<u16> {
    ZONES
        .iter()
        .position(|z| *z == zone)
        .and_then(|i| u16::try_from(i).ok())
}

/// The zone at `index`, or `None` outside the table.
pub fn zone_at(index: u16) -> Option<&'static str> {
    ZONES.get(usize::from(index)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-015: the table starts with UTC, holds no zone twice, and each
    /// index reads back its zone.
    #[test]
    fn adr015_zone_table_is_utc_first_and_unique() {
        assert_eq!(ZONES.first().copied(), Some("UTC"));
        for (i, z) in ZONES.iter().enumerate() {
            let ix = u16::try_from(i).unwrap_or(u16::MAX);
            assert_eq!(index_of(z), Some(ix), "{z}");
            assert_eq!(zone_at(ix), Some(*z));
        }
        assert_eq!(index_of("Canary/Nowhere"), None);
    }

    /// ADR-015 "only appends": the first zones keep their indices. A
    /// change that reorders or removes one of them fails here.
    #[test]
    fn adr015_zone_table_only_grows_at_its_end() {
        let pinned = [
            (0u16, "UTC"),
            (2, "Europe/Brussels"),
            (13, "Europe/Berlin"),
            (23, "Europe/Amsterdam"),
            (37, "Europe/Oslo"),
            (39, "Indian/Reunion"),
        ];
        for (ix, z) in pinned {
            assert_eq!(zone_at(ix), Some(z), "index {ix}");
        }
    }
}
