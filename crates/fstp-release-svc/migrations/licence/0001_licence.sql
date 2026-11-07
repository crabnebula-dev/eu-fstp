-- The licence registry database licence on the control cluster (M3
-- design sections 4.1, 4.6 and 10, ADR-005). fstp_release_svc::CATALOGUE
-- lists every table and column below, in order.
--
-- It holds only the licence holder name, contact address and licence
-- type (SPEC/05-compliance/gdpr.md, Licence registration). Name and
-- contact are sealed before they are written: random nonce (12) ||
-- AES-256-GCM ciphertext || tag (16). The key is a ControlPlane chain
-- key (ADR-005, interim, pending Daniel). No amount (I-16), no tenant
-- data of any cell (I-38).
-- TODO(legal): L-15, the provider's operator access to these rows.

CREATE SCHEMA licence;

-- One registration per licence. kind is fstp_release::licence::LicenceKind.
CREATE TABLE licence.registration (
  licence_id      bytea    PRIMARY KEY CHECK (octet_length(licence_id) = 16),
  kind            smallint NOT NULL,
  holder_name     bytea    NOT NULL CHECK (octet_length(holder_name) >= 28),
  contact_address bytea    NOT NULL CHECK (octet_length(contact_address) >= 28),
  registered_at   bigint   NOT NULL
);
