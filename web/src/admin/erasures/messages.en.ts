// The English labels of the tenant admin's erasure page (P-41, ADR-007,
// lane m5/retention). Every id starts with `admin.erasures.`. Plain
// language only (docs/design/10). No approved or legal text is held here.

export const ADMIN_ERASURE_LABELS: Readonly<Record<string, string>> = {
  "admin.erasures.title": "Erasures",
  "admin.erasures.intro":
    "Texts are erased by destroying their keys. The erasure log keeps each erased text with its cause and its times. It never keeps the text.",
  "admin.erasures.ended.heading": "Grants ready for erasure",
  "admin.erasures.ended.intro":
    "A grant's texts must be kept for the number of years the programme sets, counted from the day its last payment was confirmed. When that time is up, the grant appears here and you can ask for its texts to be erased.",
  "admin.erasures.ended.none": "No grant is ready for erasure yet.",
  "admin.erasures.ended.row": "Grant {grant} (programme {programme}): kept from {start} until {end}.",
  "admin.erasures.request.heading": "Request an erasure",
  "admin.erasures.request.intro":
    "Choose a grant whose retention ended and the cause. The request erases every text of the grant and cannot be undone. It needs a fresh confirmation with your passkey.",
  "admin.erasures.request.grant": "Grant",
  "admin.erasures.request.cause": "Cause",
  "admin.erasures.request.submit": "Request erasure",
  "admin.erasures.request.invalid": "Choose a grant and a cause.",
  "admin.erasures.request.done": "The erasure of the texts of grant {grant} was recorded.",
  "admin.erasures.cause.retention_expiry": "The retention period ended",
  "admin.erasures.cause.erasure_request": "A person asked for erasure",
  "admin.erasures.cause.cell_erasure": "The organisation's data is being erased",
  "admin.erasures.cause.verification_completed": "An identity check was completed",
  "admin.erasures.log.heading": "Erasure log",
  "admin.erasures.log.none": "No text has been erased.",
  "admin.erasures.log.row": "Text {text} ({kind}), grant {grant}: {cause}. Requested {requested}, completed {completed}.",
  "admin.erasures.log.epoch": "Its key died with key epoch {epoch}.",
  "admin.erasures.kind.text": "a text",
  "admin.erasures.kind.display_name": "a display name",
  "admin.erasures.kind.document": "a document",
  "admin.erasures.log.no_grant": "none",
  "admin.erasures.log.pending": "not yet",
  "admin.erasures.log.reason": "Reason: {reason}",
  "admin.erasures.authoriser.system": "Erased automatically by the platform.",
  "admin.erasures.authoriser.account": "Requested by a person.",
  "admin.erasures.documents.heading": "Documents",
  "admin.erasures.documents.intro":
    "Documents uploaded to programmes. Erasing one destroys its key and then deletes the stored copy. It cannot be undone. Write down why you erase it.",
  "admin.erasures.documents.none": "No document has been uploaded.",
  "admin.erasures.documents.row": "Document {document} (programme {programme}, {media})",
  "admin.erasures.documents.erased": "is erased.",
  "admin.erasures.documents.reason": "Reason",
  "admin.erasures.documents.erase": "Erase",
  "admin.erasures.documents.invalid": "Write a reason of at most {max} characters.",
  "admin.erasures.documents.done": "Document {document} is being erased.",
  "admin.erasures.back": "Back to home",
};
