// The English labels of the tenant admin's branding and terminology
// screens (M9 lane P2, R-NF-04). Every id starts with `admin.branding.`
// or `admin.terminology.`. Plain language only (docs/design/10). No
// approved or legal text is held here.

export const ADMIN_BRANDING_LABELS: Readonly<Record<string, string>> = {
  "admin.branding.title": "Brand colours",
  "admin.branding.intro":
    "Set the tenant name and the brand colours of your pages, in light and dark mode. Each colour pair must meet WCAG 2.2 AA contrast, or the colours are not saved.",
  "admin.branding.start":
    "The fields start from the platform colours. Saving replaces the brand colours in force.",
  "admin.branding.footer_note":
    "The page footer always uses platform wording. No brand setting can hide or change it.",
  "admin.branding.name": "Tenant name, as pages show it",
  "admin.branding.mode.light": "Light mode",
  "admin.branding.mode.dark": "Dark mode",
  "admin.branding.colour.brand": "Brand fill, such as the main button",
  "admin.branding.colour.brand-hover": "Brand fill under the pointer",
  "admin.branding.colour.brand-text": "Links and active navigation",
  "admin.branding.colour.on-brand": "Text on the brand fill",
  "admin.branding.colour.focus": "Focus ring",
  "admin.branding.check": "Check contrast",
  "admin.branding.save": "Save brand colours",
  "admin.branding.invalid":
    "Enter a tenant name of 1 to 80 characters without angle brackets, and each colour as # and six hexadecimal digits.",
  "admin.branding.checks.heading": "Contrast check",
  "admin.branding.checks.none": "Not checked yet.",
  "admin.branding.checks.pass": "Every colour pair meets the contrast minimum in both modes.",
  "admin.branding.checks.fail": "These colour pairs are below the contrast minimum. Change them before you save:",
  "admin.branding.not_saved": "Nothing was saved. Some colour pairs are below the contrast minimum.",
  "admin.branding.saved": "The brand colours are saved. Pages use them from the next page load.",
  "admin.branding.pair": "{mode}: {pair}",
  "admin.branding.pair.brand-text/surface-0": "links on the page background",
  "admin.branding.pair.brand-text/surface-1": "links on cards and the sidebar",
  "admin.branding.pair.on-brand/brand": "text on the brand fill",
  "admin.branding.pair.on-brand/brand-hover": "text on the brand fill under the pointer",
  "admin.branding.pair.focus/surface-0": "focus ring on the page background",
  "admin.branding.back": "Back to your work",
  "admin.terminology.title": "Terminology",
  "admin.terminology.intro":
    "Rename interface labels for your tenant. Leave a field empty to keep the platform label. Labels are plain text without braces or angle brackets.",
  "admin.terminology.scope":
    "Terminology changes labels only. Approved texts, contracts, notices, the Guide, funder documents and emails keep their wording.",
  "admin.terminology.start": "The fields start empty, because the screen cannot read the labels in force. Saving replaces them all.",
  "admin.terminology.voyage": "Show the Voyage label as a second line beside each label",
  "admin.terminology.labels": "Labels",
  "admin.terminology.default": "Platform label: {text}",
  "admin.terminology.fixed.heading": "Fixed wording",
  "admin.terminology.fixed.intro": "These labels name outcomes with legal effect or a withdrawal. Their wording cannot change.",
  "admin.terminology.save": "Save terminology",
  "admin.terminology.invalid": "Some labels are not plain text of at most 200 characters. Check the marked fields.",
  "admin.terminology.field_invalid": "This label is not accepted.",
  "admin.terminology.saved": "The terminology is saved.",
};
