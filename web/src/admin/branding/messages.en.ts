// The English labels of the tenant admin's branding and terminology
// screens (M9 lane P2, R-NF-04). Every id starts with `admin.branding.`
// or `admin.terminology.`. Plain language only (docs/design/10). No
// approved or legal text is held here.

export const ADMIN_BRANDING_LABELS: Readonly<Record<string, string>> = {
  "admin.branding.title": "Logos and brand colours",
  "admin.branding.colours.heading": "Brand colours",
  "admin.branding.logos.heading": "Logos",
  "admin.branding.logos.programme_title": "Programme logo",
  "admin.branding.logos.loading": "Loading the logos in force.",
  "admin.branding.logos.unavailable": "The logos could not be loaded. Reload the page to try again.",
  "admin.branding.logos.intro":
    "Your logo shows in the top bar, on the sign-in pages, on public pages, in emails and on PDFs. Use a PNG or WebP image of up to 256 KB.",
  "admin.branding.logos.tenant": "Organisation logo",
  "admin.branding.logos.programme": "Logo of {name}",
  "admin.branding.logos.light": "For light mode",
  "admin.branding.logos.dark": "For dark mode. Without one, the light logo shows in dark mode too.",
  "admin.branding.logos.none": "No logo yet.",
  "admin.branding.logos.choose": "Choose an image",
  "admin.branding.logos.preview": "This is how the image looks on the light and the dark top bar.",
  "admin.branding.logos.save": "Use this logo",
  "admin.branding.logos.remove": "Remove this logo",
  "admin.branding.logos.saved": "The logo is saved.",
  "admin.branding.logos.removed": "The logo is removed.",
  "admin.branding.logos.too_big": "This file is too big. Choose an image of up to 256 KB.",
  "admin.branding.logos.wrong_type": "Only PNG or WebP images can be used. SVG and other formats are not accepted.",
  "admin.branding.logos.dimensions": "This image is too small or too large. Use 16 to 2048 pixels on each side.",
  "admin.branding.logos.unreadable": "This image could not be read. Try saving it again as a PNG.",
  "admin.branding.logos.low_contrast_light": "This logo may be hard to see on the light top bar.",
  "admin.branding.logos.low_contrast_dark":
    "This logo may be hard to see on the dark top bar. You can add a separate logo for dark mode.",
  "admin.branding.logos.no_pdf":
    "PDFs show this logo only as a PNG without see-through areas. Until then, PDFs leave it out.",
  "admin.branding.logos.no_email": "Emails show PNG logos only. A WebP logo is left out of emails.",
  "admin.branding.logos.refused": "This image was not accepted. Check that it is a PNG or WebP of up to 256 KB.",
  "admin.branding.logos.emblem_note":
    "The EU emblem and the funding statement have their own fixed place on public pages and PDFs. No logo can replace them.",
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
