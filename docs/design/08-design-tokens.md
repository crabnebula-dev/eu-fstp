# 08. Design tokens

Status: draft. Files: `design/tokens.css`, `design/prototypes/tokens-showcase.html`.

## Purpose and audience

One set of CSS custom properties for every screen, overridable per tenant (I-72). Every colour pair used for text meets WCAG 2.2 AA in light and dark themes (I-70). Fonts are self-hosted tenant tokens, never third-party (ADR-014).

## How ratios were checked

Every ratio below was computed with the WCAG 2.x relative luminance formula, using a small in-house Node script on this machine. The script is not part of the deliverable. Thresholds: 4.5:1 for normal text, 3:1 for large text and non-text UI (WCAG 1.4.3, 1.4.11).

Some ratios in the brief's starting palette were optimistic. The measured values are used here. Two pairs fail and are handled by usage rules or replaced tokens. Both are listed under "Corrections".

## Theme switching

- Light is the default in `:root`.
- Dark applies under `prefers-color-scheme: dark` unless `html[data-theme="light"]`.
- `html[data-theme="dark"]` forces dark. The `/app/me` theme choice sets this attribute server-side.

## Colour tokens

| Token | Light | Dark | Use and measured ratio |
| --- | --- | --- | --- |
| `--color-brand` | #2563EB | #3B82F6 | Fills, links on fills. Light 5.17:1 on surface-0. Dark 4.85:1 on surface-0. |
| `--color-brand-hover` | #1D4ED8 | #60A5FA | Hover fill. On-brand text: light 6.70:1, dark 7.02:1. |
| `--color-brand-text` | #1E40AF | #93C5FD | Links. Light 8.72:1 on surface-0. Dark 9.90:1 on surface-0, 8.11:1 on surface-1. |
| `--color-on-brand` | #FFFFFF | #0F172A | Text on brand. Light 5.17:1. Dark 4.85:1 (white would be 3.68:1, a fail). |
| `--color-surface-0` | #FFFFFF | #0F172A | Page |
| `--color-surface-1` | #F8FAFC | #1E293B | Cards, header |
| `--color-surface-2` | #F1F5F9 | #293548 | Table heads, insets |
| `--color-surface-3` | #E2E8F0 | #334155 | Borders, dividers. Decorative only. |
| `--color-border-strong` | #64748B | #94A3B8 | Form control borders. Light 4.76:1, dark 6.96:1. Meets 3:1 non-text. |
| `--color-text-1` | #0F172A | #F1F5F9 | Body. Light 17.85:1. Dark 16.30:1. |
| `--color-text-2` | #334155 | #CBD5E1 | Secondary. Light 10.35:1 (9.45:1 on surface-2). Dark 12.02:1 (8.33:1 on surface-2). |
| `--color-text-3` | #64748B | #94A3B8 | Placeholder, muted. Light 4.76:1 on surface-0, 4.55:1 on surface-1. Dark 6.96:1, 5.71:1 on surface-1. |
| `--color-danger` | #B91C1C | #F87171 | Danger fills. On-danger text: light 6.47:1 (white), dark 6.45:1 (#0F172A). |
| `--color-focus` | #2563EB | #60A5FA | Focus outline. Light 5.17:1, dark 7.02:1 against surface-0. |

## State colour pairs

Each state has a background, a border and a text colour. Text is measured on its own background and on surface-0.

| State | Light bg / border / text | Light ratio | Dark bg / border / text | Dark ratio |
| --- | --- | --- | --- | --- |
| Success | #F0FDF4 / #86EFAC / #15803D | 4.79:1 on bg, 5.02:1 on surface-0 | #052E16 / #15803D / #4ADE80 | 8.55:1 on bg, 10.25:1 on surface-0 |
| Warning | #FFFBEB / #FCD34D / #B45309 | 4.84:1 on bg, 5.02:1 on surface-0 | #422006 / #B45309 / #FCD34D | 10.11:1 on bg, 12.38:1 on surface-0 |
| Error | #FEF2F2 / #FCA5A5 / #B91C1C | 5.91:1 on bg, 6.47:1 on surface-0 | #450A0A / #B91C1C / #F87171 | 5.84:1 on bg, 6.45:1 on surface-0 |
| Info | #EFF6FF / #93C5FD / #1D4ED8 | 6.16:1 on bg, 6.70:1 on surface-0 | #172554 / #1D4ED8 / #93C5FD | 8.15:1 on bg, 9.90:1 on surface-0 |
| Neutral | #F1F5F9 / #CBD5E1 / #334155 | 9.45:1 on bg | #1E293B / #475569 / #CBD5E1 | 9.85:1 on bg |

Body text inside callouts uses `--color-text-1`, which passes on every state background.

## Journey colours

Used for SVG strokes, glyphs and list borders. Each status also has a glyph and a stroke pattern, so colour is never the only cue.

| Token | Light | Dark | Pattern |
| --- | --- | --- | --- |
| `--color-journey-complete` | #15803D | #4ADE80 | check mark, solid stroke |
| `--color-journey-current` | #2563EB | #60A5FA | filled dot, thick stroke, ring |
| `--color-journey-upcoming` | #64748B | #94A3B8 | open circle, dashed stroke |
| `--color-journey-terminal-positive` | #15803D | #4ADE80 | star, double border |
| `--color-journey-terminal-negative` | #B91C1C | #F87171 | filled square, dotted stroke, square corners |

All five meet 3:1 against surface-0 in both themes (non-text minimum). Fill tokens reuse the state backgrounds.

## Corrections to the starting palette

| Issue | Measured | Fix |
| --- | --- | --- |
| White text on dark `--color-brand` #3B82F6 | 3.68:1, fails | Added `--color-on-brand`, #0F172A in dark (4.85:1) |
| `--color-text-3` #64748B on light surface-2 | 4.34:1, fails | Usage rule: text-3 only on surface-0 and surface-1. Use text-2 on surface-2. |
| Dark error text #F87171 on dark surface-2 | 4.47:1, fails | Usage rule: error text never on surface-2. Use it on surface-0, surface-1 or the error bg. |
| Stated ratios in the brief (for example 5.74:1 for brand) | Brand is 5.17:1 | Measured values replace stated values. All still pass where used. |

## Focus

- `--focus-outline: 3px solid var(--color-focus)` and `--focus-offset: 2px` on every `:focus-visible` interactive element.
- The outline is at least 2px thick and meets 3:1 against adjacent colours (WCAG 2.4.13 is AAA, but the design meets its area guidance anyway).
- SVG route nodes show focus with a 4px stroke in the focus colour.

## Type scale

Base 16px. Tokens give size and line height separately.

| Token | Size | Line height |
| --- | --- | --- |
| `--text-xs` | 0.75rem | 1rem |
| `--text-sm` | 0.875rem | 1.25rem |
| `--text-base` | 1rem | 1.5rem |
| `--text-lg` | 1.125rem | 1.75rem |
| `--text-xl` | 1.25rem | 1.75rem |
| `--text-2xl` | 1.5rem | 2rem |
| `--text-3xl` | 1.875rem | 2.25rem |

Fonts: `--font-sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` and `--font-mono: ui-monospace, "Cascadia Code", "Source Code Pro", monospace`. A tenant may point these at self-hosted font files.

## Spacing

`--space-1` to `--space-16`, in 4px steps from 4px to 64px. `--space-11` (44px) and `--target-min` set the minimum touch target.

## Components in tokens.css

Skip link, `.sr-only` and `.visually-hidden`, top row and footer. `.badge` with five variants (each with a default glyph), `.callout`, `.btn` with primary, secondary, ghost and danger variants plus a dashed disabled style, `.card`, form controls with invalid and disabled states, `.journey-node--*`, SVG node classes, the strip, activity log entries, pagination and steppers.

`.voyage-label` (added 2026-11-01) styles the secondary Voyage pack line: `--text-sm`, `--color-text-2`, italic. It reuses existing tokens, so the palette and the contrast fixes above are unchanged. The `--color-journey-*` token names stay as code names. They are not shown to users.

## Accessibility notes

- Reduced motion stops the current ring pulse and replaces it with a static dashed ring.
- Disabled controls use a dashed border as well as a muted fill.
- Error fields use a 3px border and an "Error:" text prefix.

## Spec IDs

I-70, I-72, R-NF-03, ADR-014 (self-hosted fonts, no third-party assets).

## Open points

- Tenant overrides must pass the same contrast check. Recommendation: the tenant settings page runs the check server-side and refuses a failing pair.
