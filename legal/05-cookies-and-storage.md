# Cookies and browser storage notice

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Used where: a section of the privacy notice (`01-privacy-notice.md`, section 16), or a page of its own linked from it. No code site holds a cookie text today.

What the code does:

- The cell sets one cookie, `__Host-fstp`, with `Path=/`, `Secure`, `HttpOnly` and `SameSite=Strict` (`crates/fstp-cell/src/http/cookie.rs`). It holds a cell id and a random session token.
- The session ends after the idle and absolute lifetimes of P-72. Proposed defaults: 30 minutes idle, 12 hours absolute. A tenant can set its own.
- The agent connection page keeps one consent handle in the tab's `sessionStorage` across a sign-in, and removes it when done (`web/src/connect/page.ts`).
- Public pages run no script and carry no tracking (R-PB-04). The attribution link carries no tracking parameters.
- No analytics, advertising or third-party cookie was found in the code.

TODO(legal): confirm that a strictly necessary session cookie and the session storage entry need no consent, and whether a banner is needed at all.

---

## Cookies and similar storage

This platform uses one cookie and one browser storage entry. Both are needed for the service to work. We use no cookies for analytics or advertising, and no third-party cookies.

| Name | Type | What it does | How long |
| --- | --- | --- | --- |
| `__Host-fstp` | Cookie | Keeps you signed in. It holds a random session token, not your name or email. Your browser sends it only to this site. | Until you sign out, or until the session ends after {{P-72.idle}} without activity or {{P-72.absolute}} in total |
| Agent connection handle | Session storage in this tab | Remembers a pending agent connection while you sign in | Removed when the connection is decided, or when you close the tab |

Public pages of a programme set no cookie and run no script.

You can block cookies in your browser. You then cannot sign in.
