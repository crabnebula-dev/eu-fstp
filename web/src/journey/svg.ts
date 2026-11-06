// The progress map of the web app (ADR-015 "Rendering" and its amendment
// of 2026-11-06, ADR-014 "DOM"; `docs/design/02-voyager-route-diary.md`
// "The progress map").
//
// The server lays out and renders the map (`fstp_html::route::tree`), and
// `proposal.route_map` returns its checked element tree as data. The
// `/app/` pages run under Trusted Types with no HTML sink, so the browser
// only validates that tree against the closed SVG subset and builds it
// with `createElementNS`, `setAttribute` and text nodes (`tree.ts`). It
// lays out nothing of its own.
//
// `web/test/journey_tree.test.ts` checks that the build of the server's
// tree serialises to the renderer's golden map
// `crates/fstp-html/testdata/route_stage2.svg`, byte for byte.

export { type RouteTree, type RouteTreeAttr, type RouteTreeEl, type RouteTreeText, buildRouteTree, readRouteTree } from "./tree.js";
