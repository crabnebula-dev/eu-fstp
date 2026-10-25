# Specification viewer

Builds `dist/fstp-spec-viewer.html`, a single-file browsable view of this repository with search and tappable identifiers.

Run `npm install` then `npm run build` in this folder.

This is documentation tooling, not part of the platform. It uses marked 12.0.2 at build time. The platform dependency policy in `CLAUDE.md` does not apply here.

When a new markdown file is added to the repository, add it to a group in `build.js`. The build fails if any markdown file is unlisted.
