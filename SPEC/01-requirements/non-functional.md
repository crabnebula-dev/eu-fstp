# Non-functional requirements

- **R-NF-01** The self-hosted cell runs on a single node with documented minimum resources.
- **R-NF-02** Logs and metrics contain no proposal content or identity attributes.
- **R-NF-03** The user interface meets WCAG 2.2 level AA.
  NOTE: The Annexe commits to outreach to under-represented parts of the community.
- **R-NF-04** The user interface is localisable. Proposal language follows P-25.
- **R-NF-05** Secure defaults apply on first start of a self-hosted cell, with no default credentials.
- **R-NF-06** Security updates for the self-hosted distribution can be applied without data migration loss.
- **R-NF-07** Each release ships with a machine-readable SBOM.
- **R-NF-08** All data at rest in a cell is encrypted with cell-specific keys. Vault keys are separate from application keys.
- **R-NF-09** All network traffic between components is encrypted and mutually authenticated.
- **R-NF-10** Loss of the inference provider does not block human evaluation.
