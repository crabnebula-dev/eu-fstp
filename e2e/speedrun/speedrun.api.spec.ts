/**
 * The speedrun of M5 design section 1.2, rows 5 to 14, through the API
 * the post-grant screens call (lane L-DEMO). It is the M5 exit test for
 * "call cycle through to PAID" at the wire. Each person signs in by the
 * "Sign in as" link of the demo page and acts with their own session.
 * `speedrun.ui.spec.ts` runs the same path through the screens.
 *
 * Rows 1 to 4 (build and activate, publish, submit, review and IRC) run
 * in the M4 specs. The scene `NEGOTIATION_READY` starts after them.
 *
 * Covers R-NG-03, R-CT-01, R-CT-04, R-PR-01 to R-PR-05, R-RP-03, R-RP-04
 * and the invariants I-05, I-30, I-31, I-32, I-33, I-44, I-64, I-86.
 * Every person and text is synthetic.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { Seat, WHO, X, chooseGrantScene, demoLink, until } from './support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

type Json = Record<string, unknown>;

/** The payment requests of the grant, as the lead reads them. */
async function requests(lead: Seat): Promise<Json[]> {
  const v = await lead.ok('GET', `/grants/${X}/payment-requests`);
  const rows = (v.requests ?? v.items ?? v) as unknown;
  return Array.isArray(rows) ? (rows as Json[]) : [];
}

test.describe('speedrun at the wire', () => {
  test.describe.configure({ timeout: 600_000 });

  test('speedrun_negotiation_to_paid_and_closed', async ({ browser }) => {
    const cell = await chooseGrantScene(browser, 'NEGOTIATION_READY');
    const lead = await Seat.signIn(browser, cell, WHO.lead);
    const pm = await Seat.signIn(browser, cell, WHO.pm);
    const reviewer = await Seat.signIn(browser, cell, WHO.reviewer);
    const signatory = await Seat.signIn(browser, cell, WHO.signatory);
    const finance = await Seat.signIn(browser, cell, WHO.finance);
    const releaser = await Seat.signIn(browser, cell, WHO.releaser);
    const approver = await Seat.signIn(browser, cell, WHO.reportApprover);
    const auditor = await Seat.signIn(browser, cell, WHO.auditor);

    // Row 5: the assigned reviewer determines the amount (R-NG-03). The lead cannot.
    await lead.refused('POST', `/grants/${X}/amount-determination`, {
      agreed: '6001',
      deductions: [],
      currency: 'EUR',
    });
    await reviewer.ok('POST', `/grants/${X}/amount-determination`, {
      agreed: '6001',
      deductions: [],
      currency: 'EUR',
    });
    const overview = await lead.ok('GET', `/grants/${X}`);
    const determination = String(overview.determination);
    expect(determination, 'the lead reads the determination').toMatch(/^\d+$/);
    await lead.ok('POST', `/grants/${X}/acceptance`, { determination });
    await pm.ok('POST', `/grants/${X}/approval`, { determination });

    // Row 6: draft the contract, agree a clause change, send (R-CT-01, R-CT-04).
    await lead.refused('POST', `/grants/${X}/contract`, {});
    const contract = String((await pm.ok('POST', `/grants/${X}/contract`, {})).contract);
    await lead.ok('POST', `/contracts/${contract}/changes`, {
      clause: 1,
      text: 'Synthetic change: the milestone report is due in English.',
    });
    // The proposing side does not decide its own change.
    await lead.refused('POST', `/contracts/${contract}/changes/1/decision`, { accept: true });
    await pm.ok('POST', `/contracts/${contract}/changes/1/decision`, { accept: true });
    await pm.ok('POST', `/contracts/${contract}/send`, {});
    const sent = await lead.ok('GET', `/grants/${X}/contract`);
    expect(sent.status, 'the contract is awaiting signatures').toBe('sent');

    // Row 7: the lead signs, the signatory countersigns, GRANTED (I-30).
    await pm.refused('POST', `/contracts/${contract}/signature`, { route: 'wallet_qes' });
    await lead.ok('POST', `/contracts/${contract}/signature`, { route: 'wallet_qes' });
    await signatory.ok('POST', `/contracts/${contract}/signature`, { route: 'qtsp_remote_qes' });
    expect((await lead.ok('GET', `/grants/${X}/contract`)).status).toBe('effective');
    expect((await pm.ok('GET', `/grants/${X}`)).state).toBe('GRANTED');

    // Row 8: the clock reaches the first milestone start, the sweep starts execution.
    await demoLink(browser, cell, '/demo/clock?to=milestone_start');
    await until(
      'the grant is IN_EXECUTION',
      async () => (await pm.ok('GET', `/grants/${X}`)).state,
      (s) => s === 'IN_EXECUTION',
    );

    // Row 9: the lead enters bank details, finance verifies, the hold elapses (I-33).
    const enter = String((await lead.ok('POST', `/grants/${X}/bank-details`, {})).redirect);
    await lead.page.goto(new URL(enter, cell.origin).href);
    await lead.page.locator('#vault-action').click();
    await expect(lead.page.locator('#vault-done')).toBeVisible();
    const verify = String((await finance.ok('POST', `/grants/${X}/bank-details/verification`, {})).redirect);
    await finance.page.goto(new URL(verify, cell.origin).href);
    await finance.page.locator('#vault-action').click();
    await expect(finance.page.locator('#vault-done')).toBeVisible();
    // The cell is back on the app origin pages for the API calls.
    await lead.page.goto(`${cell.origin}/app/`);
    await finance.page.goto(`${cell.origin}/app/`);

    // Row 10: payment request with evidence. The fake forge answers 404 once, the checks fail,
    // the lead resubmits (I-32, R-PR-02).
    await demoLink(browser, cell, '/demo/forge/fail');
    const body = {
      kind: { type: 'Milestone' },
      currency: 'EUR',
      lines: [
        {
          milestone: '7001',
          amount: '60000.00',
          evidence: {
            location: 'http://127.0.0.1/demo/forge/synthetic-sensor-kit',
            release: 'v1.0.0',
            licence: 'MIT',
            report: 'Synthetic delivery report: the sensor kit shipped.',
          },
        },
      ],
    };
    const first = String((await lead.ok('POST', `/grants/${X}/payment-requests`, body)).request);
    const failed = await until(
      'the checks fail on the forge 404',
      () => requests(lead),
      (rows) => rows.some((r) => r.status === 'CHECKS_FAILED'),
    );
    expect(failed.length).toBeGreaterThan(0);
    await lead.ok('POST', `/payment-requests/${first}/resubmission`, body);
    const reviewing = await until(
      'the resubmitted request is under review',
      () => requests(lead),
      (rows) => rows.some((r) => r.status === 'UNDER_REVIEW'),
    );
    const request = String(reviewing.find((r) => r.status === 'UNDER_REVIEW')?.request);
    const line = String(
      ((reviewing.find((r) => r.status === 'UNDER_REVIEW')?.lines as Json[] | undefined) ?? [])[0]?.line,
    );

    // Row 11: line review, payment approval, release, paid (I-05, I-31, I-33).
    await lead.refused('POST', `/payment-requests/${request}/lines/${line}/decision`, {
      approved: '60000.00',
      currency: 'EUR',
    });
    await reviewer.ok('POST', `/payment-requests/${request}/lines/${line}/decision`, {
      approved: '60000.00',
      currency: 'EUR',
    });
    await finance.ok('POST', `/payment-requests/${request}/approval`, {});
    // I-33: the bank hold has not elapsed, so the release is refused.
    await releaser.refused('POST', `/payment-requests/${request}/release`, {});
    await demoLink(browser, cell, '/demo/clock?to=p36');
    await releaser.ok('POST', `/payment-requests/${request}/release`, {});
    await releaser.ok('POST', `/payment-requests/${request}/payee`, {});
    await finance.ok('POST', `/payment-requests/${request}/paid`, {});
    expect((await pm.ok('GET', `/grants/${X}`)).paid).toBe('60000.00');

    // Row 13: the programme manager closes the milestone, the sweep completes the grant (I-64).
    await pm.ok('POST', `/grants/${X}/milestones/7001/closure`, {
      reason: 'Synthetic closure: the milestone was delivered and paid.',
    });
    await until(
      'the grant is COMPLETED',
      async () => (await pm.ok('GET', `/grants/${X}`)).state,
      (s) => s === 'COMPLETED',
    );

    // Row 14: five funder outputs, approved by the Financial signatory, never by the generator (R-RP-03).
    for (const kind of ['call_publication_record', 'audit_file', 'deliverable_draft', 'open_call_package']) {
      const report = String((await pm.ok('POST', '/programmes/1/reports', { kind, call: '1' })).report);
      await pm.refused('POST', `/reports/${report}/approval`, {});
      await approver.ok('POST', `/reports/${report}/approval`, {});
    }
    const list = await auditor.ok('GET', '/programmes/1/reports');
    expect(JSON.stringify(list)).toContain('"approved":true');

    for (const s of [lead, pm, reviewer, signatory, finance, releaser, approver, auditor]) await s.close();
  });
});
