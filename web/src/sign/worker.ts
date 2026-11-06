// The signing module Worker (ADR-016, ADR-014). The signing page posts
// `{ revision, field, contentsBytes }`; the Worker answers with the
// appended bytes of one increment, or a typed refusal. It touches no DOM
// and does no hashing or signing.

import { handleMessage } from "./prepare.js";

const scope = globalThis as unknown as DedicatedWorkerGlobalScope;

scope.addEventListener("message", (event: MessageEvent<unknown>) => {
  const reply = handleMessage(event.data);
  if (reply.ok) {
    scope.postMessage(reply, [reply.increment]);
  } else {
    scope.postMessage(reply);
  }
});
