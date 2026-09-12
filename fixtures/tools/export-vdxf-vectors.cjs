/**
 * Regenerate fixtures/vdxf/vectors.json from verus-typescript-primitives.
 *
 * WHAT THE ORACLE IS, AND WHAT IT IS NOT
 *
 * `fixtures/transparent/` is backed by `fixtures/daemon/`: a real daemon signed
 * those bytes, so the expectation is provable offline against consensus. There
 * is no equivalent here. No daemon RPC validates a VerusPayInvoice or a
 * LoginConsentRequest — they are wallet/application-layer formats carried in QR
 * codes and deep links, never in a transaction. The oracle is therefore the
 * deployed upstream TypeScript implementation that real wallets interoperate
 * with, which is one level weaker than daemon-proven and is stated as such in
 * fixtures/vdxf/README.md. It is still an independent implementation rather
 * than this repo checking its own output against its own expectations.
 *
 * Upstream's own tests contain no hardcoded vectors — they are self round-trips
 * (`_inv.fromBuffer(inv.toBuffer())`, then compare hex), so there was nothing to
 * copy and the bytes have to be generated. This script reproduces upstream's
 * test matrix case for case and writes down what the library produces.
 *
 * HOW TO RUN
 *
 *   git clone https://github.com/VerusCoin/verus-typescript-primitives.git
 *   cd verus-typescript-primitives
 *   git checkout 4243cd075b4f68df1ce72fd2fd9c9b18ac36767e
 *   yarn install --frozen-lockfile     # ~7s; dist/ is already committed at this pin
 *
 *   PRIMITIVES=/path/to/verus-typescript-primitives \
 *     NODE_PATH=$PRIMITIVES/node_modules \
 *     node fixtures/tools/export-vdxf-vectors.cjs
 *
 * `4243cd075b4f68df1ce72fd2fd9c9b18ac36767e` is the exact pin that
 * chainvue/verus-sdk depends on (package.json:59), and this script refuses to
 * run against a different checkout unless ALLOW_UNPINNED=1 is set. NODE_PATH is
 * what lets this file — which lives in a repo with no node_modules of its own —
 * resolve `bn.js`. Unlike export-vectors.cjs, nothing here needs a *built*
 * verus-sdk: the primitives package is required directly.
 *
 * The output is COMMITTED test data. Nothing is fetched at build or test time.
 * Run this only when a rule genuinely changes upstream, and review the byte diff
 * rather than rubber-stamping it.
 *
 * Money and heights are written as decimal strings, taken from BN.toString(10),
 * so no value passes through a JavaScript double on its way to the file.
 *
 * DELIBERATELY NOT COVERED: `isTagged` / CompactXAddressObject (x-addresses).
 * See fixtures/vdxf/README.md for why.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const PINNED_COMMIT = "4243cd075b4f68df1ce72fd2fd9c9b18ac36767e";

const PRIMITIVES = process.env.PRIMITIVES;
if (!PRIMITIVES) {
  console.error(
    "PRIMITIVES is not set. Point it at a checkout of\n" +
      "https://github.com/VerusCoin/verus-typescript-primitives at " +
      PINNED_COMMIT +
      "\nand run with NODE_PATH=$PRIMITIVES/node_modules. See the header of this file."
  );
  process.exit(1);
}

function checkoutCommit() {
  try {
    return execFileSync("git", ["-C", PRIMITIVES, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch (e) {
    return null;
  }
}

const commit = checkoutCommit();
if (commit !== PINNED_COMMIT && process.env.ALLOW_UNPINNED !== "1") {
  console.error(
    `${PRIMITIVES} is at ${commit || "an unknown commit"}, not the pin ${PINNED_COMMIT}.\n` +
      "These vectors record one implementation at one revision; generating them from\n" +
      "another revision without saying so makes the fixture a lie. Check out the pin,\n" +
      "or set ALLOW_UNPINNED=1 and update the pin in this file and in vectors.json."
  );
  process.exit(1);
}

const { BN } = require("bn.js");
const P = require(path.join(PRIMITIVES, "dist", "index.js"));

const {
  // VerusPay
  VerusPayInvoice,
  VerusPayInvoiceDetails,
  TransferDestination,
  DEST_PKH,
  SaplingPaymentAddress,
  VERUSPAY_VERSION_3,
  VERUSPAY_VERSION_4,
  fromBase58Check,
  // Login consent
  LoginConsentRequest,
  LoginConsentResponse,
  LoginConsentProvisioningRequest,
  LoginConsentProvisioningResponse,
  LoginConsentProvisioningResult,
  ProvisioningTxid,
  Context,
  Credential,
  RequestedPermission,
  Subject,
  ProvisioningInfo,
  RedirectUri,
  // Keys
  IDENTITY_VIEW,
  ID_FULLYQUALIFIEDNAME_VDXF_KEY,
  ID_ADDRESS_VDXF_KEY,
  ID_SYSTEMID_VDXF_KEY,
  ID_PARENT_VDXF_KEY,
  LOGIN_CONSENT_ID_PROVISIONING_WEBHOOK_VDXF_KEY,
  LOGIN_CONSENT_REDIRECT_VDXF_KEY,
  IDENTITY_CREDENTIAL_PLAINLOGIN,
  IDENTITY_NAME_COMMITMENT_TXID,
  IDENTITY_REGISTRATION_TXID,
  LOGIN_CONSENT_PROVISIONING_RESULT_STATE_PENDINGAPPROVAL,
  LOGIN_CONSENT_PROVISIONING_ERROR_KEY_UNKNOWN,
} = P;

// ---------------------------------------------------------------------------
// Shared inputs. Every one of these is lifted verbatim from the upstream tests
// (src/__tests__/vdxf/veruspayinvoice.test.ts, .../loginconsent.test.ts) so a
// reviewer can diff the two side by side.
// ---------------------------------------------------------------------------

const VRSCTEST = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const DEST_R_ADDR = "R9J8E2no2HVjQmzX6Ntes2ShSGcn7WiRcx";
const SYSTEM_A = "iNC9NG5Jqk2tqVtqfjfiSpaqxrXaFU6RDu";
const SYSTEM_B = "iBDkVJqik6BrtcDBQfFygffiYzTMy6EuhU";
const SIG_SYSTEM_ID = "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV";
const SIG_SIGNING_ID = "iB5PRXMHLYcNtM8dfLB6KwfJrHU2mKDYuU";
const SIGNATURE_B64 =
  "AYG2IQABQSAN1fp6A9NIVbxvKuOVLLU+0I+G3oQGbRtS6u4Eampfb217Cdf5FCMScQhV9kMxtjI9GWzpchmjuiTB2tctk6qT";
const SAPLING_ADDR =
  "zs1wczplx4kegw32h8g0f7xwl57p5tvnprwdmnzmdnsw50chcl26f7tws92wk2ap03ykaq6jyyztfa";

// The one height every hash in this file is taken at. Upstream uses 10000.
const SIGNED_BLOCKHEIGHT = 10000;

const AMOUNT = "10000000000"; // 100 VRSCTEST in satoshis
const SLIPPAGE = "40000000"; // 0.4 in satoshis
const EXPIRY = "2000000";

function pkhDestination(address) {
  return new TransferDestination({
    type: DEST_PKH,
    destination_bytes: fromBase58Check(address).hash,
  });
}

const vectors = [];

// ---------------------------------------------------------------------------
// VerusPay invoices
// ---------------------------------------------------------------------------

/**
 * Builds one invoice, asserts the three round-trips upstream asserts, and
 * records what the library produced.
 */
function emitInvoice({ name, why, version, details: detailsData, flags, signed }) {
  const details = new VerusPayInvoiceDetails(detailsData, version);
  if (flags) details.setFlags(flags);

  const invoice = new VerusPayInvoice(
    signed
      ? {
          details,
          system_id: SIG_SYSTEM_ID,
          signing_id: SIG_SIGNING_ID,
          signature: { signature: SIGNATURE_B64 },
          version,
        }
      : { details, version }
  );
  if (signed) invoice.setSigned();

  const full = invoice.toBuffer();
  const unkeyed = invoice.toBuffer(false);
  const qrString = invoice.toQrString();
  const deeplinkUri = invoice.toWalletDeeplinkUri();

  // The three properties upstream's tests assert, re-asserted here: if any of
  // them fails the vector is not worth writing down.
  assertHexEq(
    reparse(new VerusPayInvoice(), full),
    full,
    `${name}: buffer round-trip`
  );
  assertHexEq(
    VerusPayInvoice.fromQrString(qrString).toBuffer(),
    full,
    `${name}: QR round-trip`
  );
  assertHexEq(
    VerusPayInvoice.fromWalletDeeplinkUri(deeplinkUri).toBuffer(),
    full,
    `${name}: deeplink round-trip`
  );
  assertHexEq(
    VerusPayInvoice.fromJson(invoice.toJson()).toBuffer(),
    full,
    `${name}: JSON round-trip`
  );

  const vector = {
    name,
    why,
    kind: "veruspay_invoice",
    vdxfkey: invoice.vdxfkey,
    veruspay_version: version.toString(10),
    signed: !!signed,
    // `version` as serialized: the signed flag is bit 31 of the same field.
    serialized_version: invoice.version.toString(10),
    system_id: signed ? SIG_SYSTEM_ID : null,
    signing_id: signed ? SIG_SIGNING_ID : null,
    signature: signed ? SIGNATURE_B64 : null,
    // Upstream's own JSON form of the details, verbatim: every number is
    // already a decimal string there, so nothing passes through a double.
    details: invoice.details.toJson(),
    flags_decoded: invoice.details.getFlagsJson(),
    details_hex: invoice.details.toBuffer().toString("hex"),
    details_sha256: invoice.details.toSha256().toString("hex"),
    full_hex: full.toString("hex"),
    deeplink_payload_hex: unkeyed.toString("hex"),
    qr_string: qrString,
    deeplink_uri: deeplinkUri,
  };

  // getDetailsHash folds system_id, height and signing_id in only once the
  // invoice is signed; unsigned it is just details_sha256, so recording it
  // would be recording the same bytes twice.
  if (signed) {
    vector.details_hash_sigv1_h10000 = invoice
      .getDetailsHash(SIGNED_BLOCKHEIGHT, 1)
      .toString("hex");
    vector.details_hash_sigv2_h10000 = invoice
      .getDetailsHash(SIGNED_BLOCKHEIGHT, 2)
      .toString("hex");
  }

  vectors.push(vector);
}

function reparse(obj, buffer) {
  obj.fromBuffer(buffer);
  return obj.toBuffer();
}

function assertHexEq(actual, expected, what) {
  const a = Buffer.isBuffer(actual) ? actual.toString("hex") : actual;
  const b = Buffer.isBuffer(expected) ? expected.toString("hex") : expected;
  if (a !== b) {
    throw new Error(`${what} failed:\n  got      ${a}\n  expected ${b}`);
  }
}

// The six cases upstream runs against BOTH v3 and v4. v3 writes its varuints
// with writeVarInt and v4 with writeCompactSize, so the same logical invoice is
// a different byte string under each — which is the whole reason to emit both.
for (const version of [VERUSPAY_VERSION_3, VERUSPAY_VERSION_4]) {
  const v = version.toString(10);

  emitInvoice({
    name: `invoice_v${v}_basic`,
    why: `the baseline: fixed amount to a PKH destination, v${v} varuint encoding`,
    version,
    details: {
      amount: new BN(AMOUNT, 10),
      destination: pkhDestination(DEST_R_ADDR),
      requestedcurrencyid: VRSCTEST,
    },
  });

  emitInvoice({
    name: `invoice_v${v}_any_amount_any_destination`,
    why:
      "acceptsAnyAmount and acceptsAnyDestination both suppress a field: " +
      "amount and destination must be absent from the bytes, not zeroed",
    version,
    details: { requestedcurrencyid: VRSCTEST },
    flags: { acceptsAnyAmount: true, acceptsAnyDestination: true },
  });

  emitInvoice({
    name: `invoice_v${v}_accepts_conversion`,
    why: "acceptsConversion appends maxestimatedslippage after the currency id",
    version,
    details: {
      amount: new BN(AMOUNT, 10),
      destination: pkhDestination(DEST_R_ADDR),
      requestedcurrencyid: VRSCTEST,
      maxestimatedslippage: new BN(SLIPPAGE, 10),
    },
    flags: { acceptsConversion: true },
  });

  emitInvoice({
    name: `invoice_v${v}_accepts_conversion_expires`,
    why:
      "expiryheight is written BEFORE maxestimatedslippage even though the " +
      "expires flag (8) is a HIGHER bit than acceptsConversion (2) — field " +
      "order is not flag order",
    version,
    details: {
      amount: new BN(AMOUNT, 10),
      destination: pkhDestination(DEST_R_ADDR),
      requestedcurrencyid: VRSCTEST,
      maxestimatedslippage: new BN(SLIPPAGE, 10),
      expiryheight: new BN(EXPIRY, 10),
    },
    flags: { acceptsConversion: true, expires: true },
  });

  emitInvoice({
    name: `invoice_v${v}_two_nonverus_systems_expires`,
    why:
      "acceptsNonVerusSystems appends a counted array of 20-byte hashes; the " +
      "order of acceptedsystems is part of the expectation",
    version,
    details: {
      amount: new BN(AMOUNT, 10),
      destination: pkhDestination(DEST_R_ADDR),
      requestedcurrencyid: VRSCTEST,
      maxestimatedslippage: new BN(SLIPPAGE, 10),
      expiryheight: new BN(EXPIRY, 10),
      acceptedsystems: [SYSTEM_A, SYSTEM_B],
    },
    flags: { acceptsConversion: true, expires: true, acceptsNonVerusSystems: true },
  });

  emitInvoice({
    name: `invoice_v${v}_signed_two_nonverus_systems_expires`,
    why:
      "the signed path: bit 31 of the version field prepends system_id, " +
      "signing_id and the signature ahead of the details",
    version,
    signed: true,
    details: {
      amount: new BN(AMOUNT, 10),
      destination: pkhDestination(DEST_R_ADDR),
      requestedcurrencyid: VRSCTEST,
      maxestimatedslippage: new BN(SLIPPAGE, 10),
      expiryheight: new BN(EXPIRY, 10),
      acceptedsystems: [SYSTEM_A, SYSTEM_B],
    },
    flags: { acceptsConversion: true, expires: true, acceptsNonVerusSystems: true },
  });
}

// v4-only: the three v4 flags live above bit 8 and setFlags drops them on v3.

emitInvoice({
  name: "invoice_v4_signed_sapling_destination",
  why:
    "destinationIsSaplingPaymentAddress (512) swaps a 43-byte TransferDestination " +
    "for an 88-byte SaplingPaymentAddress in the same field position; v4 only",
  version: VERUSPAY_VERSION_4,
  signed: true,
  details: {
    amount: new BN(AMOUNT, 10),
    destination: SaplingPaymentAddress.fromAddressString(SAPLING_ADDR),
    requestedcurrencyid: VRSCTEST,
    maxestimatedslippage: new BN(SLIPPAGE, 10),
    expiryheight: new BN(EXPIRY, 10),
    acceptedsystems: [SYSTEM_A, SYSTEM_B],
  },
  flags: {
    acceptsConversion: true,
    expires: true,
    acceptsNonVerusSystems: true,
    destinationIsSaplingPaymentAddress: true,
  },
});

emitInvoice({
  name: "invoice_v4_any_amount_any_destination_preconvert",
  why:
    "isPreconvert (256) changes no field, only the meaning of the invoice, and " +
    "is silently dropped on v3 — so it pins that the flag survives a v4 round trip",
  version: VERUSPAY_VERSION_4,
  details: { requestedcurrencyid: SYSTEM_A },
  flags: { acceptsAnyAmount: true, acceptsAnyDestination: true, isPreconvert: true },
});

// ---------------------------------------------------------------------------
// Login consent
//
// Each vector records its inputs as a plain literal — strings, integers and
// arrays, nothing class-shaped — and that same literal is what builds the
// object. Upstream's own `toJson()` is not used as the input description
// because it leaks internals a consumer should not have to reproduce: BN
// versions as hex ("01"), `serializekey`, and the `base58Keys` lookup table
// Subject carries. Array order below is part of the expectation.
// ---------------------------------------------------------------------------

const CONTEXT_KEY = "i4KyLCxWZXeSkw15dF95CUKytEK3HU7em9";

// A Context serializes its entries in Object.keys order, i.e. insertion order,
// so the order of these pairs is part of the expectation. They are recorded as
// an ORDERED ARRAY rather than a JSON object precisely so that no consumer is
// tempted to read them into a sorted map.
function contextFrom(pairs) {
  const kv = {};
  for (const { key, value } of pairs) kv[key] = value;
  return new Context(kv);
}

const LOGIN_CHALLENGE_INPUT = {
  challenge_id: "iKNufKJdLX3Xg8qFru9AuLBvivAEJ88PW4",
  requested_access: [{ vdxfkey: IDENTITY_VIEW.vdxfid }],
  subject: [
    { vdxfkey: ID_FULLYQUALIFIEDNAME_VDXF_KEY.vdxfid, data: "fully.qualified.name" },
    { vdxfkey: ID_ADDRESS_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
    { vdxfkey: ID_SYSTEMID_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
    { vdxfkey: ID_PARENT_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
  ],
  provisioning_info: [
    {
      vdxfkey: LOGIN_CONSENT_ID_PROVISIONING_WEBHOOK_VDXF_KEY.vdxfid,
      data: "https://127.0.0.1/",
    },
    { vdxfkey: ID_ADDRESS_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
    { vdxfkey: ID_SYSTEMID_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
    { vdxfkey: ID_PARENT_VDXF_KEY.vdxfid, data: SIG_SIGNING_ID },
  ],
  session_id: "iRQZGW36o3RcVR1xyVT1qWdAKdxp3wUyrh",
  redirect_uris: [
    { vdxfkey: LOGIN_CONSENT_REDIRECT_VDXF_KEY.vdxfid, uri: "https://www.verus.io" },
  ],
  created_at: 1664382484,
  salt: "i6NawEzHMocZnU4h8pPkGpHApvsrHjxwXE",
  context: [{ key: CONTEXT_KEY, value: "test" }],
};

const LOGIN_REQUEST_INPUT = {
  system_id: SIG_SYSTEM_ID,
  signing_id: SIG_SIGNING_ID,
  signature: SIGNATURE_B64,
  challenge: LOGIN_CHALLENGE_INPUT,
};

// A Subject and a ProvisioningInfo take (data, vdxfkey); a RedirectUri takes
// (uri, vdxfkey). Getting those the wrong way round still constructs.
function buildLoginChallenge(input) {
  return {
    challenge_id: input.challenge_id,
    requested_access: input.requested_access.map((x) => new RequestedPermission(x.vdxfkey)),
    subject: input.subject.map((x) => new Subject(x.data, x.vdxfkey)),
    provisioning_info: input.provisioning_info.map(
      (x) => new ProvisioningInfo(x.data, x.vdxfkey)
    ),
    session_id: input.session_id,
    redirect_uris: input.redirect_uris.map((x) => new RedirectUri(x.uri, x.vdxfkey)),
    created_at: input.created_at,
    salt: input.salt,
    context: contextFrom(input.context),
  };
}

function buildLoginRequest(input) {
  return new LoginConsentRequest({
    system_id: input.system_id,
    signing_id: input.signing_id,
    signature: input.signature ? { signature: input.signature } : undefined,
    challenge: buildLoginChallenge(input.challenge),
  });
}

function buildLoginResponse(input) {
  return new LoginConsentResponse({
    system_id: input.system_id,
    signing_id: input.signing_id,
    signature: input.signature ? { signature: input.signature } : undefined,
    decision: {
      decision_id: input.decision.decision_id,
      created_at: input.decision.created_at,
      context: contextFrom(input.decision.context),
      request: buildLoginRequest(input.decision.request),
    },
  });
}

function emitLoginRequest({ name, why, input }) {
  const request = buildLoginRequest(input);
  const full = request.toBuffer();
  assertHexEq(reparse(new LoginConsentRequest(), full), full, `${name}: buffer round-trip`);

  // Request.toQrString() and toWalletDeeplinkUri() both THROW
  // "Request must be signed before it can be used as a deep link" when
  // `signature` is null, which is why every request vector here carries one.
  const qrString = request.toQrString();
  const deeplinkUri = request.toWalletDeeplinkUri();
  assertHexEq(
    LoginConsentRequest.fromQrString(qrString).toBuffer(),
    full,
    `${name}: QR round-trip`
  );
  assertHexEq(
    LoginConsentRequest.fromWalletDeeplinkUri(deeplinkUri).toBuffer(),
    full,
    `${name}: deeplink round-trip`
  );

  vectors.push({
    name,
    why,
    kind: "login_consent_request",
    vdxfkey: request.vdxfkey,
    request: input,
    full_hex: full.toString("hex"),
    deeplink_payload_hex: full.toString("hex"),
    challenge_sha256: request.challenge.toSha256().toString("hex"),
    // The argument pair matters: signatureVersion 1 puts the Verus data
    // signature prefix FIRST, 2 puts it after signing_id. Both are reachable,
    // both are recorded, and they are different hashes of the same challenge.
    challenge_hash_sigv1_h10000: request
      .getChallengeHash(SIGNED_BLOCKHEIGHT, 1)
      .toString("hex"),
    challenge_hash_sigv2_h10000: request
      .getChallengeHash(SIGNED_BLOCKHEIGHT, 2)
      .toString("hex"),
    qr_string: qrString,
    deeplink_uri: deeplinkUri,
  });
}

function emitLoginResponse({ name, why, input, extra }) {
  const response = buildLoginResponse(input);
  const full = response.toBuffer();
  assertHexEq(reparse(new LoginConsentResponse(), full), full, `${name}: buffer round-trip`);

  vectors.push(
    Object.assign(
      {
        name,
        why,
        kind: "login_consent_response",
        vdxfkey: response.vdxfkey,
        // A response embeds the whole request it answers. There is no QR or
        // deeplink form: Response has neither method.
        response: input,
        full_hex: full.toString("hex"),
        decision_sha256: response.decision.toSha256().toString("hex"),
        decision_hash_sigv1_h10000: response
          .getDecisionHash(SIGNED_BLOCKHEIGHT, 1)
          .toString("hex"),
        decision_hash_sigv2_h10000: response
          .getDecisionHash(SIGNED_BLOCKHEIGHT, 2)
          .toString("hex"),
      },
      extra || {}
    )
  );
}

emitLoginRequest({
  name: "login_consent_request_signed",
  why:
    "the signed request: system_id, signing_id and an IDENTITY_AUTH_SIG signature " +
    "ahead of a challenge carrying base58 and utf-8 subjects, provisioning info, " +
    "a redirect uri and a context",
  input: LOGIN_REQUEST_INPUT,
});

emitLoginResponse({
  name: "login_consent_response_signed",
  why:
    "the signed response, whose signature uses a DIFFERENT vdxf key than the " +
    "request's, and which embeds the whole request it answers",
  input: {
    system_id: SIG_SYSTEM_ID,
    signing_id: SIG_SIGNING_ID,
    signature: SIGNATURE_B64,
    decision: {
      decision_id: "iBTMBHzDbsW3QG1MLBoYtmo6c1xuzn6xxb",
      created_at: 1664392484,
      context: [{ key: CONTEXT_KEY, value: "test" }],
      request: LOGIN_REQUEST_INPUT,
    },
  },
});

// Credentials travel as hex strings inside the decision's context map, so the
// credential encoding is pinned beside the response that carries it.
const PLAINLOGIN = IDENTITY_CREDENTIAL_PLAINLOGIN.vdxfid;

function credentialFrom(input) {
  return new Credential({
    version: Credential.VERSION_CURRENT,
    credentialKey: input.credential_key,
    credential: input.credential,
    scopes: input.scopes,
    label: input.label,
  });
}

function emitCredentialResponse({ name, why, credentialInputs }) {
  const credentials = credentialInputs.map(credentialFrom);
  const context = credentials.map((cred) => ({
    key: cred.credentialKey,
    value: cred.toBuffer().toString("hex"),
  }));

  emitLoginResponse({
    name,
    why,
    input: {
      system_id: SIG_SYSTEM_ID,
      signing_id: SIG_SIGNING_ID,
      signature: SIGNATURE_B64,
      decision: {
        decision_id: "iBTMBHzDbsW3QG1MLBoYtmo6c1xuzn6xxb",
        created_at: 1664392484,
        context,
        request: LOGIN_REQUEST_INPUT,
      },
    },
    extra: {
      credentials: credentials.map((cred, i) => Object.assign({}, credentialInputs[i], {
        version: Credential.VERSION_CURRENT.toString(10),
        hex: cred.toBuffer().toString("hex"),
      })),
    },
  });
}

emitCredentialResponse({
  name: "login_consent_response_one_credential",
  why:
    "a Credential serialized to hex and carried in the decision context under " +
    "its own vdxf key: pins the Credential encoding and the context map entry",
  credentialInputs: [
    {
      credential_key: PLAINLOGIN,
      credential: ["shortname", "cookies"],
      scopes: ["FileSharingSite@"],
    },
  ],
});

emitCredentialResponse({
  name: "login_consent_response_two_credentials",
  why:
    "two credentials under two keys, the second carrying an optional label: " +
    "pins the label branch and that context keys keep insertion order",
  credentialInputs: [
    {
      credential_key: PLAINLOGIN,
      credential: ["myemail1990@uniqueemailservice.com", "secretpassword"],
      scopes: ["UniqueEmailService@"],
    },
    {
      credential_key: "iHHVJux4xjahxzGTe8esqfnAmr3s9qi9pH",
      credential: ["1234567891011121"],
      scopes: ["UniqueEmailService@"],
      label: "hint: numbers",
    },
  ],
});

// ---------------------------------------------------------------------------
// Provisioning request / response
// ---------------------------------------------------------------------------

const PROVISIONING_REQUEST_INPUT = {
  // An R-address, not an i-address: ProvisioningRequest reads signing_address
  // back with R_ADDR_VERSION while a login request uses I_ADDR_VERSION.
  signing_address: "RYQbUr9WtRRAnMjuddZGryrNEpFEV1h8ph",
  signature: SIGNATURE_B64,
  challenge: {
    challenge_id: "iKNufKJdLX3Xg8qFru9AuLBvivAEJ88PW4",
    created_at: 1664382484,
    salt: "i6NawEzHMocZnU4h8pPkGpHApvsrHjxwXE",
    context: [{ key: CONTEXT_KEY, value: "test" }],
    name: "\u{1F60A}",
    system_id: SIG_SYSTEM_ID,
    parent: SIG_SYSTEM_ID,
  },
};

function buildProvisioningRequest(input) {
  return new LoginConsentProvisioningRequest({
    signing_address: input.signing_address,
    signature: input.signature ? { signature: input.signature } : undefined,
    challenge: {
      challenge_id: input.challenge.challenge_id,
      created_at: input.challenge.created_at,
      salt: input.challenge.salt,
      context: contextFrom(input.challenge.context),
      name: input.challenge.name,
      system_id: input.challenge.system_id,
      parent: input.challenge.parent,
    },
  });
}

{
  const input = PROVISIONING_REQUEST_INPUT;
  const req = buildProvisioningRequest(input);
  const full = req.toBuffer();
  assertHexEq(
    reparse(new LoginConsentProvisioningRequest(), full),
    full,
    "provisioning_request: buffer round-trip"
  );

  vectors.push({
    name: "provisioning_request_non_ascii_name",
    why:
      "the requested identity name is a single emoji: pins that name is a utf-8 " +
      "byte string behind a byte-count prefix, not a character count",
    kind: "provisioning_request",
    vdxfkey: req.vdxfkey,
    request: input,
    full_hex: full.toString("hex"),
    challenge_sha256: req.challenge.toSha256().toString("hex"),
    // ProvisioningRequest.getChallengeHash() takes NO height and NO signature
    // version: it is sha256(prefix || challenge_sha256), a different shape from
    // Request.getChallengeHash, which is why it is spelled differently here.
    challenge_hash: req.getChallengeHash().toString("hex"),
  });
}

const PROVISIONING_RESULT_INPUT = {
  state: LOGIN_CONSENT_PROVISIONING_RESULT_STATE_PENDINGAPPROVAL.vdxfid,
  error_key: LOGIN_CONSENT_PROVISIONING_ERROR_KEY_UNKNOWN.vdxfid,
  error_desc: "Testing an error",
  identity_address: SIG_SYSTEM_ID,
  info_uri: "127.0.0.1",
  provisioning_txids: [
    {
      txid: "402e437df5aea8dc7af42f3072a43ef0e9e27edfbd2072c08aeea8e07024ee40",
      vdxfkey: IDENTITY_NAME_COMMITMENT_TXID.vdxfid,
    },
    {
      txid: "402e437df5aea8dc7af42f3072a43ef0e9e27edfbd2072c08aeea8e07024ee40",
      vdxfkey: IDENTITY_REGISTRATION_TXID.vdxfid,
    },
  ],
  system_id: SIG_SYSTEM_ID,
  fully_qualified_name: "\u{1F60A}.vrsc",
  parent: SIG_SYSTEM_ID,
};

const PROVISIONING_RESPONSE_INPUT = {
  system_id: SIG_SYSTEM_ID,
  signing_id: SIG_SIGNING_ID,
  signature: SIGNATURE_B64,
  decision: {
    decision_id: "iBTMBHzDbsW3QG1MLBoYtmo6c1xuzn6xxb",
    created_at: 1664392484,
    context: [{ key: CONTEXT_KEY, value: "test" }],
    request: PROVISIONING_REQUEST_INPUT,
    result: PROVISIONING_RESULT_INPUT,
  },
};

{
  const input = PROVISIONING_RESPONSE_INPUT;
  const result = new LoginConsentProvisioningResult({
    state: input.decision.result.state,
    error_key: input.decision.result.error_key,
    error_desc: input.decision.result.error_desc,
    identity_address: input.decision.result.identity_address,
    info_uri: input.decision.result.info_uri,
    provisioning_txids: input.decision.result.provisioning_txids.map(
      (x) => new ProvisioningTxid(x.txid, x.vdxfkey)
    ),
    system_id: input.decision.result.system_id,
    fully_qualified_name: input.decision.result.fully_qualified_name,
    parent: input.decision.result.parent,
  });

  const res = new LoginConsentProvisioningResponse({
    system_id: input.system_id,
    signing_id: input.signing_id,
    signature: { signature: input.signature },
    decision: {
      decision_id: input.decision.decision_id,
      created_at: input.decision.created_at,
      context: contextFrom(input.decision.context),
      request: buildProvisioningRequest(input.decision.request),
      result,
    },
  });

  const full = res.toBuffer();
  assertHexEq(
    reparse(new LoginConsentProvisioningResponse(), full),
    full,
    "provisioning_response: buffer round-trip"
  );

  vectors.push({
    name: "provisioning_response_result_non_ascii_fqn",
    why:
      "a full ProvisioningResult: every optional field present, two provisioning " +
      "txids whose order is part of the expectation, and a fully qualified name " +
      "whose first character is a 4-byte emoji",
    kind: "provisioning_response",
    vdxfkey: res.vdxfkey,
    response: input,
    full_hex: full.toString("hex"),
    decision_sha256: res.decision.toSha256().toString("hex"),
    result_hex: result.toBuffer().toString("hex"),
    // Upstream calls getDecisionHash(10000) here, taking the default
    // signatureVersion 2. Both are recorded because both are reachable.
    decision_hash_sigv1_h10000: res
      .getDecisionHash(SIGNED_BLOCKHEIGHT, 1)
      .toString("hex"),
    decision_hash_sigv2_h10000: res
      .getDecisionHash(SIGNED_BLOCKHEIGHT, 2)
      .toString("hex"),
  });
}

// ---------------------------------------------------------------------------
// Write it out
// ---------------------------------------------------------------------------

const out = {
  source:
    "VerusCoin/verus-typescript-primitives @ " +
    PINNED_COMMIT +
    ", generated by fixtures/tools/export-vdxf-vectors.cjs",
  note:
    "The oracle is the deployed upstream TypeScript implementation that real " +
    "wallets interoperate with. That is weaker than fixtures/transparent/, whose " +
    "expectations are backed by a daemon-signed transaction in fixtures/daemon/: " +
    "no daemon RPC validates a VerusPayInvoice or a LoginConsentRequest, because " +
    "these are wallet/application-layer formats that never enter a transaction. " +
    "Upstream's tests are pure self round-trips with no hardcoded vectors, so " +
    "these bytes were generated rather than copied. See fixtures/vdxf/README.md.",
  primitives_commit: PINNED_COMMIT,
  signed_blockheight: SIGNED_BLOCKHEIGHT,
  vectors,
};

const outPath = path.join(__dirname, "..", "vdxf", "vectors.json");
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors to ${outPath}`);
