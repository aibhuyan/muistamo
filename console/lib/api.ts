import "server-only";

import type { components as Knowledge } from "@contracts/knowledge";
import type { components as ControlPlane } from "@contracts/muistamo";

import { headers as requestHeaders } from "next/headers";

import { NotAvailable, type Session, serviceHeaders } from "./session";

// The console's own request id (set by proxy.ts), for every log line about a service call.
async function consoleRequestId(): Promise<string | null> {
  try {
    return (await requestHeaders()).get("x-muistamo-request-id");
  } catch {
    return null;
  }
}

// Server-side calls to the services as the signed-in person. The services make every
// authorisation decision; the console only relays them, refusals included.

export type Problem = ControlPlane["schemas"]["Problem"];
export type Proposal = Knowledge["schemas"]["Proposal"];
export type ProposalDecision = Knowledge["schemas"]["ProposalDecision"];
export type LeaverReview = Knowledge["schemas"]["LeaverReview"];
export type LeaverReviewDecision = Knowledge["schemas"]["LeaverReviewDecision"];
export type PersonalEntry = Knowledge["schemas"]["PersonalEntry"];
export type CatalogueRequest = ControlPlane["schemas"]["CatalogueRequest"];
export type CatalogueDecision = ControlPlane["schemas"]["CatalogueDecision"];

export type Result<T> = { ok: true; data: T } | { ok: false; problem: Problem };

type Service = "control-plane" | "knowledge";

const BASE_URL_ENV: Record<Service, string> = {
  "control-plane": "MUISTAMO_CONTROL_PLANE_URL",
  knowledge: "MUISTAMO_KNOWLEDGE_URL",
};

function baseUrl(service: Service): string {
  const name = BASE_URL_ENV[service];
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value.replace(/\/+$/, "");
}

async function call<T>(
  session: Session,
  service: Service,
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<Result<T>> {
  let credentials: Record<string, string>;
  try {
    credentials = await serviceHeaders(session, service);
  } catch (error) {
    if (error instanceof NotAvailable) {
      // Honest coverage: say it is not set up, rather than fail as if the service were down.
      return { ok: false, problem: { title: `The ${service} service is not available with this sign-in`, status: 501, detail: error.message } };
    }
    throw error;
  }
  const headers: Record<string, string> = { ...credentials, Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const url = baseUrl(service) + path;
  const requestId = await consoleRequestId();
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      // Never follow a redirect: it would carry the person's identity headers to another origin.
      redirect: "manual",
    });
  } catch (error) {
    console.error(
      JSON.stringify({
        level: "ERROR",
        msg: "service call failed",
        service,
        method,
        path,
        tenant: session.tenant,
        person: session.person,
        requestId,
        error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      }),
    );
    return { ok: false, problem: { title: `The ${service} service is unreachable`, status: 503 } };
  }
  // 204 No Content (a delete) has no body to read.
  if (response.status === 204) return { ok: true, data: undefined as T };
  if (response.ok) return { ok: true, data: (await response.json()) as T };
  // The service's own request id ties this refusal to its log line; never a token or a body.
  console.warn(
    JSON.stringify({
      level: "WARN",
      msg: "service refused",
      service,
      method,
      path,
      status: response.status,
      tenant: session.tenant,
      person: session.person,
      requestId,
      serviceRequestId: response.headers.get("X-Request-Id"),
    }),
  );
  return { ok: false, problem: await readProblem(response) };
}

async function readProblem(response: Response): Promise<Problem> {
  try {
    const body = (await response.json()) as Partial<Problem>;
    if (typeof body.title === "string") {
      return {
        title: body.title,
        status: response.status,
        ...(typeof body.detail === "string" ? { detail: body.detail } : {}),
      };
    }
  } catch {
    // Not a problem document; fall through to the status line.
  }
  return { title: response.statusText || "Request failed", status: response.status };
}

const id = (value: string) => encodeURIComponent(value);

export const api = {
  reviewerProposals: (s: Session) =>
    call<{ items: Proposal[] }>(s, "knowledge", "GET", "/v1/knowledge/proposals?role=reviewer"),
  proposal: (s: Session, proposalId: string) =>
    call<Proposal>(s, "knowledge", "GET", `/v1/knowledge/proposals/${id(proposalId)}`),
  decideProposal: (s: Session, proposalId: string, decision: ProposalDecision) =>
    call<Proposal>(s, "knowledge", "POST", `/v1/knowledge/proposals/${id(proposalId)}/decision`, decision),

  leaverReviews: (s: Session) =>
    call<{ items: LeaverReview[] }>(s, "knowledge", "GET", "/v1/knowledge/leaver-reviews"),
  leaverReview: (s: Session, reviewId: string) =>
    call<LeaverReview>(s, "knowledge", "GET", `/v1/knowledge/leaver-reviews/${id(reviewId)}`),
  decideLeaverReview: (s: Session, reviewId: string, decision: LeaverReviewDecision) =>
    call<LeaverReview>(s, "knowledge", "POST", `/v1/knowledge/leaver-reviews/${id(reviewId)}/decision`, decision),

  // The signed-in person's own personal layer (D59): only they see it, private entries included.
  personalEntries: (s: Session) =>
    call<{ items: PersonalEntry[] }>(s, "knowledge", "GET", "/v1/knowledge/personal/entries"),
  setEntryVisibility: (s: Session, entryId: string, makePrivate: boolean) =>
    call<PersonalEntry>(s, "knowledge", "PATCH", `/v1/knowledge/personal/entries/${id(entryId)}`, {
      private: makePrivate,
    }),
  deleteEntry: (s: Session, entryId: string) =>
    call<undefined>(s, "knowledge", "DELETE", `/v1/knowledge/personal/entries/${id(entryId)}`),

  pendingCatalogueRequests: (s: Session) =>
    call<{ items: CatalogueRequest[] }>(s, "control-plane", "GET", "/v1/catalogue/requests?state=pending"),
  decideCatalogueRequest: (s: Session, requestId: string, decision: CatalogueDecision) =>
    call<CatalogueRequest>(s, "control-plane", "POST", `/v1/catalogue/requests/${id(requestId)}/decision`, decision),
};
