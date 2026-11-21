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
export type ConsoleAccess = ControlPlane["schemas"]["ConsoleAccess"];
export type AgentInstanceRecord = ControlPlane["schemas"]["AgentInstanceRecord"];
export type AgentInstancePage = ControlPlane["schemas"]["AgentInstancePage"];
export type AgentTemplateRecord = ControlPlane["schemas"]["AgentTemplateRecord"];
export type AgentTemplatePage = ControlPlane["schemas"]["AgentTemplatePage"];
export type EvidenceEvent = ControlPlane["schemas"]["EvidenceEvent"];
export type EvidenceEventPage = ControlPlane["schemas"]["EvidenceEventPage"];
export type HrReceipt = ControlPlane["schemas"]["HrReceipt"];
export type HrReceiptPage = ControlPlane["schemas"]["HrReceiptPage"];
export type PersonSummary = ControlPlane["schemas"]["PersonSummary"];

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
    if (service === "control-plane") {
      // Entra could not give a control-plane token now: never a token or its claims in the log.
      console.error(
        JSON.stringify({
          level: "ERROR",
          msg: "control-plane token unavailable",
          tenant: session.tenant,
          person: session.person,
          requestId: await consoleRequestId(),
          error: error instanceof Error ? error.name : "unknown",
        }),
      );
      return { ok: false, problem: { title: "The control plane could not be reached with your sign-in", status: 503, detail: "Try again shortly." } };
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

export const PAGE_SIZE = 50;

// The service's own paging cursor, passed back as it was given.
const page = (cursor?: string) => (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");

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

  // The management screens (D70). The control plane decides who may read them; consoleAccess
  // only tells the console which navigation links to show.
  consoleAccess: (s: Session) => call<ConsoleAccess>(s, "control-plane", "GET", "/v1/console/access"),
  instances: (s: Session, cursor?: string) =>
    call<AgentInstancePage>(s, "control-plane", "GET", `/v1/instances?limit=${PAGE_SIZE}${page(cursor)}`),
  instance: (s: Session, name: string) => call<AgentInstanceRecord>(s, "control-plane", "GET", `/v1/instances/${id(name)}`),
  templates: (s: Session, cursor?: string) =>
    call<AgentTemplatePage>(s, "control-plane", "GET", `/v1/templates?limit=${PAGE_SIZE}${page(cursor)}`),
  template: (s: Session, name: string) => call<AgentTemplateRecord>(s, "control-plane", "GET", `/v1/templates/${id(name)}`),
  // The control plane's evidence chain, in chain order, for console auditors.
  events: (s: Session, afterSeq: number, limit = PAGE_SIZE) =>
    call<EvidenceEventPage>(s, "control-plane", "GET", `/v1/events?afterSeq=${afterSeq}&limit=${limit}`),
  // People and HR events, by HR id only, for console administrators.
  hrReceipts: (s: Session, cursor?: string) =>
    call<HrReceiptPage>(s, "control-plane", "GET", `/v1/hr/receipts?limit=${PAGE_SIZE}${page(cursor)}`),
  person: (s: Session, personId: string) => call<PersonSummary>(s, "control-plane", "GET", `/v1/people/${id(personId)}`),
};
