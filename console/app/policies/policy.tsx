import Link from "next/link";

import type { ActionPolicyRecord, AgentLinkEndpoint, AgentLinkRecord } from "@/lib/api";

// Shared pieces of the policy pages (D70, slice 4). Read-only.

// Release 1 does not check live agent calls or tool actions against these rules: nothing in the
// runtime asks the policy engine, and nothing is blocked. They are decided only when someone asks
// the decision API (invariant 8: never imply checking or enforcement that does not happen).
export function NotChecked() {
  return (
    <div className="notice">
      <strong>Release 1 does not check live calls or actions against these rules.</strong>
      <span>
        They are decided only when asked through the policy decision API, and nothing is blocked yet. A policy in enforce
        mode will block what it denies once the gateway enforces.
      </span>
    </div>
  );
}

// One end of a link, or the target of an action policy: a template (covering its clones), linked to
// its page, or one clone, shown by name because the console has no clone page.
export function Target({ target }: { target: AgentLinkEndpoint }) {
  if (target.template) {
    return (
      <>
        Template{" "}
        <Link href={`/templates/${encodeURIComponent(target.template)}`} className="mono">
          {target.template}
        </Link>
      </>
    );
  }
  return (
    <>
      Clone <span className="mono">{target.clone}</span>
    </>
  );
}

export const linkHref = (name: string) => `/policies/links/${encodeURIComponent(name)}`;
export const actionPolicyHref = (name: string) => `/policies/actions/${encodeURIComponent(name)}`;

// Whose access a called agent uses.
export function actFor(value: AgentLinkRecord["document"]["spec"]["actFor"]): string {
  return value === "service" ? "Itself (a service)" : "The calling person";
}

// The links from or to a template, and the action policy for it, named by the template itself.
// Those naming one of its clones are not found here: the console cannot tell a clone's template.
export function forTemplate(template: string, links: AgentLinkRecord[], policies: ActionPolicyRecord[]) {
  return {
    from: links.filter((l) => l.document.spec.from.template === template),
    to: links.filter((l) => l.document.spec.to.template === template),
    policies: policies.filter((p) => p.document.spec.appliesTo.template === template),
  };
}
