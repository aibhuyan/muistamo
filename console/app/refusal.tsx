import type { Problem } from "@/lib/api";

// The service's own words, never a console paraphrase: a refusal is an authorisation decision.
export function Refusal({ problem }: { problem: Problem }) {
  return (
    <div role="alert" className="refusal">
      <strong>
        {problem.status} {problem.title}
      </strong>
      {problem.detail ? <p>{problem.detail}</p> : null}
    </div>
  );
}
