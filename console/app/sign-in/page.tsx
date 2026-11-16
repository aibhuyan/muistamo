import { connection } from "next/server";

import { entraConfig } from "@/lib/entra/config";
import { devLoginEnabled, entraEnabled } from "@/lib/session";

import { DecisionForm } from "../decision-form";
import { signIn } from "./actions";

export default async function SignInPage(props?: { searchParams?: Promise<Record<string, string>> }) {
  await connection();
  if (entraEnabled()) {
    const { tenants } = entraConfig();
    const unknown = (await props?.searchParams)?.unknown === "1";
    return (
      <div className="panel signin">
        <h1>Sign in with your work account</h1>
        <p className="muted">
          Sign in with your organisation&apos;s Microsoft account. The console acts only for current employees, as
          your organisation&apos;s HR record says.
        </p>
        {/* A POST from this page only; the customers this console serves are never listed. */}
        <form method="post" action="/auth/start" className="decision">
          {unknown ? (
            <p role="alert" className="caution">
              That organisation is not set up in this console.
            </p>
          ) : null}
          {tenants.length === 1 ? null : (
            <label className="field">
              Your organisation
              <input type="text" name="organisation" required autoComplete="organization" />
            </label>
          )}
          <button type="submit">Sign in with Microsoft</button>
        </form>
      </div>
    );
  }
  if (!devLoginEnabled()) {
    return (
      <div className="panel signin">
        <h1>No authentication configured</h1>
        <p>
          This console has no sign-in configured, so it shows nothing and calls no service. Configure Entra sign-in
          with <code>MUISTAMO_CONSOLE_TENANTS</code>; development sign-in is enabled with{" "}
          <code>MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN=true</code>.
        </p>
      </div>
    );
  }
  return (
    <div className="panel signin">
      <h1>Development sign-in</h1>
      <p className="caution">
        Insecure: you may claim any tenant and person, exactly as the services&apos; development headers allow.
        Never enable this outside development.
      </p>
      <DecisionForm action={signIn} submit="Sign in">
        <label className="field">
          Tenant
          <input type="text" name="tenant" required placeholder="00000000-0000-4000-8000-000000000000" />
        </label>
        <label className="field">
          Person (email)
          <input type="text" name="person" required placeholder="reviewer@example.invalid" />
        </label>
      </DecisionForm>
    </div>
  );
}
