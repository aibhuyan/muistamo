import { connection } from "next/server";

import { devLoginEnabled } from "@/lib/session";

import { DecisionForm } from "../decision-form";
import { signIn } from "./actions";

export default async function SignInPage() {
  await connection();
  if (!devLoginEnabled()) {
    return (
      <>
        <h1>No authentication configured</h1>
        <p>
          This console has no sign-in configured, so it shows nothing and calls no service. Development sign-in
          is enabled with <code>MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN=true</code>.
        </p>
      </>
    );
  }
  return (
    <>
      <h1>Development sign-in</h1>
      <p className="muted">
        Insecure: you may claim any tenant and person, exactly as the services&apos; development headers allow.
        Never enable this outside development.
      </p>
      <DecisionForm action={signIn} submit="Sign in">
        <label>
          Tenant
          <input type="text" name="tenant" required placeholder="00000000-0000-4000-8000-000000000000" />
        </label>
        <label>
          Person (email)
          <input type="text" name="person" required placeholder="reviewer@example.invalid" />
        </label>
      </DecisionForm>
    </>
  );
}
