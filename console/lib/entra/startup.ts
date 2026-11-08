import { ConfigError, entraConfig, mode } from "./config";

// Refuse to start with a sign-in configuration that is not exactly right
// (docs/console-entra-signin-plan.md). Node.js only; called from instrumentation.ts.
export function checkStartup(): void {
  try {
    if (mode() === "entra") {
      const config = entraConfig();
      if (config.e2eMicrosoft) {
        console.warn(JSON.stringify({ level: "WARN", msg: "INSECURE: the e2e Microsoft fake is in use; test runs only" }));
      }
    }
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : "the sign-in configuration could not be read";
    console.error(JSON.stringify({ level: "FATAL", msg: "console configuration refused", error: message }));
    process.exit(1);
  }
}
