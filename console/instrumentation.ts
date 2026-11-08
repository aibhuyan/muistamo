// Runs once when the server starts, never during the build: refuse a sign-in configuration that
// is not exactly right (lib/entra/startup.ts).
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { checkStartup } = await import("./lib/entra/startup");
  checkStartup();
}
