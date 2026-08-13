// Vercel serverless entry point. Vercel's Node runtime accepts an Express
// app exported directly (it wraps it as a request handler) — everything
// else about the app (routes, middleware, error handling) is unchanged from
// local dev. See vercel.json for the catch-all rewrite that sends every
// path here, since the app's own routes aren't prefixed with "/api".
import { createApp } from "../src/app";

export default createApp();
