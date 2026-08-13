// Vercel serverless entry point. Vercel's Node runtime accepts an Express
// app exported directly (it wraps it as a request handler) — everything
// else about the app (routes, middleware, error handling) is unchanged from
// local dev.
//
// Single combined deployment: this project now serves both the API and the
// built frontend from one origin (see vercel.json — /api/(.*) rewrites here,
// everything else serves the frontend's static build with SPA fallback).
// createApp()'s own routes are deliberately unprefixed (e.g. "/clients",
// not "/api/clients") so local dev — where the Vite proxy forwards
// "/api/*" to this same app — and every existing test that hits routes
// directly both keep working unchanged. Mounting under "/api" here, once,
// is what makes the deployed origin's URLs match: Express strips the
// mount prefix before its own router sees the request, so "/api/clients"
// arrives at createApp() as "/clients", same as it always has.
import express from "express";
import { createApp } from "../src/app";

const root = express();
root.use("/api", createApp());
export default root;
