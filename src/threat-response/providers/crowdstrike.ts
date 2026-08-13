// Real, installed active-response provider — selected via
// THREAT_RESPONSE_PROVIDER=crowdstrike (see src/threat-response/index.ts,
// the only place that constructs it). Untested against a live CrowdStrike
// account (no credentials available to verify end to end), but it's
// ordinary Falcon API usage against two well-documented endpoints:
//
//   1. OAuth2 client-credentials token (POST /oauth2/token)
//   2. Resolve hostname -> device_id (GET /devices/queries/devices/v1)
//   3. Request network containment (POST /devices/entities/devices-actions/v2)
//
// "Contain" isolates the host from the network except for traffic to the
// Falcon cloud — it does not delete files or kill processes, and it's
// reversible (a corresponding "lift_containment" action exists in the
// Falcon console/API if this fires on a false positive).
//
// Required Falcon API scope: Hosts (read) + Hosts (write, for
// devices-actions). Scope the API client to nothing else.

import { ContainmentResult, ThreatResponseProvider } from "../provider";

export class CrowdStrikeThreatResponseProvider implements ThreatResponseProvider {
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly baseUrl: string
  ) {}

  private async getToken(): Promise<string> {
    const res = await fetch(`${this.baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret }),
    });
    if (!res.ok) throw new Error(`CrowdStrike auth failed: ${res.status}`);
    const json = (await res.json()) as { access_token: string };
    return json.access_token;
  }

  async containHost(hostIdentifier: string): Promise<ContainmentResult> {
    const token = await this.getToken();

    const filter = encodeURIComponent(`hostname:'${hostIdentifier}'`);
    const searchRes = await fetch(`${this.baseUrl}/devices/queries/devices/v1?filter=${filter}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!searchRes.ok) {
      return { success: false, message: `CrowdStrike device lookup failed: HTTP ${searchRes.status}` };
    }
    const searchJson = (await searchRes.json()) as { resources?: string[] };
    const deviceId = searchJson.resources?.[0];
    if (!deviceId) {
      return { success: false, message: `No CrowdStrike-managed device found matching hostname "${hostIdentifier}"` };
    }

    const actionRes = await fetch(`${this.baseUrl}/devices/entities/devices-actions/v2?action_name=contain`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ ids: [deviceId] }),
    });
    if (!actionRes.ok) {
      return { success: false, message: `CrowdStrike containment request failed: HTTP ${actionRes.status}` };
    }

    return { success: true, message: `Network containment requested for device ${deviceId} (${hostIdentifier}).` };
  }
}
