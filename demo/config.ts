// Shared demo configuration: the measurement the recorded genoa fixture actually
// reports. In production this allowlist is pinned out of band by the operator.
export const DEMO_MEASUREMENTS: string[] = [
  "d9912ba396ce409c2947841d93a5076b6839b898c22b4aae05edb3b2b058a99927f8cf9a4f8617ee695deb14795496c8",
];
export const DEMO_GENERATION = "genoa";
export const DEMO_PLATFORM = "snp";
// The recorded fixture's report_data is a fixed test string, so it cannot bind a
// live identity transcript. A real TEE LB binds the transcript hash; the demo
// therefore runs with freshness enforcement downgraded to a warning.
export const DEMO_REQUIRE_FRESHNESS = false;
