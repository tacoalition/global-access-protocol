import { createHash } from "node:crypto";

/**
 * Closed ISO 3166-1 alpha-3 -> numeric table used to derive credential attrs[0].
 *
 * Stored as one packed literal (6 chars per entry: 3 alpha + 3 digits) so the
 * whole closed set stays inside the 300-line file budget. The table is a
 * REVIEWED artifact: `COUNTRY_TABLE_REVISION` is signed into the provider
 * attestation (slot 13) and `countryTableDigest()` is pinned in IK config, so a
 * provider cannot sign "GBR" under a table where GBR meant something else.
 *
 * There is deliberately NO unknown/sentinel value. An alpha-3 outside this set
 * is a refusal, never a numeric that merely fails to equal 840.
 */
export const COUNTRY_TABLE_REVISION = 1;

const PACKED = [
  "ABW533AFG004AGO024AIA660ALA248ALB008AND020ARE784ARG032ARM051ASM016ATA010",
  "ATF260ATG028AUS036AUT040AZE031BDI108BEL056BEN204BES535BFA854BGD050BGR100",
  "BHR048BHS044BIH070BLM652BLR112BLZ084BMU060BOL068BRA076BRB052BRN096BTN064",
  "BVT074BWA072CAF140CAN124CCK166CHE756CHL152CHN156CIV384CMR120COD180COG178",
  "COK184COL170COM174CPV132CRI188CUB192CUW531CXR162CYM136CYP196CZE203DEU276",
  "DJI262DMA212DNK208DOM214DZA012ECU218EGY818ERI232ESH732ESP724EST233ETH231",
  "FIN246FJI242FLK238FRA250FRO234FSM583GAB266GBR826GEO268GGY831GHA288GIB292",
  "GIN324GLP312GMB270GNB624GNQ226GRC300GRD308GRL304GTM320GUF254GUM316GUY328",
  "HKG344HMD334HND340HRV191HTI332HUN348IDN360IMN833IND356IOT086IRL372IRN364",
  "IRQ368ISL352ISR376ITA380JAM388JEY832JOR400JPN392KAZ398KEN404KGZ417KHM116",
  "KIR296KNA659KOR410KWT414LAO418LBN422LBR430LBY434LCA662LIE438LKA144LSO426",
  "LTU440LUX442LVA428MAC446MAF663MAR504MCO492MDA498MDG450MDV462MEX484MHL584",
  "MKD807MLI466MLT470MMR104MNE499MNG496MNP580MOZ508MRT478MSR500MTQ474MUS480",
  "MWI454MYS458MYT175NAM516NCL540NER562NFK574NGA566NIC558NIU570NLD528NOR578",
  "NPL524NRU520NZL554OMN512PAK586PAN591PCN612PER604PHL608PLW585PNG598POL616",
  "PRI630PRK408PRT620PRY600PSE275PYF258QAT634REU638ROU642RUS643RWA646SAU682",
  "SDN729SEN686SGP702SGS239SHN654SJM744SLB090SLE694SLV222SMR674SOM706SPM666",
  "SRB688SSD728STP678SUR740SVK703SVN705SWE752SWZ748SXM534SYC690SYR760TCA796",
  "TCD148TGO768THA764TJK762TKL772TKM795TLS626TON776TTO780TUN788TUR792TUV798",
  "TWN158TZA834UGA800UKR804UMI581URY858USA840UZB860VAT336VCT670VEN862VGB092",
  "VIR850VNM704VUT548WLF876WSM882YEM887ZAF710ZMB894ZWE716",
].join("");

function buildTable(): ReadonlyMap<string, bigint> {
  if (PACKED.length % 6 !== 0) throw new Error("country table is malformed");
  const table = new Map<string, bigint>();
  for (let offset = 0; offset < PACKED.length; offset += 6) {
    const alpha3 = PACKED.slice(offset, offset + 3);
    const numeric = PACKED.slice(offset + 3, offset + 6);
    if (!/^[A-Z]{3}$/.test(alpha3) || !/^[0-9]{3}$/.test(numeric)) {
      throw new Error(`country table entry ${alpha3} is malformed`);
    }
    if (table.has(alpha3)) throw new Error(`country table entry ${alpha3} is duplicated`);
    table.set(alpha3, BigInt(numeric));
  }
  return table;
}

export const ISO3166_ALPHA3_TO_NUMERIC = buildTable();

/** Digest of the reviewed table, pinned in IK config so drift is detectable. */
export function countryTableDigest(): `0x${string}` {
  const artifact = `${COUNTRY_TABLE_REVISION}:${PACKED}`;
  return `0x${createHash("sha256").update(artifact, "utf8").digest("hex")}`;
}

/**
 * Resolve alpha-3 to the ISO numeric used as attrs[0].
 * Fail-closed: an absent, misshapen, or unknown alpha-3 throws.
 */
export function countryNumeric(alpha3: unknown): bigint {
  if (typeof alpha3 !== "string" || !/^[A-Z]{3}$/.test(alpha3)) {
    throw new Error("residency country must be an ISO 3166-1 alpha-3 code");
  }
  const numeric = ISO3166_ALPHA3_TO_NUMERIC.get(alpha3);
  if (numeric === undefined) {
    throw new Error(`residency country ${alpha3} is not in the reviewed ISO 3166-1 table`);
  }
  return numeric;
}
