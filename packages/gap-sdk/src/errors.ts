export type GapErrorCode =
  | "STALE_WITNESS"
  | "TA_DENIED"
  | "SESSION_MISSING"
  | "SESSION_UNATTESTED"
  | "SESSION_EXPIRED"
  | "PROVIDER_HOLD"
  | "CIPHERTEXT_INVALID"
  | "ARTIFACT_MISMATCH"
  | "ENVIRONMENT_MISMATCH";

export class GapSdkError extends Error {
  constructor(
    readonly code: GapErrorCode,
    message: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "GapSdkError";
  }
}

export function publicErrorMessage(error: unknown): string {
  if (!(error instanceof GapSdkError)) return "The compliance operation could not be completed.";
  switch (error.code) {
    case "STALE_WITNESS":
      return "On-chain compliance state changed. Rebuilding the proof.";
    case "TA_DENIED":
      return "The demo transfer-agent approval is not active.";
    case "SESSION_MISSING":
      return "No holder session exists for this token.";
    case "SESSION_UNATTESTED":
      return "The holder session is awaiting monitor attestation.";
    case "SESSION_EXPIRED":
      return "The holder session expired. Generate a new proof.";
    case "PROVIDER_HOLD":
      return "Identity verification is currently on hold.";
    case "CIPHERTEXT_INVALID":
      return "The transaction monitor refused the encrypted session.";
    case "ARTIFACT_MISMATCH":
      return "The proving artifacts do not match this deployment.";
    case "ENVIRONMENT_MISMATCH":
      return "This identity and chain environment combination is not permitted.";
  }
}

