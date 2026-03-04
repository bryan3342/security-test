import { Storage } from "@google-cloud/storage";
import { randomUUID } from "node:crypto";
import type { AuditEvent } from "../types.js";

export type AuditLogger = {
  log: (event: AuditEvent) => Promise<void>;
};

function createConsoleAuditLogger(): AuditLogger {
  return {
    async log(event) {
      // Intentionally simple for the exercise.
      console.log("AUDIT", JSON.stringify(event));
    },
  };
}

function createGcsAuditLogger(): AuditLogger {
  const projectId = process.env.GCP_PROJECT_ID;
  const bucketName = process.env.GCS_AUDIT_BUCKET ?? "dev-audit-bucket";
  const storage = new Storage({ projectId });

  return {
    async log(event) {
      const objectName = `audit/${event.action}/${event.targetId}/${Date.now()}-${randomUUID()}.json`;
      try {
           await storage
             .bucket(bucketName)
             .file(objectName)
             .save(JSON.stringify(event), { contentType: "application/json" });
      } catch (err) {
         console.error(
             "AUDIT_WRITE_FAILED",
             JSON.stringify({ objectName, action: event.action, targetId: event.targetId, error: String(err) })
           );
    }
  }
}

}

export function createAuditLogger(): AuditLogger {
  if (process.env.USE_GCS_AUDIT_LOGGING === "true") {
    return createGcsAuditLogger();
  }

  return createConsoleAuditLogger();
}
