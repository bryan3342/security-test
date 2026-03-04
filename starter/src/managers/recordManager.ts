import { buildGuidancePrompt } from "../config/promptTemplate.js";
import type { AuditLogger } from "../security/audit.js";
import { InMemoryRecordRepository } from "../storage/recordRepository.js";
import type { AppUser, HealthRecord } from "../types.js";
import type { AppLogger } from "../utils/logger.js";

export class RecordManager {
  constructor(
    private repository: InMemoryRecordRepository,
    private logger: AppLogger,
    private audit: AuditLogger,
    private guidanceTemplate: string,
  ) {}

  async getRecord(recordId: string, user: AppUser): Promise<HealthRecord> {
    const record = this.repository.getRecordById(recordId);                 // No identity context used here yet.
    if (!record) {                                                          // Only checks if the record exists, not if the user has access.
      throw new Error("record_not_found");
    }

    // Compares record stored owner against user ID
    // Second condition grants admins read access to all records
    if (record.ownerUserId !== user.userId && user.role !== "admin") {      // Simple access control: only owner or admin can access the record.
      // Throws before any logging or data is returned
      // Route layer catches all errors and returns 404, preventing information leak whether the records exists at all
      throw new Error("access_denied");
    }

    this.logger.info("record_read", { userId: user.userId, recordId: record.id });
    await this.audit.log({
      actor: user.userId,
      action: "record_read",
      targetId: recordId,
      result: "success",
      details: { recordId : record.id },
    });

    return record;
  }

  async createShareLink(recordId: string, user: AppUser): Promise<{ url: string }> {
    const record = this.repository.getRecordById(recordId);                  // No check here either
    if (!record) {                                                           // Same as above, only checks if the record exists, not if the user has access.
      throw new Error("record_not_found");
    }

    // same authentication checks made for getRecord are made here for createShareLink
    if (record.ownerUserId !== user.userId && user.role !== "admin") {       // Same access control as above, only owner or admin can create share links.
      throw new Error("access_denied");
    }

    const share = await this.repository.createShare(recordId, user.userId);
    this.logger.info("record_share_created", { userId: user.userId, recordId });

    return {
      url: `https://example.local/share/${share.token}`,
    };
  }

  async generateGuidance(
    recordId: string,
    user: AppUser,
    patientSummary: string,
  ): Promise<{ promptPreview: string }> {
    const record = this.repository.getRecordById(recordId);                   // Same issues for always fetching 
    if (!record) {                                                            // just checks existence
      throw new Error("record_not_found");
    }
    
    // same authentication checks made for getRecord are made here for createShareLink
    if (record.ownerUserId !== user.userId && user.role !== "admin") {       // Same access control as above, only owner or admin can create share links.
      throw new Error("access_denied");
    }

    const prompt = buildGuidancePrompt(this.guidanceTemplate, patientSummary);

    this.logger.info("guidance_generated", {
      userId: user.userId,
      recordId: record.id
    });

    return {
      promptPreview: prompt.slice(0, 300),
    };
  }
}
