import { createClient, type RedisClientType } from "redis";
// Importing Node.js built in crypto module
import { randomBytes } from "node:crypto";
import type { HealthRecord } from "../types.js";

export type ShareRecord = {
  token: string;
  recordId: string;
  createdBy: string;
  createdAt: string;
};

export type ShareTokenStore = {
  saveShare: (share: ShareRecord) => Promise<void>;
  
  redeemShare: (token: string) => Promise<ShareRecord | null>;
};

export class InMemoryShareTokenStore implements ShareTokenStore {
  private shares: ShareRecord[] = [];

  async saveShare(share: ShareRecord): Promise<void> {
    this.shares.push(share);
  }

  async redeemShare(token: string): Promise<ShareRecord | null> {
    const idx = this.shares.findIndex((s) => s.token === token);
    if (idx === -1) return null;
    const [share] = this.shares.splice(idx, 1);
    return share ?? null;


  }
}

export class RedisShareTokenStore implements ShareTokenStore {
  private client: RedisClientType;
  private connected = false;

  constructor(redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379") {
    this.client = createClient({ url: redisUrl });
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected) {
      return;
    }

    await this.client.connect();
    this.connected = true;
  }

  async saveShare(share: ShareRecord): Promise<void> {
    await this.ensureConnected();
    await this.client.set(
      `share:${share.token}`, 
      JSON.stringify(share),
      { EX: 86400 }
    );
  }

  async redeemShare(token: string): Promise<ShareRecord | null> {
    await this.ensureConnected();
    const key = `share:${token}`;
    const raw = await this.client.get(key);
    if (!raw) return null;

    await this.client.del(key);
    return JSON.parse(raw) as ShareRecord;
  }
}

export class InMemoryRecordRepository {
  private records: HealthRecord[] = [
    {
      id: "rec-100",
      ownerUserId: "user-1",
      patientName: "Taylor Reed",
      dob: "1988-05-09",
      encounterSummary: "Follow-up for recurring urinary symptoms",
      notes: "Medication changed last visit. Monitor response and side effects.",
    },
    {
      id: "rec-200",
      ownerUserId: "user-2",
      patientName: "Jordan Kim",
      dob: "1979-11-30",
      encounterSummary: "Post-procedure pain and hydration concerns",
      notes: "Pain has improved but still intermittent.",
    },
  ];

  constructor(private shareStore: ShareTokenStore = new InMemoryShareTokenStore()) {}

  getRecordById(recordId: string): HealthRecord | undefined {
    return this.records.find((r) => r.id === recordId);
  }

  async createShare(recordId: string, createdBy: string): Promise<ShareRecord> {
    const token = randomBytes(32).toString("hex");
    const share: ShareRecord = {
      token,
      recordId,
      createdBy,
      createdAt: new Date().toISOString(),
    };
    await this.shareStore.saveShare(share);
    return share;
  }
}
