/**
 * A minimal SMTP client: EHLO, optional STARTTLS, AUTH PLAIN, one message. Enough to send notification mail through an
 * ordinary relay without a dependency. It does not queue or retry (the notifier retries), and it only speaks UTF-8 text.
 */
import { randomUUID } from "node:crypto";
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

export interface SmtpConfig {
  host: string;
  port: number;
  /** Implicit TLS (port 465). */
  secure?: boolean;
  /** Upgrade with STARTTLS when the server offers it (default true). */
  starttls?: boolean;
  user?: string;
  pass?: string;
  from: string;
  /** Reject servers whose certificate does not verify (default true). */
  verify_tls?: boolean;
  timeout_ms?: number;
}

export interface MailMessage {
  to: string[];
  subject: string;
  text: string;
}

class Lines {
  private buf = "";
  private waiters: Array<(l: string) => void> = [];
  private queue: string[] = [];
  private error: Error | null = null;
  private rejecters: Array<(e: Error) => void> = [];
  constructor(private socket: Socket | TLSSocket) {
    this.attach(socket);
  }
  attach(s: Socket | TLSSocket) {
    this.socket = s;
    s.on("data", (d) => {
      this.buf += d.toString("utf8");
      let i: number;
      while ((i = this.buf.indexOf("\r\n")) >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 2);
        const w = this.waiters.shift();
        if (w) {
          this.rejecters.shift();
          w(line);
        } else this.queue.push(line);
      }
    });
    s.on("error", (e) => this.fail(e));
    s.on("close", () => this.fail(new Error("connection closed by the server")));
  }
  private fail(e: Error) {
    this.error = this.error ?? e;
    for (const r of this.rejecters.splice(0)) r(this.error);
    this.waiters.splice(0);
  }
  next(): Promise<string> {
    if (this.queue.length) return Promise.resolve(this.queue.shift() as string);
    if (this.error) return Promise.reject(this.error);
    return new Promise((res, rej) => {
      this.waiters.push(res);
      this.rejecters.push(rej);
    });
  }
  /** One full reply (multi-line replies end at a line whose 4th character is a space). */
  async reply(): Promise<{ code: number; lines: string[] }> {
    const lines: string[] = [];
    for (;;) {
      const l = await this.next();
      lines.push(l);
      if (l.length < 4 || l[3] === " ") return { code: Number(l.slice(0, 3)), lines };
    }
  }
}

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const asciiHeader = (s: string) => (/^[\x20-\x7e]*$/.test(s) ? s.replace(/[\r\n]/g, " ") : `=?UTF-8?B?${b64(s)}?=`);

export async function sendMail(cfg: SmtpConfig, msg: MailMessage): Promise<void> {
  if (msg.to.length === 0) throw new Error("no recipients");
  for (const a of [cfg.from, ...msg.to]) if (/[\r\n<>]/.test(a)) throw new Error("invalid address");
  const timeout = cfg.timeout_ms ?? 15_000;
  const tlsOpts = { host: cfg.host, port: cfg.port, servername: cfg.host, rejectUnauthorized: cfg.verify_tls !== false };
  const sock: Socket | TLSSocket = await new Promise((resolve, reject) => {
    const s = cfg.secure ? tlsConnect(tlsOpts) : netConnect({ host: cfg.host, port: cfg.port });
    s.setTimeout(timeout, () => {
      s.destroy(new Error(`SMTP timed out after ${timeout}ms`));
    });
    s.once(cfg.secure ? "secureConnect" : "connect", () => resolve(s));
    s.once("error", reject);
  });
  let lines = new Lines(sock);
  let current: Socket | TLSSocket = sock;
  const send = async (cmd: string, expect: number[]) => {
    current.write(cmd + "\r\n");
    const r = await lines.reply();
    if (!expect.includes(r.code)) throw new Error(`SMTP ${cmd.split(" ")[0]} failed: ${r.lines.join(" ")}`.replace(cfg.pass ?? "\u0000", "[redacted]"));
    return r;
  };
  try {
    const hello = await lines.reply();
    if (hello.code !== 220) throw new Error(`SMTP greeting failed: ${hello.lines.join(" ")}`);
    let ehlo = await send("EHLO reversi", [250]);
    if (!cfg.secure && cfg.starttls !== false && ehlo.lines.some((l) => /STARTTLS/i.test(l))) {
      await send("STARTTLS", [220]);
      const upgraded: TLSSocket = await new Promise((resolve, reject) => {
        const t = tlsConnect({ socket: current as Socket, servername: cfg.host, rejectUnauthorized: cfg.verify_tls !== false });
        t.once("secureConnect", () => resolve(t));
        t.once("error", reject);
      });
      current = upgraded;
      lines = new Lines(upgraded);
      ehlo = await send("EHLO reversi", [250]);
    }
    if (cfg.user) await send(`AUTH PLAIN ${b64(`\u0000${cfg.user}\u0000${cfg.pass ?? ""}`)}`, [235]);
    await send(`MAIL FROM:<${cfg.from}>`, [250]);
    for (const to of msg.to) await send(`RCPT TO:<${to}>`, [250, 251]);
    await send("DATA", [354]);
    const headers = [
      `From: ${cfg.from}`,
      `To: ${msg.to.join(", ")}`,
      `Subject: ${asciiHeader(msg.subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${randomUUID()}@reversi>`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: base64",
    ];
    const body = (b64(msg.text).match(/.{1,76}/g) ?? []).join("\r\n");
    current.write(`${headers.join("\r\n")}\r\n\r\n${body}\r\n.\r\n`);
    const done = await lines.reply();
    if (done.code !== 250) throw new Error(`SMTP message rejected: ${done.lines.join(" ")}`);
    current.write("QUIT\r\n");
    await Promise.race([lines.reply().catch(() => null), new Promise((r) => setTimeout(r, 1000))]); // let the server say goodbye
  } finally {
    current.destroy();
  }
}
