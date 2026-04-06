/**
 * MDPersona OpenClaw Plugin
 *
 * Fetches and decrypts the user's MDPersona preference profiles into the workspace.
 * Credentials are never stored — the password is used in-memory only and zeroed
 * immediately after decryption.
 */

import { definePluginEntry } from 'openclaw/plugin-sdk/core';
import type { OpenClawPluginApi } from 'openclaw/plugin-sdk/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';

// ── Configuration ──────────────────────────────────────────────────────────────

const SUPABASE_URL =
  process.env.MDPERSONA_SUPABASE_URL ?? 'https://vjfwoxdzxryuwoqyjbce.supabase.co';
const SUPABASE_ANON_KEY =
  process.env.MDPERSONA_SUPABASE_ANON_KEY ?? 'sb_publishable_vMe9u4n9DH3aQwShGvIUtg_aQ4sauZi';

if (!SUPABASE_URL.startsWith('https://')) {
  throw new Error('MDPERSONA_SUPABASE_URL must use HTTPS');
}

// Docker container paths (OpenClaw runtime)
const WORKSPACE_DIR = '/home/node/.openclaw/workspace';
const OPENCLAW_DIR = path.join(os.homedir(), '.openclaw');

const SYNC_STATE_PATH = path.join(OPENCLAW_DIR, 'mdpersona-sync-state.json');

// Profile type → workspace file
const PROFILE_FILES: Record<string, string> = {
  reservations: path.join(WORKSPACE_DIR, 'Reservations.md'),
  media: path.join(WORKSPACE_DIR, 'Media.md'),
};

// Crypto constants — must match MDPersona web app (lib/encryption.ts) exactly
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const PBKDF2_ITERATIONS = 100_000;
const GCM_AUTH_TAG_LENGTH = 16;
const MAX_CIPHERTEXT_BYTES = 512 * 1024; // 512 KB

const FETCH_TIMEOUT_MS = 10_000;

// ── CLI input helpers ──────────────────────────────────────────────────────────

async function promptText(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.once('line', (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function promptPassword(prompt: string): Promise<Buffer> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    const chars: string[] = [];
    const onData = (char: string) => {
      if (char === '\n' || char === '\r' || char === '\u0004') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(Buffer.from(chars.join('')));
      } else if (char === '\u0003') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.exit();
      } else if (char === '\u007f') {
        if (chars.length > 0) {
          chars.pop();
          process.stdout.clearLine(0);
          process.stdout.cursorTo(0);
          process.stdout.write(prompt + '*'.repeat(chars.length));
        }
      } else {
        chars.push(char);
        process.stdout.write('*');
      }
    };
    process.stdin.on('data', onData);
  });
}

// ── MDPersona profile decryption ───────────────────────────────────────────────
//
// Ciphertext layout (base64-encoded):
//   [0  – 15]  salt       (16 bytes, PBKDF2 salt)
//   [16 – 27]  iv         (12 bytes, AES-GCM nonce)
//   [28 – end] ciphertext (N bytes) + GCM auth tag (last 16 bytes)

function decryptProfile(base64Ciphertext: string, password: Buffer): string {
  // Reject oversized payloads before allocating
  if (base64Ciphertext.length > Math.ceil(MAX_CIPHERTEXT_BYTES * 4 / 3)) {
    throw new Error('Ciphertext exceeds maximum size');
  }
  const combined = Buffer.from(base64Ciphertext, 'base64');

  const salt = combined.subarray(0, SALT_LENGTH);
  const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const encryptedWithTag = combined.subarray(SALT_LENGTH + IV_LENGTH);
  const authTag = encryptedWithTag.subarray(encryptedWithTag.length - GCM_AUTH_TAG_LENGTH);
  const ciphertext = encryptedWithTag.subarray(0, encryptedWithTag.length - GCM_AUTH_TAG_LENGTH);

  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

// ── Supabase REST API ──────────────────────────────────────────────────────────

interface SupabaseSession {
  access_token: string;
  user: { id: string };
}

interface ProfileRow {
  profile_type: string;
  encrypted_content: string;
}

async function fetchWithTimeout(url: string, options: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

async function supabaseSignIn(email: string, password: string): Promise<SupabaseSession> {
  const res = await fetchWithTimeout(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<SupabaseSession>;
}

async function fetchProfiles(accessToken: string, userId: string): Promise<ProfileRow[]> {
  const url =
    `${SUPABASE_URL}/rest/v1/profiles` +
    `?select=profile_type,encrypted_content&user_id=eq.${encodeURIComponent(userId)}`;

  const res = await fetchWithTimeout(url, {
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${accessToken}`,
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const rows = await res.json();
  if (!Array.isArray(rows)) throw new Error('Unexpected response shape');
  return rows.filter(
    (r): r is ProfileRow =>
      r !== null &&
      typeof r === 'object' &&
      typeof r.profile_type === 'string' &&
      typeof r.encrypted_content === 'string',
  );
}

// ── Sync state ─────────────────────────────────────────────────────────────────

interface SyncState {
  lastSync: string;
  profiles: string[];
}

function saveSyncState(profiles: string[]): void {
  const state: SyncState = { lastSync: new Date().toISOString(), profiles };
  fs.writeFileSync(SYNC_STATE_PATH, JSON.stringify(state, null, 2));
}

function loadSyncState(): SyncState | null {
  if (!fs.existsSync(SYNC_STATE_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(SYNC_STATE_PATH, 'utf8')) as SyncState;
  } catch {
    return null;
  }
}

// ── AGENTS.md integration ──────────────────────────────────────────────────────

const AGENTS_MD_SECTION = `
## MDPersona Profile Files
On every session start, read these files if present:
- Reservations.md — use for any booking, hotel, restaurant, transport or activity tasks
- Media.md — use for news filtering, entertainment recommendations and alert preferences
`.trimStart();

function ensureAgentsMdSection(): void {
  const agentsPath = path.join(WORKSPACE_DIR, 'AGENTS.md');
  let content: string;
  try {
    content = fs.readFileSync(agentsPath, 'utf8');
  } catch {
    return;
  }
  if (content.includes('## MDPersona Profile Files')) return;
  fs.appendFileSync(agentsPath, '\n' + AGENTS_MD_SECTION);
}

// ── Core sync logic ────────────────────────────────────────────────────────────

async function runSync(email: string, password: Buffer): Promise<string> {
  // 1. Authenticate — convert to string only for the HTTP call
  let session: SupabaseSession;
  try {
    // Note: .toString() creates a JS string that cannot be zeroed later — a known
    // V8 limitation. The Buffer is zeroed below, but this string copy and the
    // JSON.stringify body in supabaseSignIn will persist in the heap until GC.
    session = await supabaseSignIn(email, password.toString('utf8'));
  } catch {
    password.fill(0);
    return '❌ Sync failed. Check your email and password and try again.';
  }

  // 2. Fetch encrypted profiles
  let rows: ProfileRow[];
  try {
    rows = await fetchProfiles(session.access_token, session.user.id);
  } catch {
    password.fill(0);
    const state = loadSyncState();
    const note = state
      ? `Last synced profiles (${state.lastSync}) remain available.`
      : 'No previously synced profiles available.';
    return `⚠️  Could not reach MDPersona. ${note}`;
  }

  // 3. Decrypt and write each profile
  const synced: string[] = [];
  const resolvedWorkspace = path.resolve(WORKSPACE_DIR);
  for (const row of rows) {
    const destPath = PROFILE_FILES[row.profile_type];
    if (!destPath) continue;

    // Guard against path traversal
    const relative = path.relative(resolvedWorkspace, path.resolve(destPath));
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      password.fill(0);
      return '❌ Sync failed.';
    }

    let plaintext: string;
    try {
      plaintext = decryptProfile(row.encrypted_content, password);
    } catch {
      password.fill(0);
      return '❌ Could not decrypt profiles. Your password may be incorrect.';
    }

    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, plaintext, 'utf8');
    synced.push(row.profile_type);
  }

  // Zero password from memory
  password.fill(0);

  // 4. Ensure AGENTS.md references the profile files
  ensureAgentsMdSection();

  // 5. Save sync state
  saveSyncState(synced);

  if (synced.length > 0) {
    return `✅ Synced profiles: ${synced.join(', ')}.`;
  }
  return (
    '✅ Connected — no profiles found yet. ' +
    'Complete your questionnaire at mdpersona.com to load preferences.'
  );
}

// ── Plugin entry point ─────────────────────────────────────────────────────────

export default definePluginEntry({
  id: 'mdpersona',
  name: 'MDPersona',
  description: 'Sync MDPersona preference profiles into the workspace',
  register(api: OpenClawPluginApi) {
    api.registerCli((ctx) => {
      const mdpersona = ctx.program
        .command('mdpersona')
        .description('MDPersona profile management');

      // ── mdpersona sync ──────────────────────────────────────────────────────
      mdpersona
        .command('sync')
        .description('Fetch and decrypt your MDPersona profiles into the workspace')
        .option('-e, --email <email>', 'MDPersona account email')
        .action(async (options: { email?: string }) => {
          if (!process.stdin.isTTY) {
            console.error('mdpersona sync requires an interactive terminal.');
            process.exit(1);
          }
          await new Promise((r) => setTimeout(r, 600));
          const email = options.email?.trim() || await promptText('Email: ');
          if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            console.error('A valid email address is required.');
            process.exit(1);
          }
          const password = await promptPassword('Password: ');
          if (!password.length) {
            console.error('Password is required.');
            process.exit(1);
          }
          const result = await runSync(email, password);
          console.log(result);
        });

      // ── mdpersona status ────────────────────────────────────────────────────
      mdpersona
        .command('status')
        .description('Show last sync time and loaded profiles')
        .action(() => {
          const state = loadSyncState();
          if (!state) {
            console.log('MDPersona: not yet synced. Run: openclaw mdpersona sync');
            return;
          }
          const profileList = state.profiles.map((p) => `  • ${p}`).join('\n');
          console.log(
            `MDPersona status:\n` +
            `  • Last sync: ${state.lastSync}\n` +
            `  • Profiles:\n${profileList}`,
          );
        });

      // ── mdpersona uninstall ─────────────────────────────────────────────────
      mdpersona
        .command('uninstall')
        .description('Remove all MDPersona data from the workspace')
        .action(() => {
          const removed: string[] = [];

          if (fs.existsSync(SYNC_STATE_PATH)) {
            fs.unlinkSync(SYNC_STATE_PATH);
            removed.push('sync state');
          }

          for (const [type, filePath] of Object.entries(PROFILE_FILES)) {
            if (fs.existsSync(filePath)) {
              fs.unlinkSync(filePath);
              removed.push(`${type} profile`);
            }
          }

          const agentsPath = path.join(WORKSPACE_DIR, 'AGENTS.md');
          if (fs.existsSync(agentsPath)) {
            const content = fs.readFileSync(agentsPath, 'utf8');
            const cleaned = content
              .replace('\n' + AGENTS_MD_SECTION, '')
              .replace(AGENTS_MD_SECTION, '');
            if (cleaned !== content) {
              fs.writeFileSync(agentsPath, cleaned, 'utf8');
              removed.push('AGENTS.md section');
            }
          }

          if (removed.length === 0) {
            console.log('MDPersona: nothing to clean up — already uninstalled.');
            return;
          }
          console.log(`✅ MDPersona uninstalled. Removed: ${removed.join(', ')}.`);
        });

    }, { commands: ['mdpersona'] });
  },
});
