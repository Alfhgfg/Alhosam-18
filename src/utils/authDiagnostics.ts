import type { User } from 'firebase/auth';

export type AuthTraceLevel = 'info' | 'ok' | 'warn' | 'error';

export type AuthTraceStage =
  | 'mount_init'
  | 'button_click'
  | 'platform_detect'
  | 'native_init'
  | 'native_login'
  | 'credential_build'
  | 'sign_in_with_credential'
  | 'web_redirect_result'
  | 'web_popup'
  | 'web_redirect'
  | 'on_auth_state_changed'
  | 'session_sync'
  | 'email_verify_check'
  | 'firestore_profile'
  | 'firestore_invite'
  | 'bootstrap_admin'
  | 'device_register'
  | 'access_gate'
  | 'logout';

export interface AuthUserSnapshot {
  present: boolean;
  uid: string | null;
  email: string | null;
  emailVerified: boolean | null;
  providerIds: string[];
}

export interface AuthTraceEvent {
  id: string;
  atIso: string;
  stage: AuthTraceStage;
  level: AuthTraceLevel;
  summary: string;
  code?: string;
  details?: string;
}

export interface AuthFailureInfo {
  stage: AuthTraceStage;
  code: string;
  message: string;
  rawSummary?: string;
  atIso: string;
}

export interface AuthDiagnosticState {
  platform: 'capacitor-native' | 'web';
  currentUserBefore: AuthUserSnapshot | null;
  currentUserAfter: AuthUserSnapshot | null;
  lastAuthStateUser: AuthUserSnapshot | null;
  lastNullReason: string | null;
  lastFailure: AuthFailureInfo | null;
  events: AuthTraceEvent[];
}

const DIAG_STORAGE_KEY = 'alhussam_auth_diag_v1';
const REDIRECT_PENDING_KEY = 'alhussam_auth_redirect_pending_v1';
const MAX_EVENTS = 45;

export function sanitizeDiagnosticText(input: unknown): string {
  const raw = input instanceof Error ? input.message : String(input ?? '');
  if (!raw) return '';
  return raw
    // Redact JWTs (header.payload.signature)
    .replace(/eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{4,}/g, '[REDACTED_JWT]')
    // Redact Bearer / OAuth tokens
    .replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]')
    .replace(/(id_?token|access_?token|refresh_?token|oauth_?token|secret|password)\s*[:=]\s*[^\s,;}"']+/gi, '$1=[REDACTED]')
    .replace(/ya29\.[a-zA-Z0-9._-]+/g, '[REDACTED_ACCESS_TOKEN]')
    .slice(0, 400);
}

export function extractErrorCode(err: unknown): string {
  if (err && typeof err === 'object') {
    const rec = err as { code?: unknown; errorCode?: unknown; status?: unknown; name?: unknown };
    if (typeof rec.code === 'string' && rec.code.trim()) return rec.code.trim();
    if (typeof rec.code === 'number') return String(rec.code);
    if (typeof rec.errorCode === 'string' && rec.errorCode.trim()) return rec.errorCode.trim();
    if (typeof rec.status === 'number') return `HTTP_${rec.status}`;
    if (typeof rec.name === 'string' && rec.name !== 'Error') return rec.name;
  }
  const msg = err instanceof Error ? err.message : String(err ?? '');
  const firebaseMatch = msg.match(/\(([a-z-]+\/[a-z0-9-]+)\)/i);
  if (firebaseMatch?.[1]) return firebaseMatch[1];
  if (msg.includes('USER_CANCELLED')) return 'USER_CANCELLED';
  if (msg.includes('28444')) return '28444_OAUTH_CONFIG';
  if (msg.includes('10:')) return '10_DEVELOPER_ERROR';
  if (msg.includes('[16]') || msg.includes('reauth failed')) return '16_REAUTH_FAILED';
  if (msg.startsWith('TIMEOUT:')) return msg.split(' ')[0];
  return 'UNKNOWN_ERROR';
}

export function snapshotFirebaseUser(user: User | null | undefined): AuthUserSnapshot {
  if (!user) {
    return {
      present: false,
      uid: null,
      email: null,
      emailVerified: null,
      providerIds: [],
    };
  }
  return {
    present: true,
    uid: user.uid,
    email: user.email || null,
    emailVerified: Boolean(user.emailVerified),
    providerIds: (user.providerData || [])
      .map((p) => p?.providerId)
      .filter((id): id is string => Boolean(id)),
  };
}

export function createInitialDiagnostics(isNative: boolean): AuthDiagnosticState {
  return {
    platform: isNative ? 'capacitor-native' : 'web',
    currentUserBefore: null,
    currentUserAfter: null,
    lastAuthStateUser: null,
    lastNullReason: null,
    lastFailure: null,
    events: [],
  };
}

export function loadAuthDiagnostics(isNative: boolean): AuthDiagnosticState {
  const base = createInitialDiagnostics(isNative);
  try {
    const raw = sessionStorage.getItem(DIAG_STORAGE_KEY);
    if (!raw) return base;
    const parsed = JSON.parse(raw) as Partial<AuthDiagnosticState>;
    return {
      ...base,
      ...parsed,
      platform: isNative ? 'capacitor-native' : 'web',
      events: Array.isArray(parsed.events) ? parsed.events.slice(-MAX_EVENTS) : [],
    };
  } catch {
    return base;
  }
}

export function persistAuthDiagnostics(state: AuthDiagnosticState): void {
  try {
    sessionStorage.setItem(DIAG_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // ignore storage quota errors
  }
}

export function appendAuthEvent(
  prev: AuthDiagnosticState,
  event: Omit<AuthTraceEvent, 'id' | 'atIso'>
): AuthDiagnosticState {
  const nextEvent: AuthTraceEvent = {
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    atIso: new Date().toISOString(),
    stage: event.stage,
    level: event.level,
    summary: sanitizeDiagnosticText(event.summary),
    ...(event.code ? { code: sanitizeDiagnosticText(event.code) } : {}),
    ...(event.details ? { details: sanitizeDiagnosticText(event.details) } : {}),
  };
  const next: AuthDiagnosticState = {
    ...prev,
    events: [...prev.events, nextEvent].slice(-MAX_EVENTS),
  };
  persistAuthDiagnostics(next);
  return next;
}

export function markRedirectPending(): void {
  try {
    sessionStorage.setItem(REDIRECT_PENDING_KEY, String(Date.now()));
  } catch {
    // ignore
  }
}

export function hasRedirectPending(): boolean {
  try {
    const raw = sessionStorage.getItem(REDIRECT_PENDING_KEY);
    if (!raw) return false;
    const ts = Number(raw);
    return Number.isFinite(ts) && Date.now() - ts < 10 * 60 * 1000;
  } catch {
    return false;
  }
}

export function consumeRedirectPending(): boolean {
  const active = hasRedirectPending();
  try {
    sessionStorage.removeItem(REDIRECT_PENDING_KEY);
  } catch {
    // ignore
  }
  return active;
}

export function stageLabelAr(stage: AuthTraceStage): string {
  switch (stage) {
    case 'mount_init':
      return 'تهيئة جلسة المصادقة';
    case 'button_click':
      return 'الضغط على زر الدخول';
    case 'platform_detect':
      return 'تحديد بيئة التشغيل';
    case 'native_init':
      return 'تهيئة SocialLogin للأندرويد';
    case 'native_login':
      return 'اختيار حساب Google (أندرويد)';
    case 'credential_build':
      return 'إنشاء بيانات اعتماد Firebase';
    case 'sign_in_with_credential':
      return 'تنفيذ signInWithCredential';
    case 'web_redirect_result':
      return 'فحص عودة Google Redirect';
    case 'web_popup':
      return 'نافذة تسجيل دخول Google (ويب)';
    case 'web_redirect':
      return 'التحويل إلى صفحة Google (ويب)';
    case 'on_auth_state_changed':
      return 'تغير حالة Firebase Auth';
    case 'session_sync':
      return 'مزامنة جلسة المستخدم';
    case 'email_verify_check':
      return 'التحقق من توثيق البريد';
    case 'firestore_profile':
      return 'جلب ملف الصلاحيات من Firestore';
    case 'firestore_invite':
      return 'فحص دعوات الموظفين';
    case 'bootstrap_admin':
      return 'التحقق من المسؤول الرئيسي';
    case 'device_register':
      return 'تسجيل الجهاز وفحص الحظر';
    case 'access_gate':
      return 'بوابة الدخول إلى الشاشة الرئيسية';
    case 'logout':
      return 'تسجيل الخروج';
  }
}

export function formatDiagnosticReport(
  state: AuthDiagnosticState,
  runtimeContext: {
    loading: boolean;
    hasContextUser: boolean;
    hasAuthCurrentUser: boolean;
    isAdmin: boolean;
    isActiveStaff: boolean;
    isDeviceBlocked: boolean;
    profileRole?: string | null;
    profileStatus?: string | null;
  }
): string {
  const lines: string[] = [
    '=== تقرير تشخيص تسجيل الدخول - بقالة الحسام ===',
    `البيئة: ${state.platform}`,
    `الحالة: loading=${runtimeContext.loading}, contextUser=${runtimeContext.hasContextUser}, auth.currentUser=${runtimeContext.hasAuthCurrentUser}`,
    `الصلاحيات: isAdmin=${runtimeContext.isAdmin}, isActiveStaff=${runtimeContext.isActiveStaff}, isDeviceBlocked=${runtimeContext.isDeviceBlocked}`,
    `الملف: role=${runtimeContext.profileRole ?? 'none'}, status=${runtimeContext.profileStatus ?? 'none'}`,
    `currentUser قبل: ${state.currentUserBefore ? `${state.currentUserBefore.present} (${state.currentUserBefore.email ?? 'none'}, verified=${state.currentUserBefore.emailVerified})` : 'غير مسجل'}`,
    `currentUser بعد: ${state.currentUserAfter ? `${state.currentUserAfter.present} (${state.currentUserAfter.email ?? 'none'}, verified=${state.currentUserAfter.emailVerified})` : 'غير مسجل'}`,
    `آخر حالة onAuthStateChanged: ${state.lastAuthStateUser ? `${state.lastAuthStateUser.present} (${state.lastAuthStateUser.email ?? 'none'})` : 'لم يُستدعَ بعد'}`,
    `سبب عودة الجلسة إلى null: ${state.lastNullReason ?? 'لا يوجد'}`,
  ];

  if (state.lastFailure) {
    lines.push(
      `آخر فشل: [${state.lastFailure.stage}] code=${state.lastFailure.code} — ${state.lastFailure.message}`
    );
  }

  lines.push('--- سجل الأحداث ---');
  for (const ev of state.events) {
    const codePart = ev.code ? ` [${ev.code}]` : '';
    const detailPart = ev.details ? ` | ${ev.details}` : '';
    lines.push(`${ev.atIso} [${ev.level.toUpperCase()}] (${ev.stage})${codePart}: ${ev.summary}${detailPart}`);
  }
  return lines.join('\n');
}
