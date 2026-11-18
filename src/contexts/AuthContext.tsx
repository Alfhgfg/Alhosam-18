import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { SocialLogin } from '@capgo/capacitor-social-login';
import {
  getRedirectResult,
  GoogleAuthProvider,
  onAuthStateChanged,
  signInWithCredential,
  signInWithPopup,
  signInWithRedirect,
  signOut,
  type User,
} from 'firebase/auth';
import {
  collection,
  doc,
  getDoc,
  getDocFromCache,
  getDocs,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
} from 'firebase/firestore';
import {
  auth,
  BOOTSTRAP_ADMIN_EMAIL,
  db,
  GOOGLE_WEB_CLIENT_ID,
  googleProvider,
  testConnection,
} from '../firebase';
import {
  registerOrHeartbeatDevice,
  renameDeviceRecord,
  type ActorInfo,
} from '../services/accountingService';
import {
  ADMIN_PERMISSIONS,
  DEFAULT_EMPLOYEE_PERMISSIONS,
  type DeviceRecord,
  type StaffInvite,
  type UserProfile,
} from '../types';
import {
  appendAuthEvent,
  consumeRedirectPending,
  createInitialDiagnostics,
  extractErrorCode,
  hasRedirectPending,
  loadAuthDiagnostics,
  markRedirectPending,
  persistAuthDiagnostics,
  sanitizeDiagnosticText,
  snapshotFirebaseUser,
  type AuthDiagnosticState,
  type AuthTraceLevel,
  type AuthTraceStage,
} from '../utils/authDiagnostics';
import {
  getLocalDeviceIdentity,
  saveDeviceName,
  type DetectedDeviceMetadata,
} from '../utils/device';
import { truncateText } from '../utils/format';

interface AuthContextValue {
  firebaseUser: User | null;
  profile: UserProfile | null;
  loading: boolean;
  signingIn: boolean;
  authError: string | null;
  isAdmin: boolean;
  isActiveStaff: boolean;
  deviceIdentity: DetectedDeviceMetadata;
  deviceRecord: DeviceRecord | null;
  isDeviceBlocked: boolean;
  actorInfo: ActorInfo | null;
  diagnostics: AuthDiagnosticState;
  clearDiagnostics: () => void;
  signInWithGoogle: () => Promise<void>;
  retryProfileSync: () => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (perm: keyof UserProfile['permissions']) => boolean;
  updateCurrentDeviceName: (name: string) => Promise<void>;
  ensureDeviceRegistered: () => Promise<DeviceRecord | null>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const FIRESTORE_BOOTSTRAP_TIMEOUT_MS = 8000;

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`TIMEOUT:${label}`));
    }, ms);
    promise.then(
      (val) => {
        clearTimeout(timer);
        resolve(val);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

function buildFallbackBootstrapAdminProfile(user: User): UserProfile {
  return {
    id: user.uid,
    uid: user.uid,
    email: user.email || BOOTSTRAP_ADMIN_EMAIL,
    displayName: truncateText(user.displayName || user.email || 'المسؤول الرئيسي', 120),
    role: 'admin',
    status: 'active',
    permissions: ADMIN_PERMISSIONS,
    createdAt: null,
    updatedAt: null,
  };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const isNative = Capacitor.isNativePlatform();
  const [firebaseUser, setFirebaseUser] = useState<User | null>(() => auth.currentUser);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [deviceIdentity, setDeviceIdentity] = useState<DetectedDeviceMetadata>(() =>
    getLocalDeviceIdentity()
  );
  const [deviceRecord, setDeviceRecord] = useState<DeviceRecord | null>(null);
  const [diagnostics, setDiagnostics] = useState<AuthDiagnosticState>(() =>
    loadAuthDiagnostics(isNative)
  );

  const registeredSessionKeyRef = useRef<string | null>(null);
  const authSeqRef = useRef(0);
  const activeSyncUidRef = useRef<string | null>(null);
  const syncInFlightRef = useRef(false);
  const explicitLogoutRef = useRef(false);
  const hadUserBeforeRef = useRef(Boolean(auth.currentUser));
  const signInAttemptActiveRef = useRef(false);
  const redirectWasPendingRef = useRef(hasRedirectPending());
  const unsubProfileRef = useRef<(() => void) | null>(null);
  const unsubDeviceRef = useRef<(() => void) | null>(null);
  const nativeSocialInitRef = useRef<Promise<void> | null>(null);

  const logDiag = useCallback(
    (
      stage: AuthTraceStage,
      level: AuthTraceLevel,
      summary: string,
      opts?: {
        code?: string;
        details?: string;
        currentUserBefore?: User | null;
        currentUserAfter?: User | null;
        lastAuthStateUser?: User | null;
        lastNullReason?: string | null;
        failureMessage?: string;
        clearFailure?: boolean;
      }
    ) => {
      setDiagnostics((prev) => {
        let next = appendAuthEvent(prev, {
          stage,
          level,
          summary,
          code: opts?.code,
          details: opts?.details,
        });
        if (opts && 'currentUserBefore' in opts) {
          next = { ...next, currentUserBefore: snapshotFirebaseUser(opts.currentUserBefore) };
        }
        if (opts && 'currentUserAfter' in opts) {
          next = { ...next, currentUserAfter: snapshotFirebaseUser(opts.currentUserAfter) };
        }
        if (opts && 'lastAuthStateUser' in opts) {
          next = { ...next, lastAuthStateUser: snapshotFirebaseUser(opts.lastAuthStateUser) };
        }
        if (opts && 'lastNullReason' in opts) {
          next = { ...next, lastNullReason: opts.lastNullReason ?? null };
        }
        if (opts?.clearFailure) {
          next = { ...next, lastFailure: null };
        } else if (opts?.failureMessage) {
          next = {
            ...next,
            lastFailure: {
              stage,
              code: sanitizeDiagnosticText(opts.code || 'AUTH_ERROR'),
              message: sanitizeDiagnosticText(opts.failureMessage),
              rawSummary: opts.details ? sanitizeDiagnosticText(opts.details) : undefined,
              atIso: new Date().toISOString(),
            },
          };
        }
        persistAuthDiagnostics(next);
        return next;
      });
    },
    []
  );

  const clearDiagnostics = useCallback(() => {
    const fresh = createInitialDiagnostics(isNative);
    persistAuthDiagnostics(fresh);
    setDiagnostics(fresh);
  }, [isNative]);

  const ensureNativeGoogleInitialized = useCallback(async () => {
    if (!Capacitor.isNativePlatform()) return;
    if (!GOOGLE_WEB_CLIENT_ID) {
      throw new Error('MISSING_WEB_CLIENT_ID');
    }
    if (!nativeSocialInitRef.current) {
      logDiag('native_init', 'info', 'بدء تهيئة SocialLogin.initialize لمزود Google', {
        details: `hasWebClientId=${Boolean(GOOGLE_WEB_CLIENT_ID)}`,
      });
      nativeSocialInitRef.current = SocialLogin.initialize({
        google: {
          webClientId: GOOGLE_WEB_CLIENT_ID,
          mode: 'online',
          skipAuthOnlyAuthorizationAfterSignIn: true,
        },
      })
        .then(() => {
          logDiag('native_init', 'ok', 'تمت تهيئة SocialLogin لمزود Google بنجاح');
        })
        .catch((err) => {
          const code = extractErrorCode(err);
          logDiag('native_init', 'error', 'فشل تهيئة SocialLogin', {
            code,
            details: sanitizeDiagnosticText(err),
            failureMessage: 'تعذر تهيئة خدمة تسجيل دخول Google على الجهاز.',
          });
          nativeSocialInitRef.current = null;
          throw err;
        });
    }
    await nativeSocialInitRef.current;
  }, [logDiag]);

  useEffect(() => {
    testConnection();
    logDiag('mount_init', 'info', 'فحص الحالة الأولية عند تشغيل التطبيق', {
      currentUserBefore: auth.currentUser,
      details: `platform=${isNative ? 'capacitor-native' : 'web'}, redirectPending=${redirectWasPendingRef.current}`,
    });

    if (!Capacitor.isNativePlatform()) {
      const pendingRedirect = consumeRedirectPending();
      if (pendingRedirect) {
        redirectWasPendingRef.current = true;
        logDiag('web_redirect_result', 'info', 'تم رصد عودة من Google Redirect؛ جاري استلام النتيجة');
      }
      getRedirectResult(auth)
        .then((res) => {
          if (res?.user) {
            redirectWasPendingRef.current = false;
            logDiag('web_redirect_result', 'ok', `تم استلام جلسة Google Redirect للمستخدم ${res.user.email || res.user.uid}`, {
              currentUserAfter: auth.currentUser,
              clearFailure: true,
            });
          } else if (pendingRedirect) {
            const current = auth.currentUser;
            logDiag(
              'web_redirect_result',
              current ? 'warn' : 'error',
              current
                ? 'getRedirectResult أعاد null لكن currentUser موجود'
                : 'عاد المتصفح من Google Redirect لكن getRedirectResult أعاد null و currentUser = null',
              {
                code: current ? 'REDIRECT_EMPTY_WITH_SESSION' : 'REDIRECT_RETURNED_NULL',
                currentUserAfter: current,
                lastNullReason: current ? null : 'redirect_returned_null',
                failureMessage: current
                  ? undefined
                  : 'عاد المتصفح من صفحة Google دون إنشاء جلسة Firebase (قد تكون ملفات تعريف الارتباط أو تخزين الطرف الثالث محجوباً داخل الإطار/المتصفح).',
              }
            );
            if (!current) {
              setAuthError(
                'عاد التطبيق من تسجيل دخول Google دون إتمام الجلسة (getRedirectResult = null). جرّب السماح بالنوافذ المنبثقة أو فتح التطبيق في نافذة مستقلة.'
              );
            }
          }
        })
        .catch((err) => {
          redirectWasPendingRef.current = false;
          const code = extractErrorCode(err);
          const msg = sanitizeDiagnosticText(err);
          logDiag('web_redirect_result', 'error', `فشل getRedirectResult: ${msg}`, {
            code,
            currentUserAfter: auth.currentUser,
            failureMessage:
              code === 'auth/unauthorized-domain'
                ? 'النطاق غير مصرح به في إعدادات Firebase Auth.'
                : 'تعذر إتمام تسجيل الدخول عبر Google Redirect.',
          });
          if (code === 'auth/unauthorized-domain') {
            setAuthError('النطاق غير مصرح به في إعدادات Firebase Auth.');
          } else if (code && code !== 'auth/popup-closed-by-user') {
            setAuthError(`تعذر إتمام تسجيل الدخول عبر Google (${code}). يرجى المحاولة مرة أخرى.`);
          }
        });
    }
  }, [isNative, logDiag]);

  const syncUserSession = useCallback(
    async (
      rawUser: User | null,
      options?: { force?: boolean; source?: string }
    ) => {
      // Never treat session as null if Firebase Auth still holds a valid currentUser
      const user = rawUser ?? auth.currentUser;
      const source = options?.source || 'onAuthStateChanged';

      if (user && !options?.force && activeSyncUidRef.current === user.uid && syncInFlightRef.current) {
        logDiag(
          'session_sync',
          'info',
          `تجاهل إعادة مزامنة مكررة لنفس المستخدم أثناء التنفيذ (${source})`,
          { details: `uid=${user.uid}` }
        );
        return;
      }

      const seq = ++authSeqRef.current;

      if (!user) {
        if (unsubProfileRef.current) {
          unsubProfileRef.current();
          unsubProfileRef.current = null;
        }
        if (unsubDeviceRef.current) {
          unsubDeviceRef.current();
          unsubDeviceRef.current = null;
        }
        registeredSessionKeyRef.current = null;
        activeSyncUidRef.current = null;
        syncInFlightRef.current = false;

        let nullReason = 'initial_no_session';
        if (explicitLogoutRef.current) {
          nullReason = 'explicit_logout';
        } else if (hadUserBeforeRef.current) {
          nullReason = 'unexpected_session_drop_to_null';
        } else if (redirectWasPendingRef.current) {
          nullReason = 'redirect_returned_null';
        } else if (signInAttemptActiveRef.current) {
          nullReason = 'null_during_sign_in_attempt';
        }

        const droppedUnexpectedly = hadUserBeforeRef.current && !explicitLogoutRef.current;
        hadUserBeforeRef.current = false;
        explicitLogoutRef.current = false;

        setFirebaseUser(null);
        setProfile(null);
        setDeviceRecord(null);
        setLoading(false);

        logDiag(
          'on_auth_state_changed',
          droppedUnexpectedly ? 'error' : 'info',
          `استلام user=null من ${source} (السبب: ${nullReason})`,
          {
            code: droppedUnexpectedly ? 'SESSION_DROPPED_TO_NULL' : undefined,
            lastAuthStateUser: null,
            currentUserAfter: auth.currentUser,
            lastNullReason: nullReason,
            failureMessage: droppedUnexpectedly
              ? 'فقدت جلسة Firebase Auth المستخدم فجأة وعادت إلى null بعد اختيار الحساب.'
              : undefined,
          }
        );

        if (droppedUnexpectedly) {
          setAuthError(
            'تم فقدان جلسة الدخول بعد التحقق (عادت الجلسة إلى null). راجع تفاصيل التشخيص أدناه.'
          );
        }
        return;
      }

      hadUserBeforeRef.current = true;
      explicitLogoutRef.current = false;
      activeSyncUidRef.current = user.uid;
      syncInFlightRef.current = true;

      if (unsubProfileRef.current) {
        unsubProfileRef.current();
        unsubProfileRef.current = null;
      }
      if (unsubDeviceRef.current) {
        unsubDeviceRef.current();
        unsubDeviceRef.current = null;
      }
      registeredSessionKeyRef.current = null;

      setFirebaseUser(user);
      setAuthError(null);

      const isBootstrap =
        Boolean(user.email) &&
        user.email!.toLowerCase() === BOOTSTRAP_ADMIN_EMAIL.toLowerCase();

      logDiag('session_sync', 'info', `بدء مزامنة الجلسة (${source})`, {
        lastAuthStateUser: user,
        currentUserAfter: auth.currentUser ?? user,
        lastNullReason: null,
        clearFailure: true,
        details: `uid=${user.uid}, email=${user.email || 'none'}, emailVerified=${user.emailVerified}, isBootstrap=${isBootstrap}, seq=${seq}`,
      });

      if (!user.emailVerified && !isBootstrap) {
        console.warn('[AlHussamAuth] Signed-in user email is not verified:', user.email);
        logDiag('email_verify_check', 'error', 'البريد الإلكتروني للحساب غير موثق (emailVerified=false)', {
          code: 'EMAIL_NOT_VERIFIED',
          failureMessage: 'يرجى استخدام حساب بريد إلكتروني موثق (Google Verified).',
        });
        setAuthError('يرجى استخدام حساب بريد إلكتروني موثق (Google Verified).');
        setProfile(null);
        setDeviceRecord(null);
        setLoading(false);
        syncInFlightRef.current = false;
        return;
      }

      if (!user.emailVerified && isBootstrap) {
        logDiag(
          'email_verify_check',
          'warn',
          'حساب المسؤول الرئيسي مسجل بدون علم emailVerified=true؛ قد ترفض قواعد Firestore الكتابة حتى يتحقق التوكن',
          { code: 'BOOTSTRAP_EMAIL_UNVERIFIED' }
        );
      } else {
        logDiag('email_verify_check', 'ok', 'تم التحقق من حالة البريد الإلكتروني الموثق', {
          details: `isBootstrap=${isBootstrap}, emailVerified=${user.emailVerified}`,
        });
      }

      const userRef = doc(db, 'users', user.uid);
      const currentDev = getLocalDeviceIdentity();
      setDeviceIdentity(currentDev);

      // Attach real-time device status listener immediately (never blocks navigation)
      unsubDeviceRef.current = onSnapshot(
        doc(db, 'devices', currentDev.deviceId),
        (devSnap) => {
          if (authSeqRef.current !== seq) return;
          if (devSnap.exists()) {
            const d = {
              id: devSnap.id,
              ...(devSnap.data() as Omit<DeviceRecord, 'id'>),
            };
            setDeviceRecord(d);
            if (d.status === 'blocked') {
              logDiag('device_register', 'error', `الجهاز ${d.deviceName} محظور من الإدارة`, {
                code: 'DEVICE_BLOCKED',
                failureMessage: 'تم حظر هذا الجهاز بواسطة مسؤول النظام.',
              });
            }
            if (d.deviceName) {
              const synced = saveDeviceName(d.deviceName);
              setDeviceIdentity((prev) =>
                prev.deviceName === synced ? prev : { ...prev, deviceName: synced }
              );
            }
          } else {
            setDeviceRecord(null);
          }
        },
        (err) => {
          console.warn('[AlHussamAuth] Device listener notice:', err?.message || err);
        }
      );

      // If this is the verified bootstrap admin, grant immediate entry to the Home shell
      // and hydrate/initialize Firestore documents in the background without blocking UI.
      if (isBootstrap) {
        logDiag('bootstrap_admin', 'ok', 'تطابق حساب المسؤول الرئيسي — تفعيل ملف المسؤول الافتراضي فوراً');
        setProfile((prev) =>
          prev && prev.uid === user.uid ? prev : buildFallbackBootstrapAdminProfile(user)
        );
        setLoading(false);
      } else {
        setLoading(true);
        // Try fast local cache first so returning users never wait on network
        try {
          const cachedSnap = await getDocFromCache(userRef);
          if (authSeqRef.current !== seq) {
            syncInFlightRef.current = false;
            return;
          }
          if (cachedSnap.exists()) {
            const cachedData = cachedSnap.data() as Omit<UserProfile, 'id'>;
            setProfile({ id: cachedSnap.id, ...cachedData });
            setLoading(false);
            logDiag('firestore_profile', 'ok', 'تم تحميل ملف الصلاحيات من الذاكرة المحلية (Cache)', {
              details: `role=${cachedData.role}, status=${cachedData.status}`,
            });
          }
        } catch {
          // Cache miss on fresh install — proceed to live profile sync
        }
      }

      // Attach real-time user profile listener (updates state as soon as profile exists or changes)
      unsubProfileRef.current = onSnapshot(
        userRef,
        (snap) => {
          if (authSeqRef.current !== seq) return;
          if (snap.exists()) {
            const data = snap.data() as Omit<UserProfile, 'id'>;
            // Protect bootstrap admin from ever getting downgraded into non-admin lockout silently
            if (isBootstrap && (data.role !== 'admin' || data.status !== 'active')) {
              logDiag(
                'bootstrap_admin',
                'warn',
                `مستند المسؤول في Firestore يحمل role=${data.role}, status=${data.status}؛ الإبقاء على صلاحية المسؤول الرئيسي`,
                { code: 'BOOTSTRAP_DOC_MISMATCH' }
              );
              setProfile({
                id: snap.id,
                ...data,
                role: 'admin',
                status: 'active',
                permissions: ADMIN_PERMISSIONS,
              });
            } else {
              setProfile({ id: snap.id, ...data });
            }
            setLoading(false);
          } else if (isBootstrap) {
            setProfile((prev) => prev || buildFallbackBootstrapAdminProfile(user));
            setLoading(false);
          }
        },
        (err) => {
          if (authSeqRef.current !== seq) return;
          console.error('[AlHussamAuth] User profile listener error:', err);
          const code = extractErrorCode(err);
          logDiag('firestore_profile', 'error', `خطأ مستمع ملف المستخدم: ${sanitizeDiagnosticText(err)}`, {
            code,
            failureMessage: isBootstrap
              ? undefined
              : 'تعذر مزامنة ملف الصلاحيات من قاعدة البيانات.',
          });
          if (!isBootstrap) {
            setAuthError(`تعذر مزامنة ملف الصلاحيات من قاعدة البيانات (${code}). يرجى المحاولة مرة أخرى.`);
          }
          setLoading(false);
        }
      );

      // Run Firestore user creation / bootstrap setup safely (with timeout for non-admin first login)
      try {
        const userSnap = await withTimeout(
          getDoc(userRef),
          FIRESTORE_BOOTSTRAP_TIMEOUT_MS,
          'getDoc:users'
        );
        if (authSeqRef.current !== seq) {
          syncInFlightRef.current = false;
          return;
        }

        if (!userSnap.exists()) {
          let matchedInvite: (StaffInvite & { id: string }) | null = null;
          if (!isBootstrap && user.email) {
            try {
              const lowerEmail = user.email.trim().toLowerCase();
              let inviteSnaps = await withTimeout(
                getDocs(query(collection(db, 'staff_invites'), where('email', '==', lowerEmail))),
                FIRESTORE_BOOTSTRAP_TIMEOUT_MS,
                'getDocs:staff_invites'
              );
              if (inviteSnaps.empty && lowerEmail !== user.email) {
                inviteSnaps = await withTimeout(
                  getDocs(query(collection(db, 'staff_invites'), where('email', '==', user.email))),
                  FIRESTORE_BOOTSTRAP_TIMEOUT_MS,
                  'getDocs:staff_invites_raw'
                );
              }
              const activeInv = inviteSnaps.docs.find((d) => d.data().status === 'active');
              if (activeInv) {
                matchedInvite = {
                  id: activeInv.id,
                  ...(activeInv.data() as Omit<StaffInvite, 'id'>),
                };
                logDiag('firestore_invite', 'ok', 'تم العثور على دعوة موظف فعالة', {
                  details: `role=${matchedInvite.role}`,
                });
              } else {
                logDiag('firestore_invite', 'info', 'لا توجد دعوة موظف فعالة لهذا البريد');
              }
            } catch (inviteErr) {
              console.warn('[AlHussamAuth] Staff invite lookup notice:', inviteErr);
              logDiag('firestore_invite', 'warn', `تعذر فحص الدعوات: ${sanitizeDiagnosticText(inviteErr)}`, {
                code: extractErrorCode(inviteErr),
              });
            }
          }

          if (authSeqRef.current !== seq) {
            syncInFlightRef.current = false;
            return;
          }

          const displayName = truncateText(
            matchedInvite?.name || user.displayName || user.email || 'مستخدم جديد',
            120
          );

          if (isBootstrap) {
            const adminDocPayload = {
              uid: user.uid,
              email: user.email || BOOTSTRAP_ADMIN_EMAIL,
              displayName,
              role: 'admin' as const,
              status: 'active' as const,
              permissions: ADMIN_PERMISSIONS,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            };
            await setDoc(userRef, adminDocPayload);
            await setDoc(doc(db, 'admins', user.uid), {
              uid: user.uid,
              email: user.email || BOOTSTRAP_ADMIN_EMAIL,
              createdAt: serverTimestamp(),
            });
            logDiag('bootstrap_admin', 'ok', 'تم إنشاء سجل المسؤول الرئيسي ومؤشر admins بنجاح');
          } else if (matchedInvite) {
            const staffProfile: UserProfile = {
              id: user.uid,
              uid: user.uid,
              email: user.email || '',
              displayName,
              role: matchedInvite.role,
              status: 'active',
              permissions: matchedInvite.permissions,
              inviteId: matchedInvite.id,
              createdAt: null,
              updatedAt: null,
            };
            await setDoc(userRef, {
              uid: user.uid,
              email: user.email || '',
              displayName,
              role: matchedInvite.role,
              status: 'active',
              permissions: matchedInvite.permissions,
              inviteId: matchedInvite.id,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
            if (authSeqRef.current === seq) {
              setProfile(staffProfile);
            }
            logDiag('firestore_profile', 'ok', 'تم إنشاء ملف الموظف من الدعوة بنجاح');
          } else {
            const pendingProfile: UserProfile = {
              id: user.uid,
              uid: user.uid,
              email: user.email || '',
              displayName,
              role: 'pending',
              status: 'pending',
              permissions: DEFAULT_EMPLOYEE_PERMISSIONS,
              createdAt: null,
              updatedAt: null,
            };
            await setDoc(userRef, {
              uid: user.uid,
              email: user.email || '',
              displayName,
              role: 'pending',
              status: 'pending',
              permissions: DEFAULT_EMPLOYEE_PERMISSIONS,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
            if (authSeqRef.current === seq) {
              setProfile(pendingProfile);
            }
            logDiag('firestore_profile', 'warn', 'حساب جديد مسجل بحالة بانتظار التفعيل (pending)', {
              code: 'PROFILE_PENDING_APPROVAL',
            });
          }
        } else {
          const existingData = userSnap.data() as Omit<UserProfile, 'id'>;
          if (authSeqRef.current === seq) {
            if (isBootstrap && (existingData.role !== 'admin' || existingData.status !== 'active')) {
              setProfile({
                id: userSnap.id,
                ...existingData,
                role: 'admin',
                status: 'active',
                permissions: ADMIN_PERMISSIONS,
              });
            } else {
              setProfile({ id: userSnap.id, ...existingData });
            }
          }
          logDiag('firestore_profile', 'ok', 'تم جلب ملف المستخدم من Firestore', {
            details: `role=${existingData.role}, status=${existingData.status}`,
          });

          if (isBootstrap) {
            const adminMarkerSnap = await getDoc(doc(db, 'admins', user.uid));
            if (!adminMarkerSnap.exists()) {
              await setDoc(doc(db, 'admins', user.uid), {
                uid: user.uid,
                email: user.email || BOOTSTRAP_ADMIN_EMAIL,
                createdAt: serverTimestamp(),
              });
              logDiag('bootstrap_admin', 'ok', 'تم استكمال مؤشر admins للمسؤول الرئيسي');
            }
          }
        }

        // Ensure default store settings and counters exist when bootstrap admin signs in
        if (isBootstrap) {
          try {
            const settingsRef = doc(db, 'settings', 'store');
            const settingsSnap = await getDoc(settingsRef);
            if (!settingsSnap.exists()) {
              await setDoc(settingsRef, {
                storeName: 'بقالة الحسام',
                phone: '',
                address: '',
                currency: 'ر.ي',
                receiptFooter: 'شكراً لتعاملكم مع بقالة الحسام',
                updatedAt: serverTimestamp(),
              });
            } else if (settingsSnap.data().currency === 'ر.س') {
              await updateDoc(settingsRef, {
                currency: 'ر.ي',
                updatedAt: serverTimestamp(),
              });
            }
            const countersRef = doc(db, 'counters', 'main');
            const countersSnap = await getDoc(countersRef);
            if (!countersSnap.exists()) {
              await setDoc(countersRef, {
                nextProductSeq: 1001,
                nextCustomerSeq: 1001,
                nextSupplierSeq: 1001,
                nextInvoiceSeq: 1,
                nextPurchaseSeq: 1,
                nextReturnSeq: 1,
                nextVoucherSeq: 1,
                cashBalance: 0,
                updatedAt: serverTimestamp(),
              });
            }
          } catch (seedErr) {
            console.warn('[AlHussamAuth] Default settings/counters seed notice:', seedErr);
            logDiag('bootstrap_admin', 'warn', `تنبيه تهيئة الإعدادات الافتراضية: ${sanitizeDiagnosticText(seedErr)}`, {
              code: extractErrorCode(seedErr),
            });
          }
        }

        if (authSeqRef.current === seq) {
          setLoading(false);
        }
      } catch (err) {
        if (authSeqRef.current !== seq) {
          syncInFlightRef.current = false;
          return;
        }
        const code = extractErrorCode(err);
        console.error('[AlHussamAuth] Auth bootstrap error:', err);
        logDiag('firestore_profile', 'error', `فشل قراءة/تهيئة ملف المستخدم: ${sanitizeDiagnosticText(err)}`, {
          code,
          failureMessage: isBootstrap
            ? `تعذر مزامنة بيانات المسؤول الرئيسي في Firestore (${code})، تم الإبقاء على الجلسة النشطة.`
            : 'تم تسجيل الدخول بحساب Google، لكن تعذر الاتصال بقاعدة البيانات أو التحقق من الصلاحيات.',
        });
        if (!isBootstrap) {
          setAuthError(
            `تم تسجيل الدخول بحساب Google، لكن تعذر إتمام التحقق من قاعدة البيانات (${code}). تأكد من الاتصال بالإنترنت ثم اضغط إعادة التحقق.`
          );
        }
        setLoading(false);
      } finally {
        if (authSeqRef.current === seq) {
          syncInFlightRef.current = false;
        }
      }
    },
    [logDiag]
  );

  useEffect(() => {
    const unsubAuth = onAuthStateChanged(auth, (user) => {
      console.info(
        '[AlHussamAuth] onAuthStateChanged:',
        user ? `${user.email} (uid=${user.uid}, verified=${user.emailVerified})` : 'signed-out'
      );
      logDiag(
        'on_auth_state_changed',
        'info',
        user
          ? `استدعاء onAuthStateChanged بمستخدم: ${user.email || user.uid}`
          : `استدعاء onAuthStateChanged بـ null (auth.currentUser=${auth.currentUser ? 'present' : 'null'})`,
        {
          lastAuthStateUser: user,
          currentUserAfter: auth.currentUser,
          details: user
            ? `uid=${user.uid}, emailVerified=${user.emailVerified}`
            : `explicitLogout=${explicitLogoutRef.current}, hadUserBefore=${hadUserBeforeRef.current}`,
        }
      );
      void syncUserSession(user, { source: 'onAuthStateChanged' });
    });

    return () => {
      authSeqRef.current++;
      syncInFlightRef.current = false;
      unsubAuth();
      if (unsubProfileRef.current) {
        unsubProfileRef.current();
        unsubProfileRef.current = null;
      }
      if (unsubDeviceRef.current) {
        unsubDeviceRef.current();
        unsubDeviceRef.current = null;
      }
    };
  }, [syncUserSession, logDiag]);

  const retryProfileSync = useCallback(async () => {
    const current = auth.currentUser || firebaseUser;
    if (!current) {
      setLoading(false);
      logDiag('session_sync', 'warn', 'إعادة المزامنة: لا توجد جلسة Firebase نشطة (currentUser=null)');
      return;
    }
    setAuthError(null);
    setLoading(true);
    await syncUserSession(current, { force: true, source: 'retryProfileSync' });
  }, [firebaseUser, logDiag, syncUserSession]);

  // Always preserve a valid Firebase session if auth.currentUser is still valid
  const activeFirebaseUser = firebaseUser ?? auth.currentUser;

  const isAdmin =
    Boolean(profile && profile.role === 'admin' && profile.status === 'active') ||
    Boolean(
      activeFirebaseUser &&
        activeFirebaseUser.email?.toLowerCase() === BOOTSTRAP_ADMIN_EMAIL.toLowerCase() &&
        (activeFirebaseUser.emailVerified || Boolean(profile?.role === 'admin'))
    );

  const isActiveStaff =
    isAdmin ||
    Boolean(
      profile &&
        profile.status === 'active' &&
        (profile.role === 'admin' || profile.role === 'employee')
    );

  const isDeviceBlocked = deviceRecord?.status === 'blocked';

  // Record final gate decision whenever access state stabilizes
  const lastGateKeyRef = useRef<string>('');
  useEffect(() => {
    const key = `${loading}|${Boolean(activeFirebaseUser)}|${activeFirebaseUser?.uid ?? 'none'}|${isAdmin}|${isActiveStaff}|${isDeviceBlocked}|${profile?.role ?? 'none'}|${profile?.status ?? 'none'}`;
    if (lastGateKeyRef.current === key) return;
    lastGateKeyRef.current = key;

    if (loading) return;

    const destination =
      activeFirebaseUser && isActiveStaff && !isDeviceBlocked ? 'MainShell' : 'LoginView';

    logDiag(
      'access_gate',
      destination === 'MainShell' ? 'ok' : activeFirebaseUser ? 'warn' : 'info',
      `قرار البوابة: ${destination}`,
      {
        currentUserAfter: auth.currentUser,
        details: `session=${Boolean(activeFirebaseUser)}, isAdmin=${isAdmin}, isActiveStaff=${isActiveStaff}, isDeviceBlocked=${isDeviceBlocked}, profile=${profile ? `${profile.role}/${profile.status}` : 'null'}`,
      }
    );
  }, [loading, activeFirebaseUser, isAdmin, isActiveStaff, isDeviceBlocked, profile, logDiag]);

  // Register/heartbeat device in the background once the user is authorized
  useEffect(() => {
    if (!activeFirebaseUser || !isActiveStaff) return;
    const roleForDev: 'admin' | 'employee' = isAdmin ? 'admin' : 'employee';
    const sessionKey = `${activeFirebaseUser.uid}:${roleForDev}`;
    if (registeredSessionKeyRef.current === sessionKey) return;
    registeredSessionKeyRef.current = sessionKey;

    const dev = getLocalDeviceIdentity();
    registerOrHeartbeatDevice({
      deviceId: dev.deviceId,
      deviceName: dev.deviceName,
      deviceType: dev.deviceType,
      platform: dev.platform,
      userId: activeFirebaseUser.uid,
      userName:
        profile?.displayName || activeFirebaseUser.displayName || activeFirebaseUser.email || 'موظف',
      userEmail: activeFirebaseUser.email || 'staff@local',
      userRole: roleForDev,
    })
      .then((reg) => {
        if (reg) {
          setDeviceRecord(reg);
          logDiag('device_register', 'ok', `تم تسجيل/تحديث الجهاز (${reg.deviceName})`, {
            details: `status=${reg.status}`,
          });
        }
      })
      .catch((err) => {
        console.warn('[AlHussamAuth] Background device registration notice:', err);
        logDiag('device_register', 'warn', `تعذر تسجيل الجهاز: ${sanitizeDiagnosticText(err)}`, {
          code: extractErrorCode(err),
        });
      });
  }, [activeFirebaseUser, isActiveStaff, isAdmin, profile?.displayName, logDiag]);

  const ensureDeviceRegistered = useCallback(async (): Promise<DeviceRecord | null> => {
    if (!activeFirebaseUser || !isActiveStaff) return null;
    const dev = getLocalDeviceIdentity();
    const roleForDev: 'admin' | 'employee' = isAdmin ? 'admin' : 'employee';
    const reg = await registerOrHeartbeatDevice({
      deviceId: dev.deviceId,
      deviceName: deviceIdentity.deviceName || dev.deviceName,
      deviceType: dev.deviceType,
      platform: dev.platform,
      userId: activeFirebaseUser.uid,
      userName:
        profile?.displayName || activeFirebaseUser.displayName || activeFirebaseUser.email || 'موظف',
      userEmail: activeFirebaseUser.email || 'staff@local',
      userRole: roleForDev,
    });
    if (reg) setDeviceRecord(reg);
    return reg;
  }, [activeFirebaseUser, isActiveStaff, isAdmin, profile?.displayName, deviceIdentity.deviceName]);

  const actorInfo = useMemo<ActorInfo | null>(() => {
    if (!activeFirebaseUser || !isActiveStaff) return null;
    return {
      uid: activeFirebaseUser.uid,
      name:
        profile?.displayName || activeFirebaseUser.displayName || activeFirebaseUser.email || 'موظف',
      role: isAdmin ? 'admin' : 'employee',
      deviceId: deviceIdentity.deviceId,
      deviceName: deviceRecord?.deviceName || deviceIdentity.deviceName,
    };
  }, [
    activeFirebaseUser,
    isActiveStaff,
    isAdmin,
    profile?.displayName,
    deviceIdentity,
    deviceRecord?.deviceName,
  ]);

  const updateCurrentDeviceName = useCallback(
    async (newName: string) => {
      const saved = saveDeviceName(newName);
      setDeviceIdentity((prev) => ({ ...prev, deviceName: saved }));
      if (actorInfo && isActiveStaff && deviceRecord) {
        await renameDeviceRecord(actorInfo, deviceIdentity.deviceId, saved, {
          isActiveStaff,
        });
      }
    },
    [actorInfo, isActiveStaff, deviceRecord, deviceIdentity.deviceId]
  );

  const signInWithGoogle = async () => {
    if (signingIn) return;
    setAuthError(null);
    setSigningIn(true);
    signInAttemptActiveRef.current = true;

    logDiag('button_click', 'info', 'ضغط المستخدم على زر الدخول بحساب Google', {
      currentUserBefore: auth.currentUser,
      clearFailure: true,
    });
    logDiag(
      'platform_detect',
      'info',
      `بيئة التشغيل: ${Capacitor.isNativePlatform() ? 'Capacitor Native (Android/iOS)' : 'Web Browser'}`,
      {
        details: `isNative=${Capacitor.isNativePlatform()}, platform=${Capacitor.getPlatform()}`,
      }
    );

    if (Capacitor.isNativePlatform()) {
      try {
        console.info('[AlHussamAuth] Initializing native SocialLogin...');
        await ensureNativeGoogleInitialized();

        logDiag('native_login', 'info', 'فتح نافذة اختيار حساب Google عبر SocialLogin.login');
        console.info('[AlHussamAuth] Opening native Google account picker...');
        const res = await SocialLogin.login({
          provider: 'google',
          options: {
            style: 'standard',
          },
        });

        const hasIdToken = Boolean(res?.result && 'idToken' in res.result && res.result.idToken);
        const hasAccessToken = Boolean(
          res?.result && 'accessToken' in res.result && res.result.accessToken?.token
        );

        console.info(
          '[AlHussamAuth] SocialLogin returned:',
          res?.result?.responseType,
          'hasIdToken=',
          hasIdToken
        );

        logDiag(
          'native_login',
          hasIdToken ? 'ok' : 'error',
          `استجابة SocialLogin.login: responseType=${res?.result?.responseType ?? 'unknown'}, hasIdToken=${hasIdToken}, hasAccessToken=${hasAccessToken}`,
          {
            code: hasIdToken ? undefined : 'MISSING_ID_TOKEN',
            failureMessage: hasIdToken
              ? undefined
              : 'لم يتم استلام رمز التحقق (ID Token) من حساب Google.',
          }
        );

        if (res.result.responseType !== 'online' || !res.result.idToken) {
          setAuthError('لم يتم استلام رمز التحقق (ID Token) من حساب Google. يرجى المحاولة مرة أخرى.');
          return;
        }

        let credential;
        try {
          credential = GoogleAuthProvider.credential(
            res.result.idToken,
            res.result.accessToken?.token ?? undefined
          );
          logDiag('credential_build', 'ok', 'تم إنشاء GoogleAuthProvider.credential بنجاح');
        } catch (credErr) {
          const credCode = extractErrorCode(credErr);
          logDiag('credential_build', 'error', `فشل إنشاء Credential: ${sanitizeDiagnosticText(credErr)}`, {
            code: credCode,
            failureMessage: 'تعذر تجهيز بيانات اعتماد Google لـ Firebase.',
          });
          setAuthError(`تعذر تجهيز بيانات اعتماد Google (${credCode}).`);
          return;
        }

        logDiag('sign_in_with_credential', 'info', 'بدء تنفيذ signInWithCredential(auth, credential)');
        try {
          const userCred = await signInWithCredential(auth, credential);
          console.info(
            '[AlHussamAuth] Firebase signInWithCredential succeeded:',
            userCred.user.email,
            'uid=',
            userCred.user.uid
          );
          logDiag(
            'sign_in_with_credential',
            'ok',
            `نجاح signInWithCredential للمستخدم ${userCred.user.email || userCred.user.uid}`,
            {
              currentUserAfter: auth.currentUser ?? userCred.user,
              details: `uid=${userCred.user.uid}, emailVerified=${userCred.user.emailVerified}`,
              clearFailure: true,
            }
          );

          setFirebaseUser(userCred.user);
          // Ensure session sync runs even if onAuthStateChanged timing races
          if (activeSyncUidRef.current !== userCred.user.uid) {
            await syncUserSession(userCred.user, { source: 'post_signInWithCredential' });
          }
        } catch (fbErr) {
          const fbCode = extractErrorCode(fbErr);
          const fbMsg = sanitizeDiagnosticText(fbErr);
          console.error('[AlHussamAuth] Firebase signInWithCredential failed:', fbCode, fbMsg, fbErr);
          logDiag(
            'sign_in_with_credential',
            'error',
            `فشل signInWithCredential: ${fbMsg}`,
            {
              code: fbCode,
              currentUserAfter: auth.currentUser,
              failureMessage:
                fbCode === 'auth/invalid-credential'
                  ? 'رفض Firebase Auth رمز الدخول (auth/invalid-credential).'
                  : fbCode === 'auth/network-request-failed'
                  ? 'تعذر الاتصال بخوادم Firebase بسبب الشبكة.'
                  : `فشل التحقق من جلسة Firebase (${fbCode}).`,
            }
          );
          if (fbCode === 'auth/invalid-credential') {
            setAuthError(
              'تم رفض رمز Google من Firebase Auth (auth/invalid-credential). تأكد من تطابق Web Client ID في الإعدادات ومشروع Firebase.'
            );
          } else if (fbCode === 'auth/network-request-failed') {
            setAuthError('تعذر الاتصال بالإنترنت لإتمام تسجيل الدخول (auth/network-request-failed).');
          } else if (fbCode === 'auth/operation-not-allowed') {
            setAuthError('مزود Google غير مفعّل في إعدادات Firebase Authentication.');
          } else {
            setAuthError(`فشل تسجيل الدخول في Firebase (${fbCode}): ${fbMsg}`);
          }
        }
      } catch (err) {
        const code = extractErrorCode(err);
        const msg = sanitizeDiagnosticText(err);
        const lower = `${code} ${msg}`.toLowerCase();
        console.error('[AlHussamAuth] Native Google sign-in error:', code, msg, err);

        const isCancelled =
          code === 'USER_CANCELLED' ||
          lower.includes('cancelled') ||
          lower.includes('canceled');

        let friendlyMsg = `تعذر إتمام تسجيل الدخول عبر Google على الهاتف (${code}): ${msg}`;
        if (isCancelled) {
          friendlyMsg =
            'تم إلغاء أو إغلاق نافذة تسجيل الدخول قبل استلام الرمز (USER_CANCELLED). إذا حدث ذلك تلقائياً بعد اختيار الحساب، راجع تقرير التشخيص أدناه.';
        } else if (
          lower.includes('developer_error') ||
          lower.includes('developer console') ||
          lower.includes('28444') ||
          lower.includes('10:') ||
          lower.includes('google cloud oauth is not configured')
        ) {
          friendlyMsg =
            'فشل التحقق من إعدادات OAuth لتطبيق Android (DEVELOPER_ERROR). تأكد من تسجيل الحزمة com.alhussam.grocery وبصمتي SHA-1 و SHA-256 في Firebase Console.';
        } else if (lower.includes('no credentials') || lower.includes('nocredential')) {
          friendlyMsg =
            'لا يوجد حساب Google مسجل أو متاح على هذا الهاتف. يرجى إضافة حساب Google في إعدادات الجهاز وتحديث خدمات Google Play.';
        } else if (lower.includes('missing_web_client_id')) {
          friendlyMsg = 'معرّف Web Client ID غير مضبوط في إعدادات Firebase.';
        } else if (lower.includes('network')) {
          friendlyMsg = 'تعذر الاتصال بالإنترنت. يرجى التحقق من الشبكة والمحاولة مرة أخرى.';
        }

        logDiag('native_login', isCancelled ? 'warn' : 'error', `فشل مسار Google على الهاتف: ${msg}`, {
          code,
          currentUserAfter: auth.currentUser,
          failureMessage: friendlyMsg,
        });
        setAuthError(friendlyMsg);
      } finally {
        signInAttemptActiveRef.current = false;
        setSigningIn(false);
      }
      return;
    }

    // Web path
    try {
      logDiag('web_popup', 'info', 'فتح نافذة تسجيل الدخول عبر signInWithPopup');
      const userCred = await signInWithPopup(auth, googleProvider);
      logDiag(
        'web_popup',
        'ok',
        `نجاح signInWithPopup للمستخدم ${userCred.user.email || userCred.user.uid}`,
        {
          currentUserAfter: auth.currentUser ?? userCred.user,
          details: `uid=${userCred.user.uid}, emailVerified=${userCred.user.emailVerified}`,
          clearFailure: true,
        }
      );
      setFirebaseUser(userCred.user);
      if (activeSyncUidRef.current !== userCred.user.uid) {
        await syncUserSession(userCred.user, { source: 'post_signInWithPopup' });
      }
    } catch (err) {
      const code = extractErrorCode(err);
      const msg = sanitizeDiagnosticText(err);
      if (code === 'auth/unauthorized-domain') {
        logDiag('web_popup', 'error', 'النطاق غير مصرح به في Firebase Auth', {
          code,
          currentUserAfter: auth.currentUser,
          failureMessage: 'النطاق غير مصرح به في إعدادات Firebase Auth.',
        });
        setAuthError('النطاق غير مصرح به في إعدادات Firebase Auth.');
        return;
      }
      if (
        code === 'auth/popup-blocked' ||
        code === 'auth/operation-not-supported-in-this-environment'
      ) {
        logDiag('web_redirect', 'warn', `النافذة المنبثقة محجوبة (${code}) — التحويل إلى signInWithRedirect`, {
          code,
        });
        try {
          markRedirectPending();
          await signInWithRedirect(auth, googleProvider);
          return;
        } catch (redirErr) {
          consumeRedirectPending();
          const redirCode = extractErrorCode(redirErr);
          logDiag('web_redirect', 'error', `فشل signInWithRedirect: ${sanitizeDiagnosticText(redirErr)}`, {
            code: redirCode,
            currentUserAfter: auth.currentUser,
            failureMessage: 'تعذر التحويل إلى صفحة تسجيل دخول Google.',
          });
          setAuthError(`تعذر تسجيل الدخول عبر Google (${redirCode}). يرجى المحاولة مرة أخرى.`);
          return;
        }
      }
      const isPopupClosed =
        code === 'auth/popup-closed-by-user' ||
        code === 'auth/cancelled-popup-request' ||
        msg.includes('popup-closed-by-user');
      const friendly = isPopupClosed
        ? 'تم إغلاق نافذة تسجيل الدخول قبل إتمام المصادقة (popup-closed-by-user).'
        : `تعذر تسجيل الدخول عبر Google (${code}): يرجى التحقق من السماح بالنوافذ المنبثقة.`;

      logDiag('web_popup', isPopupClosed ? 'warn' : 'error', `فشل signInWithPopup: ${msg}`, {
        code,
        currentUserAfter: auth.currentUser,
        failureMessage: friendly,
      });
      setAuthError(friendly);
    } finally {
      signInAttemptActiveRef.current = false;
      setSigningIn(false);
    }
  };

  const logout = async () => {
    explicitLogoutRef.current = true;
    logDiag('logout', 'info', 'تسجيل خروج صريح من المستخدم', {
      currentUserBefore: auth.currentUser,
      clearFailure: true,
    });
    if (Capacitor.isNativePlatform()) {
      await SocialLogin.logout({ provider: 'google' }).catch(() => {});
    }
    await signOut(auth);
  };

  const hasPermission = (perm: keyof UserProfile['permissions']): boolean => {
    if (isAdmin) return true;
    if (!isActiveStaff || !profile) return false;
    return Boolean(profile.permissions?.[perm]);
  };

  return (
    <AuthContext.Provider
      value={{
        firebaseUser: activeFirebaseUser,
        profile,
        loading,
        signingIn,
        authError,
        isAdmin,
        isActiveStaff,
        deviceIdentity,
        deviceRecord,
        isDeviceBlocked,
        actorInfo,
        diagnostics,
        clearDiagnostics,
        signInWithGoogle,
        retryProfileSync,
        logout,
        hasPermission,
        updateCurrentDeviceName,
        ensureDeviceRegistered,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
