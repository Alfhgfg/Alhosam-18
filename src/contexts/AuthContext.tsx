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
  const [firebaseUser, setFirebaseUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [deviceIdentity, setDeviceIdentity] = useState<DetectedDeviceMetadata>(() =>
    getLocalDeviceIdentity()
  );
  const [deviceRecord, setDeviceRecord] = useState<DeviceRecord | null>(null);
  const registeredSessionKeyRef = useRef<string | null>(null);
  const authSeqRef = useRef(0);
  const unsubProfileRef = useRef<(() => void) | null>(null);
  const unsubDeviceRef = useRef<(() => void) | null>(null);

  const nativeSocialInitRef = useRef<Promise<void> | null>(null);

  const ensureNativeGoogleInitialized = useCallback(async () => {
    if (!Capacitor.isNativePlatform()) return;
    if (!GOOGLE_WEB_CLIENT_ID) {
      throw new Error('MISSING_WEB_CLIENT_ID');
    }
    if (!nativeSocialInitRef.current) {
      nativeSocialInitRef.current = SocialLogin.initialize({
        google: {
          webClientId: GOOGLE_WEB_CLIENT_ID,
          mode: 'online',
          skipAuthOnlyAuthorizationAfterSignIn: true,
        },
      }).catch((err) => {
        nativeSocialInitRef.current = null;
        throw err;
      });
    }
    await nativeSocialInitRef.current;
  }, []);

  useEffect(() => {
    testConnection();
    if (!Capacitor.isNativePlatform()) {
      getRedirectResult(auth).catch((err) => {
        const code = (err as { code?: string })?.code || '';
        if (code === 'auth/unauthorized-domain') {
          setAuthError('النطاق غير مصرح به في إعدادات Firebase Auth.');
        } else if (code && code !== 'auth/popup-closed-by-user') {
          setAuthError('تعذر إتمام تسجيل الدخول عبر Google. يرجى المحاولة مرة أخرى.');
        }
      });
    }
  }, []);

  const syncUserSession = useCallback(async (user: User | null) => {
    const seq = ++authSeqRef.current;

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

    if (!user) {
      setProfile(null);
      setDeviceRecord(null);
      setLoading(false);
      return;
    }

    const isBootstrap =
      Boolean(user.email) &&
      user.email!.toLowerCase() === BOOTSTRAP_ADMIN_EMAIL.toLowerCase();

    if (!user.emailVerified && !isBootstrap) {
      console.warn('[AlHussamAuth] Signed-in user email is not verified:', user.email);
      setAuthError('يرجى استخدام حساب بريد إلكتروني موثق (Google Verified).');
      setProfile(null);
      setDeviceRecord(null);
      setLoading(false);
      return;
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
      setProfile((prev) => (prev && prev.uid === user.uid ? prev : buildFallbackBootstrapAdminProfile(user)));
      setLoading(false);
    } else {
      setLoading(true);
      // Try fast local cache first so returning users never wait on network
      try {
        const cachedSnap = await getDocFromCache(userRef);
        if (authSeqRef.current !== seq) return;
        if (cachedSnap.exists()) {
          setProfile({
            id: cachedSnap.id,
            ...(cachedSnap.data() as Omit<UserProfile, 'id'>),
          });
          setLoading(false);
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
          setProfile({ id: snap.id, ...data });
          setLoading(false);
        } else if (isBootstrap) {
          setProfile((prev) => prev || buildFallbackBootstrapAdminProfile(user));
          setLoading(false);
        }
      },
      (err) => {
        if (authSeqRef.current !== seq) return;
        console.error('[AlHussamAuth] User profile listener error:', err);
        if (!isBootstrap) {
          setAuthError('تعذر مزامنة ملف الصلاحيات من قاعدة البيانات. يرجى المحاولة مرة أخرى.');
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
      if (authSeqRef.current !== seq) return;

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
            const activeInv = inviteSnaps.docs.find(
              (d) => d.data().status === 'active'
            );
            if (activeInv) {
              matchedInvite = {
                id: activeInv.id,
                ...(activeInv.data() as Omit<StaffInvite, 'id'>),
              };
            }
          } catch (inviteErr) {
            console.warn('[AlHussamAuth] Staff invite lookup notice:', inviteErr);
          }
        }

        if (authSeqRef.current !== seq) return;

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
        }
      } else {
        const existingData = userSnap.data() as Omit<UserProfile, 'id'>;
        if (authSeqRef.current === seq) {
          setProfile({ id: userSnap.id, ...existingData });
        }

        if (isBootstrap) {
          const adminMarkerSnap = await getDoc(doc(db, 'admins', user.uid));
          if (!adminMarkerSnap.exists()) {
            await setDoc(doc(db, 'admins', user.uid), {
              uid: user.uid,
              email: user.email || BOOTSTRAP_ADMIN_EMAIL,
              createdAt: serverTimestamp(),
            });
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
        }
      }

      if (authSeqRef.current === seq) {
        setLoading(false);
      }
    } catch (err) {
      if (authSeqRef.current !== seq) return;
      console.error('[AlHussamAuth] Auth bootstrap error:', err);
      if (!isBootstrap) {
        setAuthError(
          'تم تسجيل الدخول بحساب Google، لكن تعذر الاتصال بقاعدة البيانات لإتمام التحقق. تأكد من الاتصال بالإنترنت ثم اضغط إعادة المحاولة.'
        );
      }
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const unsubAuth = onAuthStateChanged(auth, (user) => {
      console.info(
        '[AlHussamAuth] onAuthStateChanged:',
        user ? `${user.email} (uid=${user.uid}, verified=${user.emailVerified})` : 'signed-out'
      );
      void syncUserSession(user);
    });

    return () => {
      authSeqRef.current++;
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
  }, [syncUserSession]);

  const retryProfileSync = useCallback(async () => {
    const current = auth.currentUser;
    if (!current) {
      setLoading(false);
      return;
    }
    setLoading(true);
    await syncUserSession(current);
  }, [syncUserSession]);

  const isAdmin =
    Boolean(profile && profile.role === 'admin' && profile.status === 'active') ||
    Boolean(
      firebaseUser?.emailVerified &&
        firebaseUser.email?.toLowerCase() === BOOTSTRAP_ADMIN_EMAIL.toLowerCase()
    );

  const isActiveStaff =
    isAdmin ||
    Boolean(
      profile &&
        profile.status === 'active' &&
        (profile.role === 'admin' || profile.role === 'employee')
    );

  // Register/heartbeat device in the background once the user is authorized
  useEffect(() => {
    if (!firebaseUser || !isActiveStaff) return;
    const roleForDev: 'admin' | 'employee' = isAdmin ? 'admin' : 'employee';
    const sessionKey = `${firebaseUser.uid}:${roleForDev}`;
    if (registeredSessionKeyRef.current === sessionKey) return;
    registeredSessionKeyRef.current = sessionKey;

    const dev = getLocalDeviceIdentity();
    registerOrHeartbeatDevice({
      deviceId: dev.deviceId,
      deviceName: dev.deviceName,
      deviceType: dev.deviceType,
      platform: dev.platform,
      userId: firebaseUser.uid,
      userName: profile?.displayName || firebaseUser.displayName || firebaseUser.email || 'موظف',
      userEmail: firebaseUser.email || 'staff@local',
      userRole: roleForDev,
    })
      .then((reg) => {
        if (reg) setDeviceRecord(reg);
      })
      .catch((err) => {
        console.warn('[AlHussamAuth] Background device registration notice:', err);
      });
  }, [firebaseUser, isActiveStaff, isAdmin, profile?.displayName]);

  const ensureDeviceRegistered = useCallback(async (): Promise<DeviceRecord | null> => {
    if (!firebaseUser || !isActiveStaff) return null;
    const dev = getLocalDeviceIdentity();
    const roleForDev: 'admin' | 'employee' = isAdmin ? 'admin' : 'employee';
    const reg = await registerOrHeartbeatDevice({
      deviceId: dev.deviceId,
      deviceName: deviceIdentity.deviceName || dev.deviceName,
      deviceType: dev.deviceType,
      platform: dev.platform,
      userId: firebaseUser.uid,
      userName: profile?.displayName || firebaseUser.displayName || firebaseUser.email || 'موظف',
      userEmail: firebaseUser.email || 'staff@local',
      userRole: roleForDev,
    });
    if (reg) setDeviceRecord(reg);
    return reg;
  }, [firebaseUser, isActiveStaff, isAdmin, profile?.displayName, deviceIdentity.deviceName]);

  const actorInfo = useMemo<ActorInfo | null>(() => {
    if (!firebaseUser || !isActiveStaff) return null;
    return {
      uid: firebaseUser.uid,
      name: profile?.displayName || firebaseUser.displayName || firebaseUser.email || 'موظف',
      role: isAdmin ? 'admin' : 'employee',
      deviceId: deviceIdentity.deviceId,
      deviceName: deviceRecord?.deviceName || deviceIdentity.deviceName,
    };
  }, [firebaseUser, isActiveStaff, isAdmin, profile?.displayName, deviceIdentity, deviceRecord?.deviceName]);

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

    if (Capacitor.isNativePlatform()) {
      try {
        console.info('[AlHussamAuth] Initializing native SocialLogin...');
        await ensureNativeGoogleInitialized();
        console.info('[AlHussamAuth] Opening native Google account picker...');
        const res = await SocialLogin.login({
          provider: 'google',
          options: {
            style: 'standard',
          },
        });
        console.info(
          '[AlHussamAuth] SocialLogin returned:',
          res?.result?.responseType,
          'hasIdToken=',
          Boolean(res?.result && 'idToken' in res.result && res.result.idToken)
        );
        if (res.result.responseType !== 'online' || !res.result.idToken) {
          setAuthError('لم يتم استلام رمز التحقق (ID Token) من حساب Google. يرجى المحاولة مرة أخرى.');
          return;
        }
        const credential = GoogleAuthProvider.credential(
          res.result.idToken,
          res.result.accessToken?.token ?? undefined
        );
        const userCred = await signInWithCredential(auth, credential);
        console.info(
          '[AlHussamAuth] Firebase signInWithCredential succeeded:',
          userCred.user.email,
          'uid=',
          userCred.user.uid
        );
        setFirebaseUser(userCred.user);
      } catch (err) {
        const code = (err as { code?: string })?.code || '';
        const msg = err instanceof Error ? err.message : String(err);
        const lower = `${code} ${msg}`.toLowerCase();
        console.error('[AlHussamAuth] Native Google sign-in error:', code, msg, err);

        if (
          code === 'USER_CANCELLED' ||
          lower.includes('cancelled') ||
          lower.includes('canceled')
        ) {
          return;
        }
        if (
          lower.includes('developer_error') ||
          lower.includes('developer console') ||
          lower.includes('28444') ||
          lower.includes('10:') ||
          lower.includes('google cloud oauth is not configured')
        ) {
          setAuthError(
            'فشل التحقق من إعدادات OAuth لتطبيق Android (DEVELOPER_ERROR). تأكد من تسجيل الحزمة com.alhussam.grocery وبصمتي SHA-1 و SHA-256 لمفتاح التوقيع في Firebase Console ووجود ملف google-services.json المحدّث.'
          );
          return;
        }
        if (lower.includes('no credentials') || lower.includes('nocredential')) {
          setAuthError(
            'لا يوجد حساب Google مسجل أو متاح على هذا الهاتف. يرجى إضافة حساب Google في إعدادات الجهاز وتحديث خدمات Google Play.'
          );
          return;
        }
        if (code === 'auth/invalid-credential' || lower.includes('invalid-credential')) {
          setAuthError(
            'تم رفض رمز Google من Firebase Auth (invalid-credential). تأكد من تطابق Web Client ID في الإعدادات ومشروع Firebase.'
          );
          return;
        }
        if (code === 'auth/network-request-failed' || lower.includes('network')) {
          setAuthError('تعذر الاتصال بالإنترنت. يرجى التحقق من الشبكة والمحاولة مرة أخرى.');
          return;
        }
        if (lower.includes('missing_web_client_id')) {
          setAuthError('معرّف Web Client ID غير مضبوط في إعدادات Firebase.');
          return;
        }
        setAuthError(`تعذر إتمام تسجيل الدخول عبر Google على الهاتف: ${msg}`);
      } finally {
        setSigningIn(false);
      }
      return;
    }

    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      const code = (err as { code?: string })?.code || '';
      const msg = err instanceof Error ? err.message : String(err);
      if (code === 'auth/unauthorized-domain') {
        setAuthError('النطاق غير مصرح به في إعدادات Firebase Auth.');
        return;
      }
      if (
        code === 'auth/popup-blocked' ||
        code === 'auth/operation-not-supported-in-this-environment'
      ) {
        try {
          await signInWithRedirect(auth, googleProvider);
          return;
        } catch {
          setAuthError('تعذر تسجيل الدخول عبر Google. يرجى المحاولة مرة أخرى.');
          return;
        }
      }
      if (!msg.includes('popup-closed-by-user')) {
        setAuthError('تعذر تسجيل الدخول عبر Google. يرجى التحقق من السماح بالنوافذ المنبثقة.');
      }
    } finally {
      setSigningIn(false);
    }
  };

  const logout = async () => {
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

  const isDeviceBlocked = deviceRecord?.status === 'blocked';

  return (
    <AuthContext.Provider
      value={{
        firebaseUser,
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
