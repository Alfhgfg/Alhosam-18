import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Copy,
  Laptop,
  LogOut,
  Pencil,
  RefreshCw,
  ShieldAlert,
  Smartphone,
  Store,
  Tablet,
  Trash2,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { auth } from '../firebase';
import {
  formatDiagnosticReport,
  stageLabelAr,
  type AuthUserSnapshot,
} from '../utils/authDiagnostics';
import { deviceTypeLabel } from '../utils/device';

function formatUserSnap(snap: AuthUserSnapshot | null): string {
  if (!snap) return 'لم يُفحص بعد';
  if (!snap.present) return 'null (غير مسجل)';
  return `${snap.email || snap.uid} · verified=${snap.emailVerified ? 'نعم' : 'لا'}`;
}

const AuthDiagnosticsPanel: React.FC<{ defaultOpen?: boolean }> = ({
  defaultOpen = false,
}) => {
  const {
    firebaseUser,
    profile,
    loading,
    isAdmin,
    isActiveStaff,
    isDeviceBlocked,
    authError,
    diagnostics,
    clearDiagnostics,
  } = useAuth();

  const hasAutoAlert = Boolean(
    diagnostics.lastFailure ||
      authError ||
      diagnostics.lastNullReason === 'unexpected_session_drop_to_null' ||
      diagnostics.lastNullReason === 'redirect_returned_null'
  );
  const [manualOpen, setManualOpen] = useState<boolean | null>(null);
  const [copied, setCopied] = useState(false);

  const open = manualOpen !== null ? manualOpen : defaultOpen || hasAutoAlert;
  const activeAuthCurrentUser = auth.currentUser;

  const handleCopy = async () => {
    const report = formatDiagnosticReport(diagnostics, {
      loading,
      hasContextUser: Boolean(firebaseUser),
      hasAuthCurrentUser: Boolean(activeAuthCurrentUser),
      isAdmin,
      isActiveStaff,
      isDeviceBlocked,
      profileRole: profile?.role ?? null,
      profileStatus: profile?.status ?? null,
    });
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // ignore clipboard errors on restricted contexts
    }
  };

  return (
    <div className="border border-slate-200 rounded-xl bg-slate-50/90 text-right overflow-hidden">
      <button
        type="button"
        onClick={() => setManualOpen(!open)}
        className="w-full px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs font-semibold text-slate-700 hover:bg-slate-100/80 transition-colors cursor-pointer"
      >
        <span className="inline-flex items-center gap-2">
          <Activity
            className={`w-4 h-4 ${
              diagnostics.lastFailure ? 'text-red-600' : 'text-emerald-700'
            }`}
          />
          <span>
            شاشة تشخيص تسجيل الدخول ({diagnostics.events.length} حدث)
          </span>
          {diagnostics.lastFailure && (
            <span className="px-2 py-0.5 rounded-md bg-red-100 text-red-700 font-mono-num text-[10px]">
              {diagnostics.lastFailure.code}
            </span>
          )}
        </span>
        {open ? (
          <ChevronUp className="w-4 h-4 text-slate-500" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {open && (
        <div className="border-t border-slate-200 p-3.5 space-y-3 text-xs">
          {diagnostics.lastFailure && (
            <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 space-y-1">
              <div className="font-bold flex items-center justify-between gap-2">
                <span>
                  مرحلة الفشل: {stageLabelAr(diagnostics.lastFailure.stage)} (
                  <span className="font-mono-num" dir="ltr">
                    {diagnostics.lastFailure.stage}
                  </span>
                  )
                </span>
                <span className="font-mono-num px-1.5 py-0.5 bg-red-100 rounded text-[11px]" dir="ltr">
                  {diagnostics.lastFailure.code}
                </span>
              </div>
              <div className="leading-relaxed">{diagnostics.lastFailure.message}</div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
            <div className="bg-white border border-slate-200 rounded-lg p-2.5 space-y-1">
              <div className="text-slate-400 font-medium">Firebase currentUser (قبل)</div>
              <div className="font-mono-num text-slate-800 break-all" dir="ltr">
                {formatUserSnap(diagnostics.currentUserBefore)}
              </div>
            </div>
            <div className="bg-white border border-slate-200 rounded-lg p-2.5 space-y-1">
              <div className="text-slate-400 font-medium">Firebase currentUser (الآن / بعد)</div>
              <div className="font-mono-num text-slate-800 break-all" dir="ltr">
                {activeAuthCurrentUser
                  ? `${activeAuthCurrentUser.email || activeAuthCurrentUser.uid} · verified=${activeAuthCurrentUser.emailVerified ? 'نعم' : 'لا'}`
                  : formatUserSnap(diagnostics.currentUserAfter)}
              </div>
            </div>
            <div className="bg-white border border-slate-200 rounded-lg p-2.5 space-y-1">
              <div className="text-slate-400 font-medium">آخر حالة onAuthStateChanged</div>
              <div className="font-mono-num text-slate-800 break-all" dir="ltr">
                {formatUserSnap(diagnostics.lastAuthStateUser)}
              </div>
            </div>
            <div className="bg-white border border-slate-200 rounded-lg p-2.5 space-y-1">
              <div className="text-slate-400 font-medium">حالة التحقق والبوابة</div>
              <div className="font-mono-num text-slate-800" dir="ltr">
                {`env=${diagnostics.platform} | isAdmin=${isAdmin} | active=${isActiveStaff} | role=${profile?.role ?? 'none'}/${profile?.status ?? 'none'}`}
              </div>
              {diagnostics.lastNullReason && (
                <div className="text-amber-700 font-mono-num" dir="ltr">
                  nullReason={diagnostics.lastNullReason}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-700 text-[11px]">
                تتبع خطوات Google Sign-In والمصادقة (دون كشف أي رموز سرية)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 text-[11px] cursor-pointer"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copied ? 'تم النسخ' : 'نسخ التقرير'}</span>
                </button>
                <button
                  type="button"
                  onClick={clearDiagnostics}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white border border-slate-200 text-slate-600 hover:text-red-700 text-[11px] cursor-pointer"
                >
                  <Trash2 className="w-3 h-3" />
                  <span>مسح</span>
                </button>
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-lg max-h-52 overflow-y-auto divide-y divide-slate-100">
              {diagnostics.events.length === 0 ? (
                <div className="p-3 text-center text-slate-400 text-[11px]">
                  لم تُسجل أحداث بعد. اضغط زر الدخول لتتبع جميع المراحل.
                </div>
              ) : (
                [...diagnostics.events].reverse().map((ev) => (
                  <div key={ev.id} className="p-2.5 text-[11px] space-y-0.5">
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`font-semibold ${
                          ev.level === 'error'
                            ? 'text-red-700'
                            : ev.level === 'warn'
                            ? 'text-amber-700'
                            : ev.level === 'ok'
                            ? 'text-emerald-700'
                            : 'text-slate-700'
                        }`}
                      >
                        {stageLabelAr(ev.stage)}
                      </span>
                      <span className="font-mono-num text-[10px] text-slate-400" dir="ltr">
                        {ev.atIso.slice(11, 19)}
                      </span>
                    </div>
                    <div className="text-slate-700 leading-relaxed">{ev.summary}</div>
                    {(ev.code || ev.details) && (
                      <div className="font-mono-num text-[10px] text-slate-500 break-all" dir="ltr">
                        {ev.code ? `[${ev.code}] ` : ''}
                        {ev.details || ''}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export const LoginView: React.FC = () => {
  const {
    firebaseUser,
    profile,
    loading,
    signingIn,
    authError,
    isAdmin,
    isActiveStaff,
    isDeviceBlocked,
    deviceIdentity,
    deviceRecord,
    signInWithGoogle,
    retryProfileSync,
    logout,
    updateCurrentDeviceName,
  } = useAuth();

  const [editingDevice, setEditingDevice] = useState(false);
  const [deviceDraft, setDeviceDraft] = useState(deviceIdentity.deviceName);
  const [savingDevice, setSavingDevice] = useState(false);

  // Never fall back to the sign-in screen when a valid Firebase session exists
  const activeSessionUser = firebaseUser ?? auth.currentUser;

  const DeviceIcon =
    deviceIdentity.deviceType === 'mobile'
      ? Smartphone
      : deviceIdentity.deviceType === 'tablet'
      ? Tablet
      : Laptop;

  const handleSaveDeviceName = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deviceDraft.trim()) return;
    setSavingDevice(true);
    try {
      await updateCurrentDeviceName(deviceDraft);
      setEditingDevice(false);
    } finally {
      setSavingDevice(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[100dvh] bg-slate-50 flex items-center justify-center p-4 sm:p-6">
        <div className="bg-white border border-slate-200 rounded-xl p-8 max-w-lg w-full text-center space-y-4">
          <div className="w-10 h-10 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-slate-700 font-medium">جاري التحقق من الحساب والصلاحيات والجهاز...</p>
          <AuthDiagnosticsPanel />
        </div>
      </div>
    );
  }

  if (activeSessionUser && isDeviceBlocked) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-red-200 rounded-xl p-8 max-w-lg w-full space-y-5 text-center">
          <div className="w-12 h-12 rounded-xl bg-red-50 border border-red-200 text-red-600 flex items-center justify-center mx-auto">
            <Ban className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-900">تم حظر هذا الجهاز</h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              تم تعطيل الوصول من الجهاز{' '}
              <strong className="text-slate-900">
                {deviceRecord?.deviceName || deviceIdentity.deviceName}
              </strong>{' '}
              بواسطة مسؤول النظام. لا يمكن تنفيذ عمليات بيع أو الاطلاع على البيانات من هذا الجهاز حتى تتم إعادة تفعيله.
            </p>
            <div className="text-xs font-mono-num text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-2.5">
              معرّف الجهاز: {deviceIdentity.deviceId}
            </div>
          </div>
          <AuthDiagnosticsPanel />
          <button
            onClick={logout}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
            <span>تسجيل الخروج</span>
          </button>
        </div>
      </div>
    );
  }

  if (activeSessionUser && profile && profile.status === 'suspended') {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-slate-200 rounded-xl p-8 max-w-lg w-full space-y-5 text-center">
          <div className="w-12 h-12 rounded-xl bg-red-50 border border-red-200 text-red-600 flex items-center justify-center mx-auto">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-900">تم إيقاف هذا الحساب</h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              حسابك ({profile.email}) موقوف حالياً من قبل مسؤول النظام في بقالة الحسام. يرجى التواصل مع الإدارة لتفعيل الصلاحية.
            </p>
          </div>
          <AuthDiagnosticsPanel />
          <button
            onClick={logout}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
            <span>تسجيل الخروج</span>
          </button>
        </div>
      </div>
    );
  }

  if (activeSessionUser && profile && profile.status === 'pending') {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-slate-200 rounded-xl p-8 max-w-lg w-full space-y-5 text-center">
          <div className="w-12 h-12 rounded-xl bg-amber-50 border border-amber-200 text-amber-700 flex items-center justify-center mx-auto">
            <Clock className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-900">بانتظار تفعيل الصلاحية</h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              تم تسجيل دخولك بنجاح عبر البريد{' '}
              <span className="font-mono-num font-semibold text-slate-900" dir="ltr">
                {profile.email}
              </span>
              . حسابك الآن قيد المراجعة من قبل المسؤول الرئيسي لتحديد دورك وصلاحياتك داخل بقالة الحسام.
            </p>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-right space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">اسم هذا الجهاز ({deviceTypeLabel(deviceIdentity.deviceType)}):</span>
              {!editingDevice && (
                <button
                  type="button"
                  onClick={() => {
                    setDeviceDraft(deviceIdentity.deviceName);
                    setEditingDevice(true);
                  }}
                  className="inline-flex items-center gap-1 text-emerald-700 font-semibold hover:underline cursor-pointer"
                >
                  <Pencil className="w-3 h-3" />
                  <span>تسمية الجهاز</span>
                </button>
              )}
            </div>
            {editingDevice ? (
              <form onSubmit={handleSaveDeviceName} className="flex gap-2">
                <input
                  type="text"
                  value={deviceDraft}
                  onChange={(e) => setDeviceDraft(e.target.value)}
                  className="flex-1 px-2.5 py-1.5 text-xs border border-slate-200 rounded-lg bg-white"
                  placeholder="مثال: هاتف الكاشير 1"
                />
                <button
                  type="submit"
                  disabled={savingDevice}
                  className="px-3 py-1.5 bg-emerald-700 text-white text-xs font-semibold rounded-lg cursor-pointer"
                >
                  حفظ
                </button>
              </form>
            ) : (
              <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                <DeviceIcon className="w-4 h-4 text-slate-600" />
                <span>{deviceIdentity.deviceName}</span>
                <span className="text-slate-400">({deviceIdentity.platform})</span>
              </div>
            )}
          </div>

          <AuthDiagnosticsPanel />

          <div className="space-y-2.5">
            <button
              type="button"
              onClick={retryProfileSync}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-700 text-white text-sm font-semibold rounded-lg hover:bg-emerald-800 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              <span>تحديث حالة الصلاحية</span>
            </button>
            <button
              onClick={logout}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
              <span>تسجيل الخروج</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (activeSessionUser && !profile) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-slate-200 rounded-xl p-8 max-w-lg w-full space-y-5 text-center">
          <div className="w-12 h-12 rounded-xl bg-amber-50 border border-amber-200 text-amber-700 flex items-center justify-center mx-auto">
            <Clock className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-900">استكمال التحقق من الحساب</h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              جلسة Firebase نشطة عبر{' '}
              <span className="font-mono-num font-semibold text-slate-900" dir="ltr">
                {activeSessionUser.email || activeSessionUser.uid}
              </span>
              .
            </p>
            {authError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs text-right leading-relaxed">
                {authError}
              </div>
            )}
          </div>
          <AuthDiagnosticsPanel defaultOpen />
          <div className="space-y-2.5">
            <button
              type="button"
              onClick={retryProfileSync}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-700 text-white text-sm font-semibold rounded-lg hover:bg-emerald-800 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              <span>إعادة التحقق والمزامنة</span>
            </button>
            <button
              type="button"
              onClick={logout}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
              <span>تسجيل الخروج</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // CRITICAL GUARD: Never show the Google Sign-In form while a valid Firebase session exists!
  if (activeSessionUser) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-amber-200 rounded-xl p-8 max-w-lg w-full space-y-5 text-center">
          <div className="w-12 h-12 rounded-xl bg-amber-50 border border-amber-200 text-amber-700 flex items-center justify-center mx-auto">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-900">
              جلسة Firebase نشطة — يتعذر فتح الشاشة الرئيسية
            </h1>
            <p className="text-sm text-slate-600 leading-relaxed">
              تم تسجيل الدخول بالحساب{' '}
              <span className="font-mono-num font-semibold text-slate-900" dir="ltr">
                {activeSessionUser.email || activeSessionUser.uid}
              </span>{' '}
              ولم تُستوفَ شروط بوابة الدخول بعد (
              <span className="font-mono-num" dir="ltr">
                {`role=${profile?.role ?? 'none'}, status=${profile?.status ?? 'none'}, isAdmin=${isAdmin}, isActiveStaff=${isActiveStaff}`}
              </span>
              ). تم إبقاء جلستك نشطة دون إرجاعك لشاشة الدخول.
            </p>
            {authError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs text-right leading-relaxed">
                {authError}
              </div>
            )}
          </div>
          <AuthDiagnosticsPanel defaultOpen />
          <div className="space-y-2.5">
            <button
              type="button"
              onClick={retryProfileSync}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-700 text-white text-sm font-semibold rounded-lg hover:bg-emerald-800 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              <span>إعادة مزامنة الصلاحيات</span>
            </button>
            <button
              type="button"
              onClick={logout}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
              <span>تسجيل الخروج</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[100dvh] bg-slate-50 flex flex-col justify-center items-center p-4 sm:p-6">
      <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 md:p-10 space-y-6 sm:space-y-7">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl bg-emerald-700 text-white flex items-center justify-center shrink-0">
            <Store className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900">بقالة الحسام</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              النظام المحاسبي السحابي متعدد الأجهزة · الريال اليمني (ر.ي)
            </p>
          </div>
        </div>

        {/* Local Device Identity Box */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-700 font-semibold">
              <DeviceIcon className="w-4 h-4 text-emerald-700" />
              <span>اسم هذا الجهاز: {deviceIdentity.deviceName}</span>
            </div>
            <button
              type="button"
              onClick={() => {
                setDeviceDraft(deviceIdentity.deviceName);
                setEditingDevice((v) => !v);
              }}
              className="text-emerald-700 font-medium hover:underline cursor-pointer"
            >
              {editingDevice ? 'إلغاء' : 'تغيير الاسم'}
            </button>
          </div>
          {editingDevice && (
            <form onSubmit={handleSaveDeviceName} className="flex gap-2 pt-1">
              <input
                type="text"
                value={deviceDraft}
                onChange={(e) => setDeviceDraft(e.target.value)}
                placeholder="مثال: كمبيوتر الكاشير الرئيسي أو هاتف أحمد"
                className="flex-1 px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg"
              />
              <button
                type="submit"
                disabled={savingDevice}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-emerald-700 text-white text-xs font-semibold rounded-lg cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                <span>حفظ</span>
              </button>
            </form>
          )}
          <div className="text-[11px] text-slate-500">
            {deviceTypeLabel(deviceIdentity.deviceType)} · {deviceIdentity.platform} · سيُسجل هذا الاسم في كل عملية بيع أو حركة من هذا الجهاز
          </div>
        </div>

        <div className="border-t border-slate-100 pt-6 space-y-4">
          <div className="space-y-1.5">
            <h2 className="text-base font-semibold text-slate-900">
              تسجيل الدخول إلى النظام
            </h2>
            <p className="text-sm text-slate-600 leading-relaxed">
              سجّل الدخول بحساب Google المعتمد للمسؤول أو الموظف للوصول إلى شاشة البيع والمخزون والمزامنة اللحظية عبر جميع الأجهزة.
            </p>
          </div>

          {authError && (
            <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm leading-relaxed">
              {authError}
            </div>
          )}

          <button
            type="button"
            onClick={signInWithGoogle}
            disabled={signingIn}
            className="w-full flex items-center justify-center gap-3 px-5 py-3 bg-emerald-700 hover:bg-emerald-800 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold text-sm rounded-xl transition-colors cursor-pointer"
          >
            {signingIn ? (
              <>
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>جاري تسجيل الدخول عبر Google...</span>
              </>
            ) : (
              <>
                <svg className="w-5 h-5" viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    fill="currentColor"
                    d="M21.35 11.1h-9.17v2.73h6.51c-.33 3.81-3.5 5.44-6.5 5.44C8.36 19.27 5 16.25 5 12c0-4.1 3.2-7.27 7.2-7.27c3.09 0 4.9 1.97 4.9 1.97L19 4.72S16.56 2 12.1 2C6.42 2 2.03 6.8 2.03 12c0 5.05 4.13 10 10.22 10c5.35 0 9.25-3.67 9.25-9.09c0-1.15-.15-1.81-.15-1.81Z"
                  />
                </svg>
                <span>الدخول باستخدام حساب Google</span>
              </>
            )}
          </button>
        </div>

        <AuthDiagnosticsPanel />

        <div className="border-t border-slate-100 pt-5 grid grid-cols-3 gap-4 text-center text-xs text-slate-500">
          <div>مزامنة سحابية فورية</div>
          <div>حماية وتعدد أجهزة</div>
          <div>معالجة انقطاع النت</div>
        </div>
      </div>
    </div>
  );
};
