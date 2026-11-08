
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import api from "../services/api";

import type {
  AuthResponse,
  LoginData,
  LoginResponse,
  RegisterData,
  User,
  EmailOtpResendResponse,
} from "../types/auth";

type RegistrationStart = {
  registration_token: string;
  requires_email_verification: boolean;
  expires_in: number;
  message: string;
};

type EmailVerificationResult = {
  enrollment_token: string;
  email_verified: boolean;
  requires_two_factor_setup: boolean;
  available_methods: ("totp" | "email")[];
  message: string;
};

type TotpSetupResult = {
  secret: string;
  provisioning_uri: string;
  message: string;
};

type RegistrationCompleteResult = AuthResponse & {
  registration_complete: boolean;
};

type RegistrationResendResult = {
  message: string;
  expires_in: number;
};

interface AuthContextValue {
  user: User | null;
  loading: boolean;

  login: (data: LoginData) => Promise<LoginResponse>;

  verifyTwoFactor: (
    challengeToken: string,
    code: string
  ) => Promise<void>;

  resendEmailOtp: (
    challengeToken: string
  ) => Promise<EmailOtpResendResponse>;

  register: (data: RegisterData) => Promise<RegistrationStart>;

  verifyRegistrationEmail: (
    registrationToken: string,
    code: string
  ) => Promise<EmailVerificationResult>;

  resendRegistrationEmail: (
    registrationToken: string
  ) => Promise<RegistrationResendResult>;

  selectRegistrationMethod: (
    enrollmentToken: string,
    method: "totp" | "email"
  ) => Promise<void>;

  setupRegistrationTotp: (
    enrollmentToken: string
  ) => Promise<TotpSetupResult>;

  setupRegistrationEmail: (
    enrollmentToken: string
  ) => Promise<RegistrationResendResult>;

  completeRegistration: (
    enrollmentToken: string,
    code: string
  ) => Promise<void>;

  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(
  undefined
);

function bearer(token: string) {
  return {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };
}

export function AuthProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // =====================================================
  // LOGOUT
  // =====================================================

  const logout = useCallback(() => {
    sessionStorage.removeItem("idps_token");
    setUser(null);
  }, []);

  // =====================================================
  // SAVE FINAL AUTHENTICATED SESSION ONLY
  // =====================================================

  const saveAuth = useCallback((response: AuthResponse) => {
    sessionStorage.setItem(
      "idps_token",
      response.access_token
    );

    setUser(response.user);
  }, []);

  // =====================================================
  // LOGIN
  // =====================================================

  const login = useCallback(
    async (data: LoginData): Promise<LoginResponse> => {
      const response = await api.post<LoginResponse>(
        "/api/auth/login",
        data
      );

      const result = response.data;

      if ("access_token" in result) {
        saveAuth(result);
      }

      return result;
    },
    [saveAuth]
  );

  // =====================================================
  // VERIFY LOGIN 2FA
  // =====================================================

  const verifyTwoFactor = useCallback(
    async (challengeToken: string, code: string) => {
      const response = await api.post<AuthResponse>(
        "/api/auth/verify-2fa",
        { code },
        bearer(challengeToken)
      );

      saveAuth(response.data);
    },
    [saveAuth]
  );

  // =====================================================
  // RESEND LOGIN OTP
  // =====================================================

  const resendEmailOtp = useCallback(
    async (challengeToken: string) => {
      const response = await api.post<EmailOtpResendResponse>(
        "/api/auth/2fa/resend-email",
        {},
        bearer(challengeToken)
      );

      return response.data;
    },
    []
  );

  // =====================================================
  // START REGISTRATION
  // =====================================================

  const register = useCallback(
    async (data: RegisterData): Promise<RegistrationStart> => {
      const response = await api.post<RegistrationStart>(
        "/api/auth/register",
        data
      );

      // Do not save registration_token as idps_token.
      return response.data;
    },
    []
  );

  // =====================================================
  // VERIFY REGISTRATION EMAIL
  // =====================================================

  const verifyRegistrationEmail = useCallback(
    async (
      registrationToken: string,
      code: string
    ): Promise<EmailVerificationResult> => {
      const response = await api.post<EmailVerificationResult>(
        "/api/auth/register/verify-email",
        { code },
        bearer(registrationToken)
      );

      return response.data;
    },
    []
  );

  // =====================================================
  // RESEND REGISTRATION EMAIL OTP
  // =====================================================

  const resendRegistrationEmail = useCallback(
    async (registrationToken: string) => {
      const response = await api.post<RegistrationResendResult>(
        "/api/auth/register/resend-email",
        {},
        bearer(registrationToken)
      );

      return response.data;
    },
    []
  );

  // =====================================================
  // SELECT REGISTRATION 2FA METHOD
  // =====================================================

  const selectRegistrationMethod = useCallback(
    async (
      enrollmentToken: string,
      method: "totp" | "email"
    ) => {
      await api.post(
        "/api/auth/register/2fa/method",
        { method },
        bearer(enrollmentToken)
      );
    },
    []
  );

  // =====================================================
  // SET UP REGISTRATION TOTP
  // =====================================================

  const setupRegistrationTotp = useCallback(
    async (enrollmentToken: string) => {
      const response = await api.post<TotpSetupResult>(
        "/api/auth/register/2fa/totp/setup",
        {},
        bearer(enrollmentToken)
      );

      return response.data;
    },
    []
  );

  // =====================================================
  // SET UP REGISTRATION EMAIL 2FA
  // =====================================================

  const setupRegistrationEmail = useCallback(
    async (enrollmentToken: string) => {
      const response = await api.post<RegistrationResendResult>(
        "/api/auth/register/2fa/email/setup",
        {},
        bearer(enrollmentToken)
      );

      return response.data;
    },
    []
  );

  // =====================================================
  // COMPLETE REGISTRATION
  // =====================================================

  const completeRegistration = useCallback(
    async (enrollmentToken: string, code: string) => {
      const response = await api.post<RegistrationCompleteResult>(
        "/api/auth/register/complete",
        { code },
        bearer(enrollmentToken)
      );

      if (!response.data.registration_complete) {
        throw new Error("Registration was not completed.");
      }

      // Only the final access token becomes idps_token.
      saveAuth(response.data);
    },
    [saveAuth]
  );

  // =====================================================
  // REFRESH CURRENT USER
  // =====================================================

  const refreshUser = useCallback(async () => {
    const token = sessionStorage.getItem("idps_token");

    if (!token) {
      setUser(null);
      return;
    }

    const response = await api.get<User>("/api/auth/me");
    setUser(response.data);
  }, []);

  // =====================================================
  // RESTORE SESSION
  // =====================================================

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const token = sessionStorage.getItem("idps_token");

      if (!token) {
        if (active) setLoading(false);
        return;
      }

      try {
        const response = await api.get<User>("/api/auth/me");

        if (active) setUser(response.data);
      } catch {
        if (!active) return;

        // An invalid or expired access token should not
        // remain in session storage.
        sessionStorage.removeItem("idps_token");
        setUser(null);
      } finally {
        if (active) setLoading(false);
      }
    }

    void restoreSession();

    return () => {
      active = false;
    };
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        verifyTwoFactor,
        resendEmailOtp,
        register,
        verifyRegistrationEmail,
        resendRegistrationEmail,
        selectRegistrationMethod,
        setupRegistrationTotp,
        setupRegistrationEmail,
        completeRegistration,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside AuthProvider"
    );
  }

  return context;
}
