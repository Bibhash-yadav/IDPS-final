
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
  RegisterData,
  User,
} from "../types/auth";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (data: LoginData) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    sessionStorage.removeItem("idps_token");
    setUser(null);
  }, []);

  const saveAuth = useCallback((response: AuthResponse) => {
    sessionStorage.setItem("idps_token", response.access_token);
    setUser(response.user);
  }, []);

  const login = useCallback(
    async (data: LoginData) => {
      const response = await api.post<AuthResponse>(
        "/api/auth/login",
        data,
      );

      saveAuth(response.data);
    },
    [saveAuth],
  );

  const register = useCallback(
    async (data: RegisterData) => {
      const response = await api.post<AuthResponse>(
        "/api/auth/register",
        data,
      );

      saveAuth(response.data);
    },
    [saveAuth],
  );

  // Refresh the current user's data from the backend.
  // The backend should return date_of_birth and a DOB-derived age.
  const refreshUser = useCallback(async () => {
    const token = sessionStorage.getItem("idps_token");

    if (!token) {
      setUser(null);
      return;
    }

    const response = await api.get<User>("/api/auth/me");
    setUser(response.data);
  }, []);

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

        if (active) {
          setUser(response.data);
        }
      } catch {
        // A temporary network/server error should not automatically
        // destroy the token. Clear it only for an authentication failure.
        if (!active) return;

        setUser(null);
      } finally {
        if (active) {
          setLoading(false);
        }
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
        register,
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
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
}
