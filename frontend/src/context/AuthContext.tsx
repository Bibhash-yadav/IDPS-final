
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

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const token = sessionStorage.getItem("idps_token");

      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const response = await api.get<User>("/api/auth/me");

        if (active) {
          setUser(response.data);
        }
      } catch {
        sessionStorage.removeItem("idps_token");

        if (active) {
          setUser(null);
        }
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
      value={{ user, loading, login, register, logout }}
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
