
export type TwoFactorMethod = "totp" | "email";

export type OAuthProvider = "google" | "github";

// =====================================================
// USER
// =====================================================

export interface User {
  id: number;
  name: string;
  email: string;
  role: string;

  date_of_birth: string | null;
  age: number | null;

  auth_provider?: string;
  email_verified?: boolean;

  two_factor_enabled?: boolean;
  two_factor_method?: TwoFactorMethod | null;

  totp_enabled?: boolean;
  email_otp_enabled?: boolean;

  created_at?: string | null;
  updated_at?: string | null;
}

// =====================================================
// AUTHENTICATED SESSION
// =====================================================

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

// =====================================================
// LOGIN
// =====================================================

export interface LoginData {
  email: string;
  password: string;
}

export interface TwoFactorChallengeResponse {
  requires_two_factor: true;
  challenge_token: string;
  available_methods: TwoFactorMethod[];
  expires_in: number;
  message?: string;
}

export type LoginResponse =
  | AuthResponse
  | TwoFactorChallengeResponse;

// =====================================================
// REGISTRATION
// =====================================================

export interface RegisterData {
  name: string;
  email: string;
  password: string;
  date_of_birth: string;
}

// Initial registration response.
// The backend must not issue a normal access token here.

export interface RegistrationStartResponse {
  requires_email_verification: true;
  registration_token: string;
  expires_in: number;
  message: string;
}

// Email verification response.

export interface RegistrationEmailVerifyResponse {
  email_verified: true;
  requires_two_factor_setup: true;
  enrollment_token: string;
  available_methods: TwoFactorMethod[];
  message: string;
}

// TOTP enrollment response.

export interface RegistrationTotpSetupResponse {
  secret: string;
  provisioning_uri: string;
  message: string;
}

// Successful registration after 2FA confirmation.

export interface RegistrationCompleteResponse
  extends AuthResponse {
  registration_complete: true;
}

// =====================================================
// TWO-FACTOR VERIFICATION
// =====================================================

export interface TwoFactorVerifyData {
  code: string;
}

export interface TwoFactorSetupVerifyRequest {
  code: string;
}

export interface EmailOtpResendResponse {
  message: string;
  expires_in: number;
}

// =====================================================
// TWO-FACTOR STATUS
// =====================================================

export interface TwoFactorStatus {
  two_factor_enabled: boolean;
  two_factor_method: TwoFactorMethod | null;
  totp_enabled: boolean;
  email_otp_enabled: boolean;
}

// =====================================================
// OAUTH
// =====================================================

export interface OAuthLoginResponse {
  message: string;

  requires_profile_completion?: boolean;
  requires_two_factor?: boolean;

  challenge_token?: string | null;

  available_methods?: TwoFactorMethod[];

  access_token?: string | null;
  token_type?: string;

  user?: User | null;
}

// OAuth callbacks may return a final login or
// a temporary registration/2FA challenge.

export type OAuthResponse =
  | AuthResponse
  | TwoFactorChallengeResponse
  | OAuthLoginResponse;
