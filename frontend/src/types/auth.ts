
export interface User {
  id: number;
  name: string;
  email: string;
  role: string;

  // Saved date of birth in YYYY-MM-DD format
  date_of_birth: string | null;

  // Age calculated from date_of_birth by the backend
  age: number | null;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface LoginData {
  email: string;
  password: string;
}

export interface RegisterData {
  name: string;
  email: string;
  password: string;

  // Required during new account registration
  date_of_birth: string;
}
