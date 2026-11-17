/** One account row of the access-list form (#387). original is the stored username. */
export interface AuthUserRow {
  key: string;
  username: string;
  password: string;
  original?: string;
}

export type AuthUserError = 'usernameRequired' | 'usernameInvalid' | 'passwordRequired' | 'passwordTooShort';

/** An account keeps its stored password only under its stored username. */
export const keepsPassword = (row: AuthUserRow) => row.original !== undefined && row.username.trim() === row.original;

/** The first problem of each row, checked as the API checks it. */
export function authUserErrors(rows: AuthUserRow[]): Record<string, AuthUserError> {
  const errors: Record<string, AuthUserError> = {};
  for (const row of rows) {
    const name = row.username.trim();
    if (!name) errors[row.key] = 'usernameRequired';
    else if (/[:\s]/.test(name) || name.length > 64) errors[row.key] = 'usernameInvalid';
    else if (!row.password && !keepsPassword(row)) errors[row.key] = 'passwordRequired';
    else if (row.password && row.password.length < 8) errors[row.key] = 'passwordTooShort';
  }
  return errors;
}

let nextKey = 0;

/** The rows of a stored list's accounts, or none for a new list. */
export function rowsFromAuthUsers(users: { username: string }[] | undefined): AuthUserRow[] {
  return (users ?? []).map((u) => ({ key: `u${nextKey++}`, username: u.username, password: '', original: u.username }));
}

export const blankAuthUser = (): AuthUserRow => ({ key: `u${nextKey++}`, username: '', password: '' });

/** The accounts as the API takes them: a password only when one was typed. */
export function buildAuthUsersRequest(rows: AuthUserRow[]): { username: string; password?: string }[] {
  return rows.map((row) => ({ username: row.username.trim(), ...(row.password ? { password: row.password } : {}) }));
}
