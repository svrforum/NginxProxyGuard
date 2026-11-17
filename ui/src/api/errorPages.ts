import { apiDelete, apiGet, apiPut } from './client';

/** A custom HTML page for one of NPG's own error pages (#335). */
export interface CustomErrorPage {
  status_code: number;
  html: string;
  updated_at: string;
}

export interface CustomErrorPages {
  /** The pages that can be replaced: 403, 502, 503, 504. */
  statuses: number[];
  pages: CustomErrorPage[];
}

const BASE = '/api/v1/settings/error-pages';

export const fetchErrorPages = () => apiGet<CustomErrorPages>(BASE);

export const saveErrorPage = (status: number, html: string) => apiPut<CustomErrorPages>(`${BASE}/${status}`, { html });

export const resetErrorPage = (status: number) => apiDelete(`${BASE}/${status}`);
