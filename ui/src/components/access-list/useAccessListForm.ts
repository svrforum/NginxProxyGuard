import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createAccessList, updateAccessList } from '../../api/access';
import { ApiError, isNginxReloadRefusal } from '../../api/client';
import type { AccessList, CreateAccessListRequest } from '../../types/access';
import {
  blankRow,
  buildItemsRequest,
  errorTextKey,
  itemFieldError,
  rowsFromList,
  type AccessRuleRow,
  type RowError,
  type RuleField,
} from './accessListItems';
import { authUserErrors, blankAuthUser, buildAuthUsersRequest, rowsFromAuthUsers, type AuthUserError, type AuthUserRow } from './authUsers';

export interface AccessListSaved {
  /** Set when the list is saved but nginx refused to load it (409 nginx_reload_rejected). */
  refusal?: ApiError;
}

/** State and save logic of the access-list form. */
export function useAccessListForm(accessList: AccessList | null, onSaved: (result: AccessListSaved) => void) {
  const { t } = useTranslation(['accessControl', 'dnsEntries']);
  const [name, setName] = useState(accessList?.name || '');
  const [description, setDescription] = useState(accessList?.description || '');
  const [satisfyAny, setSatisfyAny] = useState(accessList?.satisfy_any ?? true);
  const [passAuth, setPassAuth] = useState(accessList?.pass_auth ?? false);
  const [rows, setRows] = useState<AccessRuleRow[]>(() => rowsFromList(accessList));
  const [users, setUsers] = useState<AuthUserRow[]>(() => rowsFromAuthUsers(accessList?.auth_users));
  const [userErrors, setUserErrors] = useState<Record<string, AuthUserError>>({});
  const [formError, setFormError] = useState('');
  const [rowErrors, setRowErrors] = useState<Record<string, RowError>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const clearRowError = (key: string) =>
    setRowErrors((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });

  const addRow = () => setRows((prev) => [...prev, blankRow()]);

  const removeRow = (key: string) => {
    setRows((prev) => prev.filter((row) => row.key !== key));
    clearRowError(key);
  };

  const changeRow = (key: string, field: RuleField, value: string) => {
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, [field]: value } : row)));
    clearRowError(key);
  };

  const addUser = () => setUsers((prev) => [...prev, blankAuthUser()]);
  const removeUser = (key: string) => setUsers((prev) => prev.filter((u) => u.key !== key));
  const changeUser = (key: string, field: 'username' | 'password', value: string) => {
    setUsers((prev) => prev.map((u) => (u.key === key ? { ...u, [field]: value } : u)));
    setUserErrors((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  // The operator's explicit promotion of a legacy allow: from now on the row is
  // an ordinary rule whose address is a domain, sent with kind "hostname".
  const moveToDomain = (key: string) => {
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, legacy: undefined, directive: 'allow' } : row)));
    clearRowError(key);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setFormError('');
    const built = buildItemsRequest(rows);
    setRowErrors(built.errors);
    if (Object.keys(built.errors).length > 0) {
      setFormError(t('messages.fixRules'));
      return;
    }
    const badUsers = authUserErrors(users);
    setUserErrors(badUsers);
    if (Object.keys(badUsers).length > 0) {
      setFormError(t('messages.fixUsers'));
      return;
    }

    setIsSubmitting(true);
    const data: CreateAccessListRequest = {
      name,
      description: description || undefined,
      satisfy_any: satisfyAny,
      pass_auth: passAuth,
      items: built.items,
      auth_users: buildAuthUsersRequest(users),
    };
    try {
      if (accessList) {
        await updateAccessList(accessList.id, data);
      } else {
        await createAccessList(data);
      }
      onSaved({});
    } catch (err) {
      if (isNginxReloadRefusal(err)) {
        onSaved({ refusal: err });
        return;
      }
      const fieldError = itemFieldError(err);
      const rowIndex = fieldError ? built.rowOfRequestIndex[fieldError.requestIndex] : undefined;
      const row = rowIndex === undefined ? undefined : rows[rowIndex];
      if (fieldError && row) {
        setRowErrors({ [row.key]: { code: fieldError.code, message: fieldError.message } });
        setFormError(t('messages.fixRules'));
        return;
      }
      const message = err instanceof Error ? err.message : t('messages.saveError');
      const key = errorTextKey(err instanceof ApiError ? err.code : undefined);
      setFormError(key ? t(key, { detail: message }) : message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return {
    name,
    setName,
    description,
    setDescription,
    satisfyAny,
    setSatisfyAny,
    passAuth,
    setPassAuth,
    editableRows: rows.filter((row) => !row.legacy),
    legacyRows: rows.filter((row) => !!row.legacy),
    formError,
    rowErrors,
    isSubmitting,
    addRow,
    removeRow,
    changeRow,
    moveToDomain,
    submit,
    users,
    userErrors,
    addUser,
    removeUser,
    changeUser,
  };
}
