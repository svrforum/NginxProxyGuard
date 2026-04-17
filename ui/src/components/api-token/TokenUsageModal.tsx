import { useTranslation } from 'react-i18next';

interface CreatedTokenModalProps {
  token: string;
  onClose: () => void;
}

// Modal shown once after a token is created. Surfaces the plaintext token
// value alongside a copy button + warning.
export function CreatedTokenModal({ token, onClose }: CreatedTokenModalProps) {
  const { t } = useTranslation('settings');

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-lg w-full mx-4 shadow-xl">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
          {t('apiTokens.modal.created')}
        </h3>
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-4">
          <p className="text-sm text-yellow-800 dark:text-yellow-200 mb-2">
            {t('apiTokens.modal.tokenWarning')}
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-100 dark:bg-slate-700 px-3 py-2 rounded text-sm font-mono break-all text-slate-800 dark:text-slate-200">
              {token}
            </code>
            <button
              onClick={() => copyToClipboard(token)}
              className="px-3 py-2 bg-primary-600 text-white rounded hover:bg-primary-700"
            >
              {t('apiTokens.buttons.copy')}
            </button>
          </div>
        </div>
        <button
          onClick={onClose}
          className="w-full px-4 py-2 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-white rounded hover:bg-slate-200 dark:hover:bg-slate-600"
        >
          {t('apiTokens.buttons.close')}
        </button>
      </div>
    </div>
  );
}

// Footer block describing how to use the token in an HTTP header.
export function TokenUsageNote() {
  const { t } = useTranslation('settings');
  return (
    <div className="bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800 rounded-lg p-4">
      <h4 className="font-medium text-primary-800 dark:text-primary-200 mb-2">{t('apiTokens.usage.title')}</h4>
      <p className="text-sm text-primary-700 dark:text-primary-300 mb-2">
        {t('apiTokens.usage.description')}
      </p>
      <code className="block bg-primary-100 dark:bg-primary-900 px-3 py-2 rounded text-sm font-mono text-primary-800 dark:text-primary-200">
        Authorization: Bearer ng_your_token_here
      </code>
    </div>
  );
}
