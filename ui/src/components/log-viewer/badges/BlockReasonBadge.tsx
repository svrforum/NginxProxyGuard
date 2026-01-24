import { useTranslation } from 'react-i18next';
import type { BlockReason, BotCategory } from '../types';

interface BlockReasonBadgeProps {
  reason?: BlockReason;
  category?: BotCategory;
}

export function BlockReasonBadge({ reason, category }: BlockReasonBadgeProps) {
  const { t } = useTranslation('logs');
  if (!reason || reason === 'none') return null;

  const config: Record<string, { bg: string; text: string; label: string }> = {
    waf: { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-800 dark:text-orange-400', label: t('reasons.waf') },
    bot_filter: { bg: 'bg-purple-100 dark:bg-purple-900/30', text: 'text-purple-800 dark:text-purple-400', label: t('reasons.botFilter') },
    rate_limit: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-800 dark:text-yellow-400', label: t('reasons.rateLimit') },
    geo_block: { bg: 'bg-blue-100 dark:bg-blue-900/30', text: 'text-blue-800 dark:text-blue-400', label: t('reasons.geoBlock') },
    banned_ip: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-800 dark:text-red-400', label: t('reasons.bannedIp') },
    exploit_block: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-800 dark:text-red-400', label: t('reasons.exploitBlock') },
    uri_block: { bg: 'bg-pink-100 dark:bg-pink-900/30', text: 'text-pink-800 dark:text-pink-400', label: t('reasons.uriBlock') },
    cloud_provider_challenge: { bg: 'bg-cyan-100 dark:bg-cyan-900/30', text: 'text-cyan-800 dark:text-cyan-400', label: t('reasons.cloudChallenge') },
    cloud_provider_block: { bg: 'bg-cyan-100 dark:bg-cyan-900/30', text: 'text-cyan-800 dark:text-cyan-400', label: t('reasons.cloudBlock') },
    access_denied: { bg: 'bg-rose-100 dark:bg-rose-900/30', text: 'text-rose-800 dark:text-rose-400', label: t('reasons.accessDenied') },
  };

  const cfg = config[reason] || { bg: 'bg-gray-100 dark:bg-gray-800', text: 'text-gray-800 dark:text-gray-300', label: reason };
  const categoryLabel = category ? ` (${category.replace('_', ' ')})` : '';

  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium max-w-[80px] truncate ${cfg.bg} ${cfg.text}`} title={`${cfg.label}${categoryLabel}`}>
      {cfg.label}
    </span>
  );
}
