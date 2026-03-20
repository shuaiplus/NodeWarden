import { ArrowUpDown, Cloud, Clock3, Folder as FolderIcon, KeyRound, Lock, LogOut, Send as SendIcon, Settings as SettingsIcon, Shield, ShieldUser } from 'lucide-preact';
import { Link } from 'wouter';
import AppMainRoutes from '@/components/AppMainRoutes';
import type { AppMainRoutesProps } from '@/components/AppMainRoutes';
import { t } from '@/lib/i18n';
import type { Profile } from '@/lib/types';

interface AppAuthenticatedShellProps {
  profile: Profile | null;
  location: string;
  mobilePrimaryRoute: string;
  currentPageTitle: string;
  showSidebarToggle: boolean;
  sidebarToggleTitle: string;
  settingsAccountRoute: string;
  importRoute: string;
  isImportRoute: boolean;
  onLock: () => void;
  onLogout: () => void;
  mainRoutesProps: AppMainRoutesProps;
}

export default function AppAuthenticatedShell(props: AppAuthenticatedShellProps) {
  return (
    <div className="app-page">
      <div className="app-shell">
        <header className="topbar">
          <div className="brand">
            <img src="/logo-64.png" alt="NodeWarden logo" className="brand-logo" />
            <span className="brand-name">NodeWarden</span>
            <span className="mobile-page-title">{props.currentPageTitle}</span>
          </div>
          <div className="topbar-actions">
            <div className="user-chip">
              <ShieldUser size={16} />
              <span>{props.profile?.email}</span>
            </div>
            <button type="button" className="btn btn-secondary small" onClick={props.onLock}>
              <Lock size={14} className="btn-icon" /> {t('txt_lock')}
            </button>
            {props.showSidebarToggle && (
              <button
                type="button"
                className="btn btn-secondary small mobile-sidebar-toggle"
                aria-label={props.sidebarToggleTitle}
                title={props.sidebarToggleTitle}
                onClick={() => window.dispatchEvent(new CustomEvent('nodewarden:toggle-sidebar'))}
              >
                <FolderIcon size={16} className="btn-icon" />
              </button>
            )}
            <button type="button" className="btn btn-secondary small mobile-lock-btn" aria-label={t('txt_lock')} title={t('txt_lock')} onClick={props.onLock}>
              <Lock size={14} className="btn-icon" />
            </button>
            <button type="button" className="btn btn-secondary small" onClick={props.onLogout}>
              <LogOut size={14} className="btn-icon" /> {t('txt_sign_out')}
            </button>
          </div>
        </header>

        <div className="app-main">
          <aside className="app-side">
            <Link href="/vault" className={`side-link ${props.location === '/vault' ? 'active' : ''}`}>
              <KeyRound size={16} />
              <span>{t('nav_my_vault')}</span>
            </Link>
            <Link href="/vault/totp" className={`side-link ${props.location === '/vault/totp' ? 'active' : ''}`}>
              <Clock3 size={16} />
              <span>{t('txt_verification_code')}</span>
            </Link>
            <Link href="/sends" className={`side-link ${props.location === '/sends' ? 'active' : ''}`}>
              <SendIcon size={16} />
              <span>{t('nav_sends')}</span>
            </Link>
            {props.profile?.role === 'admin' && (
              <Link href="/admin" className={`side-link ${props.location === '/admin' ? 'active' : ''}`}>
                <ShieldUser size={16} />
                <span>{t('nav_admin_panel')}</span>
              </Link>
            )}
            <Link href={props.settingsAccountRoute} className={`side-link ${props.location === props.settingsAccountRoute ? 'active' : ''}`}>
              <SettingsIcon size={16} />
              <span>{t('nav_account_settings')}</span>
            </Link>
            <Link href="/security/devices" className={`side-link ${props.location === '/security/devices' ? 'active' : ''}`}>
              <Shield size={16} />
              <span>{t('nav_device_management')}</span>
            </Link>
            {props.profile?.role === 'admin' && (
              <Link href="/backup" className={`side-link ${props.location === '/backup' ? 'active' : ''}`}>
                <Cloud size={16} />
                <span>{t('nav_backup_strategy')}</span>
              </Link>
            )}
            <Link href={props.importRoute} className={`side-link ${props.isImportRoute ? 'active' : ''}`}>
              <ArrowUpDown size={14} />
              <span>{t('nav_import_export')}</span>
            </Link>
          </aside>
          <main className="content">
            <AppMainRoutes {...props.mainRoutesProps} />
          </main>
        </div>

        <nav className="mobile-tabbar" aria-label={t('txt_menu')}>
          <Link href="/vault" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault' ? 'active' : ''}`}>
            <KeyRound size={18} />
            <span>{t('nav_my_vault')}</span>
          </Link>
          <Link href="/vault/totp" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault/totp' ? 'active' : ''}`}>
            <Clock3 size={18} />
            <span>{t('txt_verification_code')}</span>
          </Link>
          <Link href="/sends" className={`mobile-tab ${props.mobilePrimaryRoute === '/sends' ? 'active' : ''}`}>
            <SendIcon size={18} />
            <span>{t('nav_sends')}</span>
          </Link>
          <Link href="/settings" className={`mobile-tab ${props.mobilePrimaryRoute === '/settings' ? 'active' : ''}`}>
            <SettingsIcon size={18} />
            <span>{t('txt_settings')}</span>
          </Link>
        </nav>
      </div>
    </div>
  );
}
