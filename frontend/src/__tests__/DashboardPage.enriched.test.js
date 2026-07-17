/**
 * Tests — DashboardPage enrichi (Sprint 5.4 / 7.1 frontend)
 *
 * Couverture :
 *   - Bannière SLA overdue affichée si des paquets dépassent le SLA
 *   - Bannière SLA overdue absente si liste vide
 *   - Contenu de la bannière (nom paquet, jours)
 *   - Chart CVE trends rendu si données présentes
 *   - Appel getEnrichedDashboard au chargement
 *   - Pas de crash si getEnrichedDashboard échoue
 */

import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

// ── Mocks ─────────────────────────────────────────────────────────────────────
vi.mock('../api', () => ({
  getDashboardStats:    vi.fn(),
  getDashboardHistory:  vi.fn(),
  getEnrichedDashboard: vi.fn(),
}));

// Recharts utilise ResizeObserver qui n'existe pas dans jsdom
global.ResizeObserver = class {
  observe()   {}
  unobserve() {}
  disconnect() {}
};

import { getDashboardStats, getDashboardHistory, getEnrichedDashboard } from '../api';
import DashboardPage from '../pages/DashboardPage';

// ── Données de test ───────────────────────────────────────────────────────────
const minimalStats = {
  total_packages:    5,
  total_size_bytes:  1_000_000,
  security_review:   { pending: 0, blocked: 0, total: 0 },
  top_packages:      [],
  clamav:            { status: 'ok', db_version: '100', db_date: '2026-01-01' },
  alerts:            [],
  recent_imports:    [],
  distributions:     [],
};

const enrichedWithSla = {
  cve_trends: [
    { window_days: 30, packages_imported: 5, cve_totals: { critical: 2, high: 3, medium: 1, low: 0, negligible: 0 } },
    { window_days: 60, packages_imported: 8, cve_totals: { critical: 4, high: 5, medium: 2, low: 1, negligible: 0 } },
    { window_days: 90, packages_imported: 12, cve_totals: { critical: 6, high: 7, medium: 3, low: 2, negligible: 1 } },
  ],
  sla_overdue: [
    { name: 'openssl', version: '3.0.1', age_days: 15 },
    { name: 'curl',    version: '7.8.0', age_days: 12 },
  ],
  top_packages: { by_versions: [], by_size: [], recently_added: [] },
};

const enrichedNoSla = {
  cve_trends: [],
  sla_overdue: [],
  top_packages: { by_versions: [], by_size: [], recently_added: [] },
};

const renderDashboard = () =>
  render(
    <MemoryRouter>
      <Toaster />
      <DashboardPage />
    </MemoryRouter>
  );

// ─────────────────────────────────────────────────────────────────────────────

describe('DashboardPage — appels API enrichis', () => {
  beforeEach(() => {
    getDashboardStats.mockResolvedValue(minimalStats);
    getDashboardHistory.mockResolvedValue({ history: [] });
    getEnrichedDashboard.mockResolvedValue(enrichedNoSla);
  });

  test('appelle getEnrichedDashboard au chargement', async () => {
    renderDashboard();
    await waitFor(() => {
      expect(getEnrichedDashboard).toHaveBeenCalledWith({ trend_windows: '30,60,90' });
    });
  });

  test('ne plante pas si getEnrichedDashboard renvoie null', async () => {
    getEnrichedDashboard.mockResolvedValue(null);
    renderDashboard();
    await waitFor(() => {
      expect(getDashboardStats).toHaveBeenCalled();
    });
    // Page toujours rendue
    expect(screen.queryByText(/erreur fatale/i)).not.toBeInTheDocument();
  });

  test('ne plante pas si getEnrichedDashboard rejette', async () => {
    getEnrichedDashboard.mockRejectedValue(new Error('server error'));
    renderDashboard();
    await waitFor(() => {
      expect(getDashboardStats).toHaveBeenCalled();
    });
    expect(screen.queryByText(/erreur fatale/i)).not.toBeInTheDocument();
  });
});

describe('DashboardPage — bannière SLA overdue', () => {
  beforeEach(() => {
    getDashboardStats.mockResolvedValue(minimalStats);
    getDashboardHistory.mockResolvedValue({ history: [] });
  });

  test('affiche la bannière si des paquets dépassent le SLA', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/dépassent le SLA de review/i)).toBeInTheDocument();
    });
  });

  test('affiche le bon nombre de paquets overdue', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/2 paquet.s. dépassent/i)).toBeInTheDocument();
    });
  });

  test('affiche les noms des paquets overdue', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/openssl@3\.0\.1/)).toBeInTheDocument();
      expect(screen.getByText(/curl@7\.8\.0/)).toBeInTheDocument();
    });
  });

  test('affiche le nombre de jours', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/15j/)).toBeInTheDocument();
    });
  });

  test('n\'affiche PAS la bannière si sla_overdue est vide', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedNoSla);
    renderDashboard();
    await waitFor(() => getDashboardStats.mock.calls.length > 0);
    // Attendre que le contenu soit chargé
    await waitFor(() => screen.getByText(/Tableau de bord/i));
    expect(screen.queryByText(/dépassent le SLA de review/i)).not.toBeInTheDocument();
  });

  test('n\'affiche PAS la bannière si enriched est null', async () => {
    getEnrichedDashboard.mockResolvedValue(null);
    renderDashboard();
    await waitFor(() => getDashboardStats.mock.calls.length > 0);
    await waitFor(() => screen.getByText(/Tableau de bord/i));
    expect(screen.queryByText(/dépassent le SLA de review/i)).not.toBeInTheDocument();
  });
});

describe('DashboardPage — section CVE Trends', () => {
  beforeEach(() => {
    getDashboardStats.mockResolvedValue(minimalStats);
    getDashboardHistory.mockResolvedValue({ history: [] });
  });

  test('affiche le titre CVE Trends si données présentes', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/Tendances CVE/i)).toBeInTheDocument();
    });
  });

  test('affiche les fenêtres temporelles (30j, 60j, 90j)', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('30j')).toBeInTheDocument();
      expect(screen.getByText('60j')).toBeInTheDocument();
      expect(screen.getByText('90j')).toBeInTheDocument();
    });
  });

  test('affiche le nombre de paquets importés par fenêtre', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedWithSla);
    renderDashboard();
    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument(); // 5 paquets pour 30j
    });
  });

  test('n\'affiche PAS la section si cve_trends est vide', async () => {
    getEnrichedDashboard.mockResolvedValue(enrichedNoSla);
    renderDashboard();
    await waitFor(() => getDashboardStats.mock.calls.length > 0);
    await waitFor(() => screen.getByText(/Tableau de bord/i));
    expect(screen.queryByText(/Tendances CVE/i)).not.toBeInTheDocument();
  });
});
