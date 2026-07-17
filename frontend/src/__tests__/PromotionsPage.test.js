/**
 * Tests — PromotionsPage (historique des promotions entre distributions)
 *
 * Couverture :
 *   - Rendu du titre et appel listPendingPromotions("all", 1, 20) au montage
 *   - État vide (aucune promotion enregistrée)
 *   - Affichage d'une promotion (nom, version, demandeur, distributions, statut)
 *   - Filtres de statut (client-side)
 *   - Détail dépliable des alertes CVE (policy_verdict)
 *   - Bouton Rafraîchir
 *   - Gestion d'erreur API (toast, pas de crash)
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

// ── Mocks ─────────────────────────────────────────────────────────────────────
vi.mock('../api', () => ({
  listPendingPromotions: vi.fn(),
}));

import { listPendingPromotions } from '../api';

import PromotionsPage from '../pages/PromotionsPage';

// ── Helpers ───────────────────────────────────────────────────────────────────
const renderPage = () =>
  render(
    <MemoryRouter>
      <Toaster />
      <PromotionsPage />
    </MemoryRouter>
  );

const makeRecord = (overrides = {}) => ({
  id:             'uuid-1',
  name:           'nginx',
  version:        '1.24.0',
  from_dist:      'jammy',
  to_dist:        'noble',
  requested_by:   'alice',
  requested_at:   '2026-01-15T10:00:00+00:00',
  status:         'approved',
  policy_verdict: {
    verdict:   'approved',
    reviewing: [],
    warnings:  [],
    blocking:  [],
  },
  decided_by:    null,
  decided_at:    null,
  decision_note: '',
  ...overrides,
});

const emptyResponse   = { total: 0, items: { items: [], total: 0 } };
const oneItemResponse = (item) => ({ total: 1, items: { items: [item], total: 1 } });

// ─────────────────────────────────────────────────────────────────────────────

describe('PromotionsPage — état vide', () => {
  beforeEach(() => {
    listPendingPromotions.mockResolvedValue(emptyResponse);
  });

  test('affiche le titre et la description', async () => {
    renderPage();
    expect(screen.getByText('Promotions')).toBeInTheDocument();
    expect(screen.getByText(/Historique des promotions de paquets entre distributions/i)).toBeInTheDocument();
  });

  test('appelle listPendingPromotions("all", 1, 20) au montage', async () => {
    renderPage();
    await waitFor(() => {
      expect(listPendingPromotions).toHaveBeenCalledWith('all', 1, 20);
    });
  });

  test('affiche le message vide quand aucune promotion enregistrée', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('Aucune promotion enregistrée')).toBeInTheDocument();
    });
  });

  test('affiche les boutons de filtre de statut', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('Toutes')).toBeInTheDocument();
      expect(screen.getByText('Effectuées')).toBeInTheDocument();
      expect(screen.getByText('En attente')).toBeInTheDocument();
      expect(screen.getByText('Refusées')).toBeInTheDocument();
      expect(screen.getByText('Bloquées')).toBeInTheDocument();
    });
  });
});

describe('PromotionsPage — avec une promotion', () => {
  const record = makeRecord();

  beforeEach(() => {
    listPendingPromotions.mockResolvedValue(oneItemResponse(record));
  });

  test('affiche le nom et la version du paquet', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('nginx')).toBeInTheDocument();
      expect(screen.getByText('1.24.0')).toBeInTheDocument();
    });
  });

  test('affiche les distributions source et cible', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('jammy')).toBeInTheDocument();
      expect(screen.getByText('noble')).toBeInTheDocument();
    });
  });

  test('affiche le demandeur', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });
  });

  test('affiche le statut "Effectuée"', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('Effectuée')).toBeInTheDocument();
    });
  });

  test('affiche le compteur d\'entrées', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText('1 entrée(s)')).toBeInTheDocument();
    });
  });
});

describe('PromotionsPage — filtres de statut', () => {
  test('filtre "En attente" masque une promotion "approved"', async () => {
    listPendingPromotions.mockResolvedValue(oneItemResponse(makeRecord({ status: 'approved' })));
    renderPage();
    await waitFor(() => screen.getByText('nginx'));

    fireEvent.click(screen.getByText('En attente'));

    await waitFor(() => {
      expect(screen.queryByText('nginx')).not.toBeInTheDocument();
      expect(screen.getByText(/Aucune promotion "pending"/)).toBeInTheDocument();
    });
  });
});

describe('PromotionsPage — détail des alertes CVE', () => {
  test('déplie la ligne et affiche les CVE bloquantes', async () => {
    const record = makeRecord({
      status: 'blocked',
      policy_verdict: {
        verdict:   'blocked',
        blocking:  ['CVE-2026-1234 (critical)'],
        reviewing: [],
        warnings:  [],
      },
    });
    listPendingPromotions.mockResolvedValue(oneItemResponse(record));
    renderPage();

    await waitFor(() => screen.getByText('nginx'));
    fireEvent.click(screen.getByText('nginx'));

    await waitFor(() => {
      expect(screen.getByText(/Bloquant :/)).toBeInTheDocument();
      expect(screen.getAllByText(/CVE-2026-1234/).length).toBeGreaterThan(0);
    });
  });
});

describe('PromotionsPage — bouton Rafraîchir', () => {
  test('recharge les données au clic', async () => {
    listPendingPromotions.mockResolvedValue(emptyResponse);
    renderPage();
    await waitFor(() => {
      expect(listPendingPromotions).toHaveBeenCalled();
    });
    const before = listPendingPromotions.mock.calls.length;

    fireEvent.click(screen.getByText('Rafraîchir'));

    await waitFor(() => {
      expect(listPendingPromotions.mock.calls.length).toBeGreaterThan(before);
    });
  });
});

describe('PromotionsPage — erreurs API', () => {
  test('affiche un toast d\'erreur si l\'API échoue, sans crasher', async () => {
    listPendingPromotions.mockRejectedValue(new Error('Network error'));
    renderPage();

    await waitFor(() => {
      expect(screen.getByText('Promotions')).toBeInTheDocument();
      expect(screen.getByText(/Impossible de charger l'historique des promotions/i)).toBeInTheDocument();
    });
  });
});
