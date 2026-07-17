/**
 * Tests — Nouvelles fonctions API (Sprints 6.2, 6.3, 7.1)
 *
 * Couverture :
 *   getEnrichedDashboard  — construit la bonne URL + params
 *   listPendingPromotions — URL + params par défaut
 *   approvePendingPromotion — POST correct
 *   rejectPendingPromotion  — POST correct
 *   promoteArtifact        — POST correct avec options
 */

// On mock axios pour éviter de vrais appels réseau
vi.mock('axios', () => {
  const mockApi = {
    get:          vi.fn(),
    post:         vi.fn(),
    patch:        vi.fn(),
    delete:       vi.fn(),
    interceptors: {
      request:  { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { baseURL: '' },
  };
  const axiosMock = vi.fn(() => mockApi);
  axiosMock.create = vi.fn(() => mockApi);
  axiosMock.get    = vi.fn();
  // Vitest (ESM) exige un objet avec une clé "default" pour `import axios from 'axios'`.
  // On conserve aussi les propriétés à plat pour le `require('axios')` du test ci-dessous.
  return { default: axiosMock, ...axiosMock };
});

// Récupération de l'instance mockée (créée par axios.create)
import axios from 'axios';
const mockApi = axios.create();

// On réimporte l'api APRÈS le mock d'axios
// (Vitest hisse les vi.mock avant les imports, donc on peut importer normalement)
import * as api from '../api';

// Helper : configure le retour d'une méthode + capture l'URL réelle
const captureCalls = (method) => {
  const calls = [];
  mockApi[method].mockImplementation((...args) => {
    calls.push(args);
    return Promise.resolve({ data: {} });
  });
  return calls;
};

beforeEach(() => {
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────

describe('getEnrichedDashboard', () => {
  test('fait un GET sur /dashboard/stats/enriched', async () => {
    const calls = captureCalls('get');
    await api.getEnrichedDashboard();
    expect(calls.length).toBe(1);
    expect(calls[0][0]).toContain('/dashboard/stats/enriched');
  });

  test('passe le paramètre trend_windows', async () => {
    const calls = captureCalls('get');
    await api.getEnrichedDashboard({ trend_windows: '30,60,90' });
    expect(calls[0][0]).toContain('trend_windows=30%2C60%2C90');
  });

  test('passe le paramètre top_limit', async () => {
    const calls = captureCalls('get');
    await api.getEnrichedDashboard({ top_limit: 5 });
    expect(calls[0][0]).toContain('top_limit=5');
  });

  test('passe le paramètre sla_max_age_days', async () => {
    const calls = captureCalls('get');
    await api.getEnrichedDashboard({ sla_max_age_days: 30 });
    expect(calls[0][0]).toContain('sla_max_age_days=30');
  });

  test('n\'inclut pas sla_max_age_days si null', async () => {
    const calls = captureCalls('get');
    await api.getEnrichedDashboard({ sla_max_age_days: null });
    expect(calls[0][0]).not.toContain('sla_max_age_days');
  });
});

describe('listPendingPromotions', () => {
  test('fait un GET sur /artifacts/admin/pending-promotions', async () => {
    const calls = captureCalls('get');
    await api.listPendingPromotions();
    expect(calls[0][0]).toContain('/artifacts/admin/pending-promotions');
  });

  test('utilise status=pending par défaut', async () => {
    const calls = captureCalls('get');
    await api.listPendingPromotions();
    expect(calls[0][0]).toContain('status=pending');
  });

  test('passe le statut personnalisé', async () => {
    const calls = captureCalls('get');
    await api.listPendingPromotions('all');
    expect(calls[0][0]).toContain('status=all');
  });

  test('passe page et per_page', async () => {
    const calls = captureCalls('get');
    await api.listPendingPromotions('pending', 2, 10);
    expect(calls[0][0]).toContain('page=2');
    expect(calls[0][0]).toContain('per_page=10');
  });
});

describe('approvePendingPromotion', () => {
  test('fait un POST sur /artifacts/{name}/promote/{id}/approve', async () => {
    const calls = captureCalls('post');
    await api.approvePendingPromotion('nginx', 'uuid-123', 'justif');
    expect(calls[0][0]).toContain('/artifacts/nginx/promote/uuid-123/approve');
  });

  test('envoie justification dans le body', async () => {
    const calls = captureCalls('post');
    await api.approvePendingPromotion('nginx', 'uuid-123', 'ma justification');
    expect(calls[0][1]).toMatchObject({ justification: 'ma justification' });
  });

  test('encode les caractères spéciaux dans le nom', async () => {
    const calls = captureCalls('post');
    await api.approvePendingPromotion('pkg name', 'uuid-1', 'j');
    expect(calls[0][0]).toContain('pkg%20name');
  });
});

describe('rejectPendingPromotion', () => {
  test('fait un POST sur /artifacts/{name}/promote/{id}/reject', async () => {
    const calls = captureCalls('post');
    await api.rejectPendingPromotion('curl', 'uuid-456', 'motif');
    expect(calls[0][0]).toContain('/artifacts/curl/promote/uuid-456/reject');
  });

  test('envoie reason dans le body', async () => {
    const calls = captureCalls('post');
    await api.rejectPendingPromotion('curl', 'uuid-456', 'CVE non corrigées');
    expect(calls[0][1]).toMatchObject({ reason: 'CVE non corrigées' });
  });
});

describe('promoteArtifact', () => {
  test('fait un POST sur /artifacts/{name}/promote', async () => {
    const calls = captureCalls('post');
    await api.promoteArtifact('nginx', 'jammy', 'noble');
    expect(calls[0][0]).toContain('/artifacts/nginx/promote');
  });

  test('envoie from_dist et to_dist', async () => {
    const calls = captureCalls('post');
    await api.promoteArtifact('nginx', 'jammy', 'noble');
    expect(calls[0][1]).toMatchObject({ from_dist: 'jammy', to_dist: 'noble' });
  });

  test('passe force=true si fourni', async () => {
    const calls = captureCalls('post');
    await api.promoteArtifact('nginx', 'jammy', 'noble', { force: true, justification: 'admin ok' });
    expect(calls[0][1]).toMatchObject({ force: true, justification: 'admin ok' });
  });

  test('force=false par défaut', async () => {
    const calls = captureCalls('post');
    await api.promoteArtifact('nginx', 'jammy', 'noble');
    expect(calls[0][1].force).toBe(false);
  });

  test('passe la version si fournie', async () => {
    const calls = captureCalls('post');
    await api.promoteArtifact('nginx', 'jammy', 'noble', { version: '1.24.0' });
    expect(calls[0][1]).toMatchObject({ version: '1.24.0' });
  });
});
