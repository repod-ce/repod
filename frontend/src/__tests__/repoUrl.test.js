/**
 * Tests — Dérivation des URLs de dépôt (getRepoUrl / getRpmRepoUrl)
 *
 * Ces deux fonctions sont le point unique dont dépendent toutes les commandes
 * client affichées par ClientSetupPage (sources.list, .repo, /etc/apk/repositories).
 *
 * En HTTP, les dépôts sont joints en direct sur leurs ports publiés (80, 8080).
 * En HTTPS, ils sont servis par le proxy TLS sous le même certificat que l'UI :
 * /repos et /apk sur apt-repo, /rpm sur rpm-repo — voir nginx/tls-proxy.conf.
 * Coller le port du dépôt en clair au protocole de la page, comme avant, donnait
 * un « https://<host>:80 » qui ne répond pas.
 */

vi.mock("axios", () => {
  const mockApi = {
    get:          vi.fn(),
    post:         vi.fn(),
    patch:        vi.fn(),
    delete:       vi.fn(),
    interceptors: {
      request:  { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { baseURL: "" },
  };
  const axiosMock = vi.fn(() => mockApi);
  axiosMock.create = vi.fn(() => mockApi);
  return { default: axiosMock, ...axiosMock };
});

import { getRepoUrl, getRpmRepoUrl } from "../api";

const setLocation = (href) => {
  const url = new URL(href);
  vi.stubGlobal("location", {
    href:     url.href,
    origin:   url.origin,
    protocol: url.protocol,
    hostname: url.hostname,
    host:     url.host,
    port:     url.port,
  });
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("HTTP — accès direct aux dépôts", () => {
  it("garde le port 80 pour APT", () => {
    setLocation("http://repod.local:3003/packages");
    expect(getRepoUrl()).toBe("http://repod.local:80");
  });

  it("garde le port 8080 pour RPM", () => {
    setLocation("http://repod.local:3003/packages");
    expect(getRpmRepoUrl()).toBe("http://repod.local:8080");
  });
});

describe("HTTPS — dépôts servis par le proxy TLS", () => {
  it("APT est servi sur l'origine courante, sans port de dépôt en clair", () => {
    setLocation("https://repod.example.com/packages");
    expect(getRepoUrl()).toBe("https://repod.example.com");
  });

  it("RPM est servi sous le préfixe /rpm", () => {
    setLocation("https://repod.example.com/packages");
    expect(getRpmRepoUrl()).toBe("https://repod.example.com/rpm");
  });

  it("conserve un port non standard, le proxy pouvant être ailleurs qu'en 443", () => {
    setLocation("https://repod.example.com:9443/packages");
    expect(getRepoUrl()).toBe("https://repod.example.com:9443");
    expect(getRpmRepoUrl()).toBe("https://repod.example.com:9443/rpm");
  });

  it("compose des URLs client exploitables", () => {
    setLocation("https://repod.example.com/packages");
    expect(`${getRepoUrl()}/repos/dists/depot.gpg`)
      .toBe("https://repod.example.com/repos/dists/depot.gpg");
    expect(`${getRepoUrl()}/apk/alpine3.20/main`)
      .toBe("https://repod.example.com/apk/alpine3.20/main");
    expect(`${getRpmRepoUrl()}/almalinux9/x86_64/`)
      .toBe("https://repod.example.com/rpm/almalinux9/x86_64/");
  });
});

describe("Surcharge explicite", () => {
  it("REACT_APP_REPO_URL l'emporte sur la dérivation", () => {
    setLocation("https://repod.example.com/packages");
    vi.stubEnv("REACT_APP_REPO_URL", "http://192.0.2.10:8085");
    expect(getRepoUrl()).toBe("http://192.0.2.10:8085");
  });

  it("REACT_APP_RPM_REPO_URL l'emporte sur la dérivation", () => {
    setLocation("https://repod.example.com/packages");
    vi.stubEnv("REACT_APP_RPM_REPO_URL", "http://192.0.2.10:8080");
    expect(getRpmRepoUrl()).toBe("http://192.0.2.10:8080");
  });
});
