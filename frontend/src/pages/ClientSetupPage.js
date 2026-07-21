import { useState } from "react";
import toast from "react-hot-toast";
import { getRepoUrl, getRpmRepoUrl } from "../api";

const REPO_URL     = getRepoUrl();
const RPM_REPO_URL = getRpmRepoUrl();
const REPO_HOST    = REPO_URL.replace(/^https?:\/\//, "").replace(/:\d+$/, "");

// ─── Composants ───────────────────────────────────────────────────────────────

function CodeBlock({ code, label }) {
  const copy = () => {
    navigator.clipboard.writeText(code).then(
      () => toast.success("Copié"),
      () => toast.error("Impossible de copier")
    );
  };
  return (
    <div className="rounded-xl overflow-hidden border border-gray-200">
      {label && (
        <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
          <span className="text-xs text-gray-400 font-mono">{label}</span>
          <button onClick={copy}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copier
          </button>
        </div>
      )}
      <pre className="bg-gray-900 text-green-400 text-sm font-mono px-5 py-4 overflow-x-auto whitespace-pre w-0 min-w-full">
        {code}
      </pre>
    </div>
  );
}

function Step({ number, title, warning, children }) {
  return (
    <div className="flex gap-5">
      <div className={`shrink-0 w-8 h-8 rounded-full text-white flex items-center justify-center text-sm font-bold mt-0.5
        ${warning ? "bg-orange-500" : "bg-blue-600"}`}>
        {number}
      </div>
      <div className="flex-1 space-y-3 pb-8 border-b border-gray-100 last:border-0 last:pb-0">
        <h3 className="font-semibold text-gray-900">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function InfoBox({ type = "info", children }) {
  const styles = {
    info:    "bg-blue-50 border-blue-200 text-blue-800",
    warning: "bg-amber-50 border-amber-200 text-amber-800",
    danger:  "bg-red-50 border-red-200 text-red-800",
    success: "bg-green-50 border-green-200 text-green-800",
  };
  const icons = {
    info:    "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
    warning: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    danger:  "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    success: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  };
  return (
    <div className={`flex gap-3 border rounded-xl px-4 py-3 text-sm ${styles[type]}`}>
      <svg className="w-5 h-5 shrink-0 mt-0.5 opacity-70" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icons[type]} />
      </svg>
      <div>{children}</div>
    </div>
  );
}

// ─── Onglet 1 : Connexion au dépôt ───────────────────────────────────────────

function TabConnexion({ distro }) {
  const gpgCmd = `curl -fsSL ${REPO_URL}/repos/depot.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/depot-interne.gpg`;
  const addSourceCmd = `echo "deb [signed-by=/etc/apt/trusted.gpg.d/depot-interne.gpg] ${REPO_URL}/repos ${distro} main" \\
  | sudo tee /etc/apt/sources.list.d/depot-interne.list`;

  const fullScript = `#!/bin/bash
# Configuration du dépôt APT interne
# Exécuter en tant que root ou avec sudo

# 1. Importer la clé GPG de signature
curl -fsSL ${REPO_URL}/repos/depot.gpg | \\
  sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/depot-interne.gpg

# 2. Ajouter le dépôt interne
echo "deb [signed-by=/etc/apt/trusted.gpg.d/depot-interne.gpg] \\
  ${REPO_URL}/repos ${distro} main" | \\
  sudo tee /etc/apt/sources.list.d/depot-interne.list

# 3. Mettre à jour
sudo apt update

echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent la machine au dépôt APT interne et permettent d'installer
        les paquets validés. La clé GPG garantit l'authenticité des paquets.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Importer la clé GPG du dépôt">
          <p className="text-sm text-gray-600">
            Permet à APT de vérifier la signature de chaque paquet téléchargé.
          </p>
          <CodeBlock code={gpgCmd} label="bash" />
        </Step>

        <Step number="2" title="Ajouter le dépôt aux sources APT">
          <p className="text-sm text-gray-600">
            Déclare le dépôt interne comme source de paquets pour cette machine.
          </p>
          <CodeBlock code={addSourceCmd} label="bash" />
          <p className="text-xs text-gray-400">
            Fichier créé : <code className="bg-gray-100 px-1 rounded">/etc/apt/sources.list.d/depot-interne.list</code>
          </p>
        </Step>

        <Step number="3" title="Mettre à jour la liste des paquets">
          <CodeBlock code="sudo apt update" label="bash" />
        </Step>

        <Step number="4" title="Installer un paquet">
          <p className="text-sm text-gray-600">
            Une fois le dépôt configuré, l'installation se fait normalement.
          </p>
          <CodeBlock code="sudo apt install <nom-du-paquet>" label="bash" />
        </Step>
      </div>

      {/* Script complet */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
          <span className="text-xs text-gray-400">Pour automatiser la configuration</span>
        </div>
        <CodeBlock code={fullScript} label="setup-depot.sh" />
      </div>

      {/* Vérification */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Vérifier la configuration</h2>
        <div className="space-y-2">
          <CodeBlock
            code={`# Vérifier que le dépôt est reconnu\napt-cache policy | grep ${REPO_HOST}`}
            label="bash"
          />
          <CodeBlock
            code={`# Rechercher un paquet\napt-cache search <nom>`}
            label="bash"
          />
        </div>
      </div>

      <InfoBox type="warning">
        <p className="font-medium">Accès réseau requis</p>
        <p className="mt-0.5">
          La machine doit pouvoir atteindre{" "}
          <code className="bg-amber-100 px-1 rounded font-mono text-xs">{REPO_URL}</code>{" "}
          sur le réseau interne. Aucune connexion internet n'est nécessaire.
        </p>
      </InfoBox>
    </div>
  );
}

// ─── Onglet 2 : Isolation réseau ─────────────────────────────────────────────

function TabIsolation({ distro }) {
  const disableSources = `# Désactiver les sources publiques Ubuntu/Debian
# Le fichier est conservé (backup) pour pouvoir revenir en arrière si besoin

sudo mv /etc/apt/sources.list /etc/apt/sources.list.backup

# Supprimer les autres sources tierces éventuelles
sudo find /etc/apt/sources.list.d/ \\
  -name "*.list" -o -name "*.sources" | \\
  grep -v depot-interne | \\
  xargs sudo rm -f

# Vérifier qu'il ne reste que le dépôt interne
apt-cache policy`;

  const checkSources = `# Lister toutes les sources APT actives
grep -r "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null

# Résultat attendu : une seule ligne pointant vers votre dépôt interne`;

  const ufwRules = `# Option A — Bloquer les dépôts publics connus avec UFW
# (Ne bloque que les dépôts, laisse le reste du trafic intact)

# Bloquer les dépôts Ubuntu
sudo ufw deny out to archive.ubuntu.com
sudo ufw deny out to security.ubuntu.com
sudo ufw deny out to ports.ubuntu.com
sudo ufw deny out to extras.ubuntu.com

# Bloquer les dépôts Debian
sudo ufw deny out to deb.debian.org
sudo ufw deny out to security.debian.org
sudo ufw deny out to ftp.debian.org

sudo ufw enable
sudo ufw status verbose`;

  const iptablesRules = `# Option B — Bloquer avec iptables (si UFW non disponible)
# Résoudre les IP des dépôts publics puis les bloquer

for host in archive.ubuntu.com security.ubuntu.com deb.debian.org security.debian.org; do
  ip=$(dig +short "$host" | head -1)
  [ -n "$ip" ] && sudo iptables -A OUTPUT -d "$ip" -p tcp --dport 80 -j DROP
  [ -n "$ip" ] && sudo iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j DROP
done

# Rendre persistant (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save`;

  const testIsolation = `# Tester que les dépôts publics sont bien inaccessibles
curl -v --max-time 5 http://archive.ubuntu.com/ubuntu/ 2>&1 | grep -E "connect|refused|timed"
# Résultat attendu : "Connection refused" ou "timed out"

# Tester que le dépôt interne est toujours accessible
curl -v --max-time 5 ${REPO_URL}/repos/depot.gpg 2>&1 | grep -E "200|OK"
# Résultat attendu : "200 OK"`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="danger">
        <p className="font-medium">Étape critique — À faire après la connexion au dépôt interne</p>
        <p className="mt-1">
          Ces commandes suppriment les sources internet publiques. Assurez-vous que le dépôt interne
          est correctement configuré (onglet <strong>Connexion au dépôt</strong>) avant de les exécuter.
        </p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">

        <Step number="1" title="Désactiver les sources APT publiques" warning>
          <p className="text-sm text-gray-600">
            Supprime toutes les références aux dépôts internet (<code className="bg-gray-100 px-1 rounded text-xs">/etc/apt/sources.list</code>{" "}
            et <code className="bg-gray-100 px-1 rounded text-xs">/etc/apt/sources.list.d/</code>).
            Le fichier original est conservé en <code className="bg-gray-100 px-1 rounded text-xs">.backup</code>.
          </p>
          <CodeBlock code={disableSources} label="bash" />
        </Step>

        <Step number="2" title="Vérifier qu'il ne reste qu'une seule source">
          <p className="text-sm text-gray-600">
            Contrôlez que seul le dépôt interne est déclaré.
          </p>
          <CodeBlock code={checkSources} label="bash" />
          <InfoBox type="success">
            Si la commande retourne uniquement une ligne avec l'adresse de votre dépôt interne,
            la configuration est correcte.
          </InfoBox>
        </Step>

        <Step number="3" title="Bloquer les dépôts publics au niveau firewall">
          <p className="text-sm text-gray-600">
            Double protection : même si une source publique est réintroduite par erreur,
            le réseau la bloquera. Choisissez l'option adaptée à votre système.
          </p>

          <div className="space-y-2">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Option A — UFW (recommandé Ubuntu)</p>
            <CodeBlock code={ufwRules} label="bash" />
          </div>

          <div className="space-y-2">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Option B — iptables (universel)</p>
            <CodeBlock code={iptablesRules} label="bash" />
          </div>

          <InfoBox type="info">
            <p className="font-medium">Recommandation entreprise</p>
            <p className="mt-0.5">
              Le blocage firewall est idéalement géré au niveau du réseau (pare-feu périmétrique,
              VLAN, proxy Squid) plutôt que sur chaque machine individuellement.
              Les règles ci-dessus servent de défense en profondeur sur les machines elles-mêmes.
            </p>
          </InfoBox>
        </Step>

        <Step number="4" title="Tester l'isolation">
          <p className="text-sm text-gray-600">
            Vérifiez que les dépôts publics sont inaccessibles et que le dépôt interne répond.
          </p>
          <CodeBlock code={testIsolation} label="bash" />
        </Step>
      </div>

      {/* Script complet isolation */}
      <div className="space-y-3">
        <h2 className="text-base font-semibold text-gray-900">Script d'isolation complet</h2>
        <CodeBlock
          label="isoler-machine.sh"
          code={`#!/bin/bash
# Isolation réseau APT — supprime les sources publiques et bloque les dépôts internet
# PRÉREQUIS : le dépôt interne doit être configuré avant d'exécuter ce script

set -e

echo "[1/3] Désactivation des sources publiques..."
sudo mv /etc/apt/sources.list /etc/apt/sources.list.backup 2>/dev/null || true
sudo find /etc/apt/sources.list.d/ \\
  -name "*.list" -o -name "*.sources" | \\
  grep -v depot-interne | xargs sudo rm -f 2>/dev/null || true

echo "[2/3] Application des règles UFW..."
for host in archive.ubuntu.com security.ubuntu.com deb.debian.org security.debian.org ports.ubuntu.com; do
  sudo ufw deny out to "$host" 2>/dev/null || true
done
sudo ufw --force enable

echo "[3/3] Vérification..."
sudo apt update && echo "OK — dépôt interne accessible"

echo "Isolation terminée."
`}
        />
      </div>
    </div>
  );
}

// ─── Onglet 3 : Mises à jour automatiques ────────────────────────────────────

function TabUnattended({ distro }) {
  const installCmd = `sudo apt install unattended-upgrades apt-listchanges -y`;

  const confUnattended = `# /etc/apt/apt.conf.d/50unattended-upgrades
# Générer ce fichier avec :
#   sudo dpkg-reconfigure -plow unattended-upgrades
# Puis l'adapter manuellement :

Unattended-Upgrade::Allowed-Origins {
    // Format : "Origine:Distribution"
    // Trouver les valeurs avec : apt-cache policy
    // Exemple pour un dépôt interne signé avec reprepro :
    "*:${distro}";
};

// Ne pas redémarrer automatiquement (recommandé en production)
Unattended-Upgrade::Automatic-Reboot "false";

// Planifier un redémarrage si nécessaire (hors heures de bureau)
// Unattended-Upgrade::Automatic-Reboot-Time "03:30";

// Supprimer les paquets obsolètes
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Réparer automatiquement les installations interrompues
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Envoyer les rapports par email (si postfix configuré)
// Unattended-Upgrade::Mail "admin@exemple.interne";
// Unattended-Upgrade::MailReport "on-change";`;

  const confAutoUpgrade = `# /etc/apt/apt.conf.d/20auto-upgrades
# Fréquence des opérations automatiques (en jours)

APT::Periodic::Update-Package-Lists "1";       // apt update chaque jour
APT::Periodic::Download-Upgradeable-Packages "1"; // télécharger les MAJ
APT::Periodic::Unattended-Upgrade "1";         // appliquer les MAJ de sécurité
APT::Periodic::AutocleanInterval "7";          // nettoyer le cache tous les 7 jours`;

  const findOrigin = `# Trouver l'origine exacte de votre dépôt interne pour Allowed-Origins
# (à exécuter APRÈS avoir configuré le dépôt interne)

apt-cache policy | grep -A3 "depot-interne\\|${REPO_HOST}"

# Chercher les lignes "release" qui contiennent o= (origin) et n= (suite/codename)
# Exemple de sortie :
#   release v=12,o=MonDepot,a=bookworm,n=bookworm,l=MonDepot,c=main
# → Allowed-Origins = "MonDepot:bookworm"`;

  const enableService = `# Activer et démarrer le service
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades
sudo systemctl status unattended-upgrades`;

  const testCmd = `# Simuler une mise à jour automatique (dry-run, aucun changement appliqué)
sudo unattended-upgrades --dry-run --debug 2>&1 | tail -30

# Forcer une exécution immédiate (applique réellement les MAJ)
sudo unattended-upgrades --debug

# Consulter les logs
sudo cat /var/log/unattended-upgrades/unattended-upgrades.log`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        <p className="font-medium">Principe</p>
        <p className="mt-1">
          <code className="bg-blue-100 px-1 rounded text-xs">unattended-upgrades</code> applique
          automatiquement les mises à jour depuis le dépôt interne,
          sans intervention humaine. Seules les sources déclarées dans{" "}
          <code className="bg-blue-100 px-1 rounded text-xs">Allowed-Origins</code> sont utilisées —
          le dépôt interne est ainsi la seule source de mise à jour.
        </p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">

        <Step number="1" title="Installer unattended-upgrades">
          <CodeBlock code={installCmd} label="bash" />
        </Step>

        <Step number="2" title="Trouver l'origine de votre dépôt interne">
          <p className="text-sm text-gray-600">
            La valeur <code className="bg-gray-100 px-1 rounded text-xs">Allowed-Origins</code> doit
            correspondre exactement au champ <strong>Origin</strong> du fichier <code className="bg-gray-100 px-1 rounded text-xs">Release</code> du dépôt.
          </p>
          <CodeBlock code={findOrigin} label="bash" />
          <InfoBox type="info">
            Si aucune valeur d'origine n'est définie dans reprepro (champ <code className="bg-blue-100 px-1 rounded text-xs">Origin</code>{" "}
            absent de <code className="bg-blue-100 px-1 rounded text-xs">conf/distributions</code>),
            utilisez le caractère joker <code className="bg-blue-100 px-1 rounded text-xs">*:{distro}</code> qui correspond à toute origine avec cette distribution.
          </InfoBox>
        </Step>

        <Step number="3" title="Configurer les origines autorisées">
          <p className="text-sm text-gray-600">
            Créer ou éditer <code className="bg-gray-100 px-1 rounded text-xs">/etc/apt/apt.conf.d/50unattended-upgrades</code>.
          </p>
          <CodeBlock code={confUnattended} label="/etc/apt/apt.conf.d/50unattended-upgrades" />
        </Step>

        <Step number="4" title="Activer les mises à jour périodiques">
          <p className="text-sm text-gray-600">
            Créer <code className="bg-gray-100 px-1 rounded text-xs">/etc/apt/apt.conf.d/20auto-upgrades</code>.
          </p>
          <CodeBlock code={confAutoUpgrade} label="/etc/apt/apt.conf.d/20auto-upgrades" />
        </Step>

        <Step number="5" title="Activer le service systemd">
          <CodeBlock code={enableService} label="bash" />
        </Step>

        <Step number="6" title="Tester la configuration">
          <p className="text-sm text-gray-600">
            Vérifiez le comportement avant de déployer sur un parc de machines.
          </p>
          <CodeBlock code={testCmd} label="bash" />
          <InfoBox type="success">
            Si le dry-run affiche les paquets à mettre à jour depuis votre dépôt interne
            (sans mentionner archive.ubuntu.com ou deb.debian.org), la configuration est correcte.
          </InfoBox>
        </Step>
      </div>

      {/* Bonnes pratiques */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-gray-800">Bonnes pratiques en production</h2>
        <div className="space-y-3 text-sm text-gray-600">
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Jamais de redémarrage automatique</strong> sur les serveurs de production.
              Planifier une fenêtre de maintenance.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Tester d'abord</strong> les mises à jour sur un serveur de staging avant
              de les promouvoir vers la distribution de production dans repod.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Surveiller les logs</strong> dans{" "}
              <code className="bg-gray-100 px-1 rounded text-xs">/var/log/unattended-upgrades/</code>.
              Configurer une alerte si des erreurs apparaissent.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-blue-500 font-bold shrink-0">→</span>
            <p><strong>Serveurs critiques (PKI, BDD, load balancer)</strong> : désactiver les MAJ
              automatiques (<code className="bg-gray-100 px-1 rounded text-xs">Unattended-Upgrade "0"</code>)
              et appliquer manuellement après validation.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Onglet : Connexion RPM (DNF/YUM — AlmaLinux, Rocky, CentOS, Oracle, Fedora) ──

function TabConnexionRPM({ distro }) {
  const repoFile = `[depot-interne]
name=Dépôt interne Repod — ${distro}
baseurl=${RPM_REPO_URL}/${distro}/x86_64/
enabled=1
gpgcheck=0`;

  const fullScript = `#!/bin/bash
# Configuration du dépôt RPM interne — ${distro}

# 1. Créer le fichier de dépôt
cat > /etc/yum.repos.d/depot-interne.repo << 'EOF'
${repoFile}
EOF

# 2. Vider le cache DNF
dnf clean all

# 3. Vérifier la configuration
dnf repolist

echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent la machine au dépôt RPM interne via un fichier <code className="bg-blue-100 px-1 rounded text-xs">.repo</code>.
        DNF/YUM téléchargera les paquets directement depuis le serveur Repod.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Créer le fichier de dépôt">
          <p className="text-sm text-gray-600">
            Crée <code className="bg-gray-100 px-1 rounded text-xs">/etc/yum.repos.d/depot-interne.repo</code> pointant
            vers le dépôt Repod pour <strong>{distro}</strong>.
          </p>
          <CodeBlock code={`cat > /etc/yum.repos.d/depot-interne.repo << 'EOF'\n${repoFile}\nEOF`} label="bash" />
        </Step>

        <Step number="2" title="Vider le cache et vérifier">
          <CodeBlock code={`dnf clean all\ndnf repolist`} label="bash" />
        </Step>

        <Step number="3" title="Installer un paquet">
          <CodeBlock code="dnf install <nom-du-paquet>" label="bash" />
        </Step>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
        </div>
        <CodeBlock code={fullScript} label="setup-depot-rpm.sh" />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Vérifier la configuration</h2>
        <CodeBlock code={`# Lister les dépôts actifs\ndnf repolist enabled\n\n# Rechercher un paquet\ndnf search <nom>`} label="bash" />
      </div>
    </div>
  );
}

// ─── Onglet : Connexion Zypper (openSUSE) ────────────────────────────────────

function TabConnexionZypper({ distro }) {
  const fullScript = `#!/bin/bash
# Configuration du dépôt RPM interne — ${distro} (Zypper)

# 1. Ajouter le dépôt
zypper addrepo --no-gpgcheck --refresh \\
  "${RPM_REPO_URL}/${distro}/x86_64/" \\
  depot-interne

# 2. Rafraîchir les métadonnées
zypper refresh depot-interne

echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent la machine openSUSE au dépôt RPM interne via <code className="bg-blue-100 px-1 rounded text-xs">zypper addrepo</code>.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Ajouter le dépôt Zypper">
          <CodeBlock
            code={`zypper addrepo --no-gpgcheck --refresh \\\n  "${RPM_REPO_URL}/${distro}/x86_64/" \\\n  depot-interne`}
            label="bash"
          />
        </Step>

        <Step number="2" title="Rafraîchir et vérifier">
          <CodeBlock code={`zypper refresh depot-interne\nzypper repos`} label="bash" />
        </Step>

        <Step number="3" title="Installer un paquet">
          <CodeBlock code="zypper install <nom-du-paquet>" label="bash" />
        </Step>
      </div>

      <div className="space-y-3">
        <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
        <CodeBlock code={fullScript} label="setup-depot-zypper.sh" />
      </div>
    </div>
  );
}

// ─── Onglet : Connexion APK (Alpine Linux) ───────────────────────────────────

function TabConnexionAPK({ distro }) {
  const repoLine  = `${REPO_URL}/apk/${distro}/main`;
  const addRepo   = `echo "${repoLine}" >> /etc/apk/repositories\napk update`;
  const fullScript = `#!/bin/sh
# Configuration du dépôt APK interne — ${distro}

# 1. Ajouter le dépôt privé Repod
echo "${repoLine}" >> /etc/apk/repositories

# 2. (Optionnel) Supprimer les miroirs publics pour l'isolation totale
# sed -i '/dl-cdn.alpinelinux.org/d' /etc/apk/repositories

# 3. Mettre à jour l'index
apk update

# 4. Vérifier
apk info --available | head -5
echo "Dépôt interne configuré avec succès."`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        Ces étapes connectent un conteneur ou une machine Alpine Linux au dépôt APK interne Repod.
        L'index <strong>APKINDEX.tar.gz</strong> est généré automatiquement à chaque upload de paquet <code className="bg-blue-100 px-1 rounded text-xs">.apk</code>.
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Ajouter le dépôt APK interne">
          <p className="text-sm text-gray-600">
            Ajoute la ligne de dépôt dans <code className="bg-gray-100 px-1 rounded text-xs">/etc/apk/repositories</code>.
          </p>
          <CodeBlock code={addRepo} label="sh" />
          <p className="text-xs text-gray-400">
            URL du dépôt : <code className="bg-gray-100 px-1 rounded">{repoLine}</code>
          </p>
        </Step>

        <Step number="2" title="(Optionnel) Isolation — supprimer les miroirs publics">
          <p className="text-sm text-gray-600">
            Pour n'utiliser que le dépôt interne, supprimez les miroirs Alpine officiels.
          </p>
          <CodeBlock
            code={`# Voir les sources actives\ncat /etc/apk/repositories\n\n# Supprimer les miroirs publics Alpine (dl-cdn.alpinelinux.org)\nsed -i '/dl-cdn.alpinelinux.org/d' /etc/apk/repositories\n\napk update`}
            label="sh"
          />
        </Step>

        <Step number="3" title="Mettre à jour et installer un paquet">
          <CodeBlock code={`apk update\napk add <nom-du-paquet>`} label="sh" />
        </Step>

        <Step number="4" title="Vérifier la configuration">
          <CodeBlock
            code={`# Lister les sources actives\ncat /etc/apk/repositories\n\n# Vérifier l'index du dépôt privé\ncurl -s ${REPO_URL}/apk/${distro}/main/x86_64/APKINDEX.tar.gz | tar -xz -O APKINDEX | head -20`}
            label="sh"
          />
        </Step>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Script d'installation complet</h2>
        </div>
        <CodeBlock code={fullScript} label="setup-depot-apk.sh" />
      </div>

      {/* Docker — ajout du dépôt dans un Dockerfile */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Utilisation dans un Dockerfile</h2>
        <CodeBlock
          label="Dockerfile"
          code={`FROM alpine:${distro.replace("alpine", "").replace(/^3\./, "3.")}

# Ajouter le dépôt privé Repod
RUN echo "${repoLine}" >> /etc/apk/repositories \\
 && apk update \\
 && apk add --no-cache <votre-paquet>
`}
        />
      </div>

      <InfoBox type="warning">
        <p className="font-medium">Accès réseau requis</p>
        <p className="mt-0.5">
          Le conteneur Alpine doit pouvoir atteindre{" "}
          <code className="bg-amber-100 px-1 rounded font-mono text-xs">{REPO_URL}</code>{" "}
          sur le réseau interne. En production, configurez le proxy ou les règles réseau en conséquence.
        </p>
      </InfoBox>
    </div>
  );
}

// ─── Onglet : Isolation réseau RPM ───────────────────────────────────────────

function TabIsolationRPM({ distro, family }) {
  const disableDnf = `# Désactiver tous les dépôts publics DNF
# (sauvegarde dans /etc/yum.repos.d/*.repo.backup)

for f in /etc/yum.repos.d/*.repo; do
  [[ "$f" == *depot-interne* ]] && continue
  mv "$f" "$f.backup"
done

# Vérifier qu'il ne reste que le dépôt interne
dnf repolist`;

  const disableZypper = `# Désactiver tous les dépôts Zypper publics

zypper repos | awk 'NR>2 && !/depot-interne/{print $3}' | while read alias; do
  zypper removerepo "$alias"
done

# Vérifier
zypper repos`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="danger">
        <p className="font-medium">Étape critique — À faire après la connexion au dépôt interne</p>
        <p className="mt-1">Assurez-vous que le dépôt interne est configuré avant d'exécuter ces commandes.</p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Désactiver les dépôts publics" warning>
          <CodeBlock
            code={family === "zypper" ? disableZypper : disableDnf}
            label="bash"
          />
        </Step>

        <Step number="2" title="Tester l'isolation">
          <CodeBlock
            code={`# Vérifier que le dépôt interne répond\ncurl -s --max-time 5 ${RPM_REPO_URL}/${distro}/x86_64/repodata/repomd.xml | grep -c "<repomd>" && echo "OK"`}
            label="bash"
          />
        </Step>
      </div>
    </div>
  );
}

// ─── Onglet : Mises à jour automatiques RPM ──────────────────────────────────

function TabUnattendedRPM({ family }) {
  const dnfAutomatic = `# Installer dnf-automatic
dnf install dnf-automatic -y

# Configurer /etc/dnf/automatic.conf
# Modifier la section [commands] :
#   apply_updates = yes   (pour appliquer automatiquement)
#   upgrade_type = security  (sécurité seulement) ou "default" (tout)

# Activer le timer systemd
systemctl enable --now dnf-automatic-install.timer

# Vérifier
systemctl status dnf-automatic-install.timer`;

  const zypperAuto = `# Installer zypper-download et le planificateur
zypper install yast2-online-update-configuration -y

# Via cron — exemple : mise à jour chaque nuit à 02:00
echo "0 2 * * * root zypper -n patch --category security" > /etc/cron.d/zypper-security

# OU via systemd timer — créer /etc/systemd/system/zypper-update.service
cat > /etc/systemd/system/zypper-update.service << 'EOF'
[Unit]
Description=Mise à jour automatique Zypper

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper -n patch --category security
EOF

cat > /etc/systemd/system/zypper-update.timer << 'EOF'
[Unit]
Description=Zypper update quotidien

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl enable --now zypper-update.timer`;

  return (
    <div className="space-y-8 p-6">
      <InfoBox type="info">
        <p className="font-medium">Mises à jour automatiques — {family === "zypper" ? "Zypper (openSUSE)" : "dnf-automatic (RHEL/Fedora)"}</p>
        <p className="mt-1">
          Seules les mises à jour provenant du dépôt interne seront appliquées.
          Configurez <strong>upgrade_type = security</strong> pour les serveurs de production.
        </p>
      </InfoBox>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-8">
        <Step number="1" title="Installer le gestionnaire de mises à jour automatiques">
          <CodeBlock
            code={family === "zypper" ? zypperAuto : dnfAutomatic}
            label="bash"
          />
        </Step>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-gray-800">Bonnes pratiques en production</h2>
        <div className="space-y-3 text-sm text-gray-600">
          {[
            "Tester les mises à jour sur un serveur de staging avant de les appliquer en production.",
            "Désactiver les redémarrages automatiques sur les serveurs critiques.",
            "Surveiller les logs dans /var/log/dnf.log ou journalctl -u dnf-automatic.",
          ].map((tip, i) => (
            <div key={i} className="flex gap-3">
              <span className="text-blue-500 font-bold shrink-0">→</span>
              <p>{tip}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

const DISTROS = [
  // APT (Debian/Ubuntu)
  { id: "jammy",           label: "Ubuntu 22.04 (Jammy)",    family: "apt" },
  { id: "noble",           label: "Ubuntu 24.04 (Noble)",    family: "apt" },
  { id: "bookworm",        label: "Debian 12 (Bookworm)",    family: "apt" },
  { id: "bullseye",        label: "Debian 11 (Bullseye)",    family: "apt" },
  // RPM — DNF (RHEL family)
  { id: "almalinux9",      label: "AlmaLinux 9",             family: "dnf" },
  { id: "almalinux8",      label: "AlmaLinux 8",             family: "dnf" },
  { id: "rocky9",          label: "Rocky Linux 9",           family: "dnf" },
  { id: "rocky8",          label: "Rocky Linux 8",           family: "dnf" },
  { id: "centos-stream9",  label: "CentOS Stream 9",         family: "dnf" },
  { id: "oraclelinux9",    label: "Oracle Linux 9",          family: "dnf" },
  { id: "oraclelinux8",    label: "Oracle Linux 8",          family: "dnf" },
  { id: "fedora",          label: "Fedora",                  family: "dnf" },
  // RPM — Zypper (openSUSE)
  { id: "opensuse-leap-15.6",   label: "openSUSE Leap 15.6",    family: "zypper" },
  { id: "opensuse-tumbleweed",  label: "openSUSE Tumbleweed",   family: "zypper" },
  // APK — Alpine Linux
  { id: "alpine3.21", label: "Alpine Linux 3.21", family: "apk" },
  { id: "alpine3.20", label: "Alpine Linux 3.20", family: "apk" },
  { id: "alpine3.19", label: "Alpine Linux 3.19", family: "apk" },
  { id: "alpine3.18", label: "Alpine Linux 3.18", family: "apk" },
];

const TABS_APT = [
  { id: "connexion",  label: "1. Connexion au dépôt",       icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { id: "isolation",  label: "2. Isolation réseau",          icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" },
  { id: "unattended", label: "3. Mises à jour automatiques", icon: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" },
];
const TABS_RPM = [
  { id: "connexion",  label: "1. Connexion au dépôt",       icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { id: "isolation",  label: "2. Isolation réseau",          icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" },
  { id: "unattended", label: "3. Mises à jour automatiques", icon: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" },
];

const TABS_APK = [
  { id: "connexion", label: "1. Connexion au dépôt", icon: "M13 10V3L4 14h7v7l9-11h-7z" },
];

const FAMILY_LABEL = { apt: "DEB · Debian / Ubuntu", dnf: "RPM · RHEL / Fedora", zypper: "RPM · openSUSE", apk: "APK · Alpine Linux" };
const FAMILY_COLOR = { apt: "text-blue-600", dnf: "text-orange-600", zypper: "text-teal-600", apk: "text-emerald-600" };

export default function ClientSetupPage() {
  const [distroId, setDistroId] = useState("jammy");
  const [activeTab, setActiveTab] = useState("connexion");

  const distroObj = DISTROS.find((d) => d.id === distroId) || DISTROS[0];
  const family = distroObj.family;
  const isRpm = family === "dnf" || family === "zypper";
  const isApk = family === "apk";
  const TABS = isApk ? TABS_APK : isRpm ? TABS_RPM : TABS_APT;

  const handleDistroChange = (id) => {
    setDistroId(id);
    setActiveTab("connexion");
  };

  // Group distros by family for display
  const aptDistros    = DISTROS.filter((d) => d.family === "apt");
  const dnfDistros    = DISTROS.filter((d) => d.family === "dnf");
  const zypperDistros = DISTROS.filter((d) => d.family === "zypper");
  const apkDistros    = DISTROS.filter((d) => d.family === "apk");

  return (
    <div className="p-6 space-y-6">
      {/* En-tête */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Configuration des machines clientes</h1>
        <p className="text-sm text-gray-500 mt-1">
          Guide complet pour connecter une machine au dépôt interne Repod — APT (Debian/Ubuntu), DNF (RHEL/Fedora), Zypper (openSUSE) ou APK (Alpine Linux).
        </p>
      </div>

      {/* Sélecteur de distribution */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Distribution cible — les scripts s'adaptent automatiquement
          </p>
          <span className={`text-xs font-semibold uppercase tracking-wider ${FAMILY_COLOR[family]}`}>
            {FAMILY_LABEL[family]}
          </span>
        </div>
        <select
          value={distroId}
          onChange={(e) => handleDistroChange(e.target.value)}
          className="w-full px-3 py-2 rounded-lg text-sm font-medium border border-gray-200 text-gray-700 bg-white cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
        >
          <optgroup label="DEB · Debian / Ubuntu">
            {aptDistros.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
          </optgroup>
          <optgroup label="RPM · RHEL / Fedora (DNF)">
            {dnfDistros.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
          </optgroup>
          <optgroup label="RPM · openSUSE (Zypper)">
            {zypperDistros.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
          </optgroup>
          <optgroup label="APK · Alpine Linux">
            {apkDistros.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
          </optgroup>
        </select>
      </div>

      {/* Onglets */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-1">
          {TABS.map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? `border-${isApk ? "emerald" : isRpm ? (family === "zypper" ? "teal" : "orange") : "blue"}-600 text-${isApk ? "emerald" : isRpm ? (family === "zypper" ? "teal" : "orange") : "blue"}-600`
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Contenu — APT */}
      {!isRpm && activeTab === "connexion"  && <TabConnexion  distro={distroId} />}
      {!isRpm && activeTab === "isolation"  && <TabIsolation  distro={distroId} />}
      {!isRpm && activeTab === "unattended" && <TabUnattended distro={distroId} />}

      {/* Contenu — RPM (DNF) */}
      {family === "dnf" && activeTab === "connexion"  && <TabConnexionRPM  distro={distroId} />}
      {family === "dnf" && activeTab === "isolation"  && <TabIsolationRPM  distro={distroId} family="dnf" />}
      {family === "dnf" && activeTab === "unattended" && <TabUnattendedRPM family="dnf" />}

      {/* Contenu — RPM (Zypper) */}
      {family === "zypper" && activeTab === "connexion"  && <TabConnexionZypper  distro={distroId} />}
      {family === "zypper" && activeTab === "isolation"  && <TabIsolationRPM     distro={distroId} family="zypper" />}
      {family === "zypper" && activeTab === "unattended" && <TabUnattendedRPM    family="zypper" />}

      {/* Contenu — APK (Alpine Linux) */}
      {isApk && activeTab === "connexion" && <TabConnexionAPK distro={distroId} />}
    </div>
  );
}
