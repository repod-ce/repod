import { useEffect, useState } from "react";
import { getHealth } from "../api";

/**
 * Retourne l'édition active de Repod ("community" | "enterprise") en lisant
 * checks.info.license depuis /health (endpoint public, sans auth).
 * Tant que la valeur n'est pas connue, isEnterprise vaut false par défaut
 * (les sections verrouillées restent verrouillées pendant le chargement).
 */
export function useEdition() {
  const [edition, setEdition] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((data) => {
        if (cancelled) return;
        const license = data?.checks?.info?.license ?? data?.checks?.non_critical?.license;
        setEdition(license?.edition || "community");
      })
      .catch(() => {
        if (!cancelled) setEdition("community");
      });
    return () => { cancelled = true; };
  }, []);

  return {
    edition,
    isEnterprise: edition === "enterprise",
    loading: edition === null,
  };
}
