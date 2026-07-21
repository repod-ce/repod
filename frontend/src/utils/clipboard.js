// navigator.clipboard n'existe que dans un contexte sécurisé (HTTPS ou
// localhost) — sur un déploiement HTTP simple (le cas le plus courant pour
// un dépôt interne accédé par IP), navigator.clipboard est undefined et
// .writeText() lève une TypeError synchrone, jamais rattrapée par les
// gestionnaires .then()/.catch() des appelants : le bouton "Copier" échouait
// silencieusement (aucun toast, juste une erreur console) sur toute page
// servie en HTTP pur. copyToClipboard() retombe sur
// document.execCommand("copy") (obsolète mais toujours supporté) dans ce cas.
export async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    const ok = document.execCommand("copy");
    if (!ok) throw new Error("execCommand copy failed");
  } finally {
    document.body.removeChild(textarea);
  }
}
