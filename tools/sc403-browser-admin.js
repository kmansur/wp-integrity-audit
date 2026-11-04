/*
 * Auditoria e revogação pontual de service worker associado ao SC 4.3.24.
 * Execução MANUAL no console de navegador, na origem do WordPress afetado.
 * Nunca envia dados para terceiros e não limpa indiscriminadamente Storage.
 *
 * Referência técnica: ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later).
 * Implementação independente do WP Integrity Audit.
 *
 * INSTRUÇÕES:
 * 1. Preserve evidências do navegador antes de qualquer revogação.
 * 2. Abra uma aba do mesmo domínio, preferencialmente no contexto administrativo
 *    autorizado, após isolamento/recuperação do servidor.
 * 3. Cole este código integralmente no console do navegador.
 * 4. Informe o endpoint numérico "endpoint_sw" de sc403-identifiers.json.
 * 5. Escolha somente INVENTARIAR ou REVOGAR o registro exato.
 *
 * LIMITAÇÃO: unregister() NÃO encerra imediatamente abas controladas nem
 * comprova remoção de payload, cache, credenciais ou todas as sessões.
 */
(async () => {
  "use strict";
  const resultado = {
    origem: location.origin,
    status: "NAO_EXECUTADO",
    registros_compatíveis: 0,
    revogados: 0,
  };
  if (!("serviceWorker" in navigator) || !window.isSecureContext) {
    console.warn("Service workers indisponíveis neste contexto.");
    return;
  }
  const entrada = prompt("Informe o endpoint_sw numérico do relatório forense SC403:");
  if (entrada === null || !/^\d{8}$/.test(entrada)) {
    console.warn("Identificador inválido. Nenhuma alteração.");
    return;
  }
  const registros = await navigator.serviceWorker.getRegistrations();
  const alvos = registros.filter((reg) => {
    const worker = reg.active || reg.waiting || reg.installing;
    if (!worker) return false;
    try {
      const url = new URL(worker.scriptURL);
      return url.origin === location.origin && url.searchParams.get("p") === entrada;
    } catch (_erro) {
      return false;
    }
  });
  resultado.registros_compatíveis = alvos.length;
  console.table(alvos.map((reg) => ({
    scope: reg.scope,
    scriptURL: (reg.active || reg.waiting || reg.installing).scriptURL,
  })));
  if (alvos.length === 0) {
    resultado.status = "NENHUM_REGISTRO_CORRESPONDENTE";
    console.info(resultado);
    return;
  }
  const escolha = prompt(
    "Digite REVOGAR para cancelar SOMENTE os registros correspondentes; qualquer outra resposta apenas inventaria:"
  );
  if (escolha !== "REVOGAR") {
    resultado.status = "SOMENTE_INVENTARIO";
    console.info(resultado);
    return;
  }
  if (!confirm(
    "Confirma revogar " + alvos.length + " registro(s) SC nesta origem? Abas abertas podem continuar controladas."
  )) {
    resultado.status = "CANCELADO";
    console.info(resultado);
    return;
  }
  for (const registro of alvos) {
    try {
      if (await registro.unregister()) resultado.revogados += 1;
    } catch (_erro) {
      console.warn("Falha ao revogar um registro; investigar manualmente.");
    }
  }
  resultado.status = resultado.revogados === alvos.length
    ? "REVOGACAO_SOLICITADA" : "REVOGACAO_PARCIAL";
  console.info(resultado);
  console.warn(
    "Reabrir navegadores, invalidar sessões e credenciais, investigar cache/storage e executar nova auditoria. " +
    "Revogar o registro não garante erradicação do SC."
  );
})();
