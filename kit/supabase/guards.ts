// Guardas do prólogo de toda função (adaptador Supabase): acesso, rate limit
// e auditoria via RPC/tabela. Todas FAIL CLOSED: erro na checagem = negar.
// Norma: core/authorization.md R4/P1, core/api-security.md R2/P2,
// core/logging-monitoring.md R5/P2. Testes: kit/tests/guards.test.ts.

/** Forma mínima do client Supabase que as guardas usam — evita acoplar o kit a
 *  uma versão do SDK e deixa as guardas testáveis com um dublê. */
export interface RpcClient {
  rpc(fn: string, args?: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
}
export interface InsertClient {
  from(table: string): { insert(row: Record<string, unknown>): PromiseLike<{ error: unknown }> };
}

// #region requireAccess
/** ÚNICA implementação da checagem de acesso; toda função chama logo após
 *  autenticar. `true` = pode seguir. A RPC `check_user_access` roda com o token
 *  do chamador e decide por `auth.uid()` — a função não recebe o id por parâmetro. */
export async function requireAccess(client: RpcClient): Promise<boolean> {
  try {
    const { data, error } = await client.rpc("check_user_access");
    return !error && data === true; // estritamente `true`: null, "true", 1, [] → negado
  } catch {
    return false; // banco fora do ar NÃO vira "todo mundo passa"
  }
}
// #endregion requireAccess

// #region checkRateLimit
/** `true` = dentro do limite. Chamar ANTES do trabalho caro. O limite e a
 *  janela moram no banco (tabela rate_limits) e o contador é do `auth.uid()`
 *  do token — ver kit/supabase/sql/02_rate_limit.sql. */
export async function checkRateLimit(client: RpcClient, action: string): Promise<boolean> {
  try {
    const { data, error } = await client.rpc("check_and_increment", { _action: action });
    return !error && data === true;
  } catch {
    return false;
  }
}
// #endregion checkRateLimit

// #region writeAudit
/** Grava a trilha de auditoria com o client de SERVIÇO (a tabela nega tudo a
 *  usuários). LANÇA se o insert falhar: operação crítica sem trilha não segue. */
export async function writeAudit(
  serviceClient: InsertClient,
  entry: { userId: string; action: string; resource: string; requestId: string; meta?: Record<string, unknown> },
): Promise<void> {
  const { error } = await serviceClient.from("audit_log").insert({
    user_id: entry.userId, action: entry.action, resource: entry.resource,
    request_id: entry.requestId, meta: entry.meta ?? {},
  });
  if (error) throw new Error("falha ao gravar audit_log"); // o boundary loga o detalhe
}
// #endregion writeAudit
