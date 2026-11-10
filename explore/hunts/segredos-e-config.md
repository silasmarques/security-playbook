# Caça: segredos e configuração

> A pergunta: **existe chave onde não devia, ou porta aberta por configuração?** A maioria dos incidentes reais começa aqui, não em exploit sofisticado. Norma: [secrets-config](../../core/secrets-config.md), [dependencies-supply-chain](../../core/dependencies-supply-chain.md), [frontend-security](../../core/frontend-security.md). Seguir o [protocolo de evidência](../PROTOCOLO.md).

## Inventário primeiro

Liste todo segredo que o sistema usa e ONDE vive cada um; todo ambiente (local, staging, produção) e o que difere entre eles; todo arquivo de configuração de host, CI e plataforma.

## Hipóteses

### H1 — Segredo no repositório
- **Procurar:** regra `C-SECRET-HARDCODED`; scripts de manutenção, seeds e arquivos de teste costumam ser os piores. O **histórico** do git só um secret scanner cobre (gitleaks com histórico completo).
- **Provar:** o valor tem formato de chave real e funciona. *Não* testar a chave contra o serviço em produção além do mínimo; ao confirmar, a ação é **rotacionar** — remover do código não basta.
- **Falso positivo:** chave pública por desenho (chave publicável/anon), valor de exemplo, fixture de teste.

### H2 — Credencial administrativa ao alcance do usuário
- **Procurar:** regra `C-SECRET-IN-BUNDLE`; variável de build com prefixo público; chave de serviço em app mobile ou em código de cliente.
- **Provar:** gerar o build e buscar o valor nos arquivos publicados (o artefato, não o código-fonte).

### H3 — Segredo com valor padrão, ou env que falta em silêncio
- **Procurar:** regra `C-ENV-FALLBACK`; leitura de env sem checar ausência.
- **Provar:** subir sem a variável. Confirmado se o sistema inicia e usa o valor do código.

### H4 — Configuração que abre a porta
- **Procurar:** CORS (`C-CORS-WILDCARD`), ausência de CSP (`CFG-NO-CSP`), verificação de token desligada (`CFG-VERIFY-JWT-OFF`), bucket público (`DB-BUCKET-PUBLIC`), modo debug, mensagem de erro detalhada (`C-ERROR-LEAK`).
- **Provar:** olhar o que o ambiente **publicado** responde: os headers reais, o erro real. Config no repositório é intenção; a resposta do servidor é o fato.

### H5 — O que só existe no painel
- **Procurar:** não há o que procurar no repositório — e esse é o achado. Limites de autenticação, provedores habilitados, políticas de senha, chaves ativas e regras criadas à mão vivem na plataforma.
- **Provar:** conferir no painel e nos verificadores da própria plataforma. Registrar no `SECURITY-STATUS.md` que este item é verificado fora do repositório.

### H6 — Cadeia de suprimentos frouxa
- **Procurar:** sem lockfile (`CFG-NO-LOCKFILE`), workflow sem permissões mínimas (`CFG-WORKFLOW-PERMISSIONS`), action por tag (`CFG-ACTION-UNPINNED`), dependência recém-adicionada de origem duvidosa, instalador via `curl | bash`.
- **Provar:** são fatos de arquivo — a prova é o próprio arquivo. Para dependência nova: conferir no registro que o pacote existe, é o certo e é mantido.

### H7 — Dado sensível escapando por log ou por storage do navegador
- **Procurar:** regras `C-LOG-SENSITIVE`, `C-STORAGE-SECRET`.
- **Provar:** executar o fluxo e ler o log gerado / o storage do navegador.

### H8 — Segredo insubstituível com cópia única
- **Procurar:** chave de assinatura de app, chave de criptografia de dados já gravados. Onde estão as cópias?
- **Provar:** **abrir a segunda cópia e usá-la.** Ver o arquivo numa pasta "sincronizada" não prova que sincronizou.

## Correção

Segredo fora do código, lido por nome e sem padrão ([env.ts](../../kit/web/env.ts)) · CORS por allowlist ([cors.ts](../../kit/web/cors.ts)) · headers em toda resposta ([http.ts](../../kit/web/http.ts)) · logger com redação ([log.ts](../../kit/web/log.ts)) · inventário de segredos no `SECURITY-STATUS.md` do projeto.
