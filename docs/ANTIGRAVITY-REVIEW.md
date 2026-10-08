# Revisão de Segurança - mcp-mikrotik

Abaixo estão os achados da auditoria de segurança independente solicitada, focada em bypass do write-guard e injeção residual, com respostas baseadas no checklist fornecido.

## 1. WRITE-GUARD
**Status:** Correto.
- **`guard.py` é o ÚNICO caminho de escrita?** Sim. Não há nenhuma chamada a `client.update()`, `add()` ou `remove()` diretamente em `server.py`. O único tool de escrita (`set_identity`) delega a execução para `guard.set_identity()`. O design força o uso da allowlist contida em `guard.py`.
- **Escrita bloqueada com `MIKROTIK_ALLOW_WRITE` desligado, mesmo com `confirm=true`?** Sim. A função `_require_allowed` valida se a escrita está habilitada antes de qualquer outra lógica e levanta `WriteDisabledError`.
- **Com `confirm=false`, o device NÃO é tocado?** Sim. A função retorna logo após montar o preview e `client.update()` não é chamado.

## 2. INJEÇÃO
**Status:** Correto.
- **A regex rejeita injeções (`8.8.8.8;/system reboot`, backticks, `$()`, etc.)?** Sim. As expressões regulares em `validation.py` (`_IPV4`, `_IPV6`, `_HOSTNAME`) utilizam âncoras estritas (`^` e `$`) e regras que não permitem espaços, ponto e vírgula ou backticks.
- **Outros parâmetros e estruturação?** Os parâmetros são processados e passados estruturados via `librouteros` (`**kwargs`). Isso elimina a possibilidade de injeção de comandos na raiz, visto que o pacote comunica via API nativa e nenhuma string é concatenada em forma de shell script/linha de comando.

## 3. SEGREDO
**Achado:** Vazamento potencial de senha via representação do objeto (Severidade: Média/Baixa)
- **Arquivo:Linha:** `src/mcp_mikrotik/config.py` (linhas 36-37)
- **Cenário:** O `dataclass` `Device` possui a propriedade `password` sem instruir a ocultação do repr. Apesar do método `to_public_dict()` estar perfeitamente correto e ocultar a senha, se ocorrer uma exceção não tratada na aplicação em que variáveis locais sejam enviadas ao log (via `logger.exception` ou crash dumps locais), o `repr(device)` imprimirá a senha em texto plano.
- **Correção sugerida:** Utilizar `field(repr=False)` na declaração do atributo do dataclass.
  ```python
  from dataclasses import dataclass, field

  # ...
  password: str = field(default="", repr=False)
  ```

## 4. ERRO
**Status:** Correto.
- **Exceções vazam stack trace ou hostname interno?** Não. O decorador `_safe` em `server.py` captura as exceções não tratadas (`Exception`), efetua log do lado do servidor e levanta um `RuntimeError` limpo (`"Internal error handling this tool call..."`), barrando vazamento de trace para o chamador do MCP. As exceções controladas (`MikrotikMCPError`) enviam apenas o nome local (`device_name`) e a string do erro.

## 5. COMPATIBILIDADE
**Status:** Correto.
- **Assume estruturas exclusivas do ROS 7?** Não. As chamadas usam os endpoints padrões (`/system/identity`, `/system/resource`, `/interface`, `/ip/address`, `/ip/route`, `/ip/neighbor`, `/log`, `/ping`) que mantêm suporte total e mesma estrutura base no RouterOS 6.49.

## 6. QUALIDADE DOS TESTES
**Status:** Correto.
- **Exercitam guard e rejeição de injeção de fato?** Sim. A suíte `test_validation.py` insere vetores de injeção agressivos (como `8.8.8.8; rm -rf /` e `$(reboot)`) confirmando a interrupção precoce. Em `test_guard.py` e `test_server.py`, os testes usam conexões _fakes_ de leitura e _RaisingConnection_ para atestar que o device real nunca seria invocado sob write lock ou _confirm=False_. O sistema não emite falsa sensação de segurança.
