# Melhorias de segurança (branch `melhorias-seguranca`)

Esta branch corrige cinco pontos fracos de segurança do SentinelMobile que
apareceram numa revisão do código. A versão estável continua na `main`.
Nada aqui foi mesclado.

Cada melhoria está num commit separado (`git log --oneline main..melhorias-seguranca`),
para facilitar a revisão e, se preciso, desfazer só uma delas.

| Item | Problema | O que mudou |
|---|---|---|
| (a) | Chave privada TLS, tokens, banco e fotos estavam no git | Arquivos removidos do controle de versão e adicionados ao `.gitignore` |
| (b) | Um único token para todos os aparelhos; identidade escolhida pelo cliente | Pareamento por código; cada aparelho tem o próprio token |
| (c) | PIN padrão `1234`, em texto puro, exibido na tela, sem limite de tentativas | PIN definido no 1º uso, salvo com hash, com limite de tentativas; erros geram `PIN_FAIL` |
| (d) | Token admin na URL, no log do servidor e em `localStorage` | Tela de login e cookie de sessão `HttpOnly` |
| (e) | Tela de bloqueio contornável pelos botões Home e Recentes; nada depois de reiniciar | Device Admin obrigatório, `lockNow()` ao sair da tela, retomada no boot, alerta se o admin for desativado |

> **Atenção:** o código Android desta branch **não foi compilado** nem testado em
> aparelho, porque a máquina onde foi escrito não tinha o Android SDK. No backend,
> foi verificada a sintaxe do Python e do JavaScript, e a migração do banco foi
> testada numa cópia do `sentinel.db` real. Os endpoints em si não foram executados,
> porque o FastAPI não estava instalado. Antes de usar na apresentação, rode o
> roteiro de teste da seção 4.

---

## 1. O que foi feito e por quê

### (a) Segredos fora do git

**Problema.** Estavam versionados `backend/certs/server.key` (chave privada TLS),
`backend/config.json` (tokens), `backend/sentinel.db` e as fotos em `backend/photos/`.
Com a chave privada, qualquer pessoa com acesso ao repositório consegue se passar
pelo servidor. O *certificate pinning* do app deixa de proteger, porque o atacante
tem exatamente o certificado em que o app confia. As fotos são imagens de pessoas
(dado pessoal, LGPD).

**O que mudou.**
- `.gitignore`: adicionados `backend/config.json`, `backend/certs/`,
  `backend/sentinel.db*`, `backend/photos/`, `__pycache__/` e `*.pyc`.
- Os arquivos saíram do controle de versão (`git rm --cached`), mas **continuam no
  disco**. O servidor já recriava todos eles sozinho quando faltavam.
- O certificado **público** (`android/.../res/raw/sentinel_cert.crt`) continua
  versionado. Ele não é segredo e o app precisa dele para compilar.

**O que ficou pendente (precisa de decisão do grupo):**
1. **Os segredos continuam no histórico.** Remover um arquivo num commit novo não
   apaga as versões antigas. Para limpar de verdade, é preciso reescrever o histórico
   (por exemplo com [`git filter-repo`](https://github.com/newren/git-filter-repo)) e
   fazer *force push*. Isso muda os hashes de todos os commits e afeta quem já clonou
   o repositório, por isso não foi feito automaticamente.
2. **Gerar chave e token novos.** Se o repositório já foi compartilhado, considere a
   chave e o token antigos como vazados. Para gerar novos:
   ```bash
   cd backend
   rm config.json                 # o servidor gera um token admin novo
   python main.py --regen-cert    # gera chave e certificado novos
   ```
   Depois, copie o novo `backend/certs/server.crt` para
   `android/app/src/main/res/raw/sentinel_cert.crt` e recompile o app.

### (b) Um token por aparelho (pareamento)

**Problema.** Todos os celulares usavam o mesmo `device_token`, e o servidor
identificava o aparelho pelo cabeçalho `X-Device-Id`, que é o próprio cliente quem
escolhe. Quem tivesse o token podia enviar alertas e localizações falsos em nome de
qualquer aparelho, ou consumir os comandos (LOCK/UNLOCK) destinados a outro.

**O que mudou.**
- **Painel:** o botão **"Parear novo aparelho"** gera um código de 8 caracteres
  (ex.: `K7QM-3XRP`), válido por **10 minutos** e para **um único** aparelho.
- **App:** campo **"Código de pareamento"** e botão **"Parear"**. O app envia o código
  para `POST /api/v1/register` e recebe um token exclusivo dele.
- **Servidor:**
  - guarda só o **SHA-256** do token (coluna `devices.token_hash`). Quem ler o
    `sentinel.db` não consegue se passar por um aparelho;
  - identifica o aparelho **pelo token**; o `X-Device-Id` passou a ser ignorado;
  - parear de novo o mesmo `device_id` troca o token, e o antigo para de funcionar
    na hora;
  - limita os erros de código de pareamento (20 a cada 10 min);
  - o `/api/v1/state` deixou de devolver o hash do token para o painel (antes era
    `SELECT *`).
- Bancos antigos são **migrados automaticamente** (`ALTER TABLE` em `db.py`).
- A fila do app (Outbox) **não descarta mais envios com HTTP 401**: um alerta gerado
  antes do pareamento fica guardado até o aparelho ser pareado.
- Depois de pareado, mudar o Device ID exige parear de novo, para o nome no app não
  divergir do nome no painel.

**Arquivos:** `backend/main.py`, `backend/db.py`, `backend/static/index.html`,
`Sentinel.kt`, `MainActivity.kt`, `Net.kt`, `Core.kt`.

**Impacto:** aparelhos que usavam o token antigo aparecem como **"nao pareado"** no
painel e precisam ser pareados de novo.

### (c) PIN do app

**Problema.**
- O PIN padrão era `1234` e ficava em texto puro nas preferências do app.
- A tela principal **mostrava o PIN correto** ("PIN correto: 1234").
- A tela de bloqueio aceitava tentativas sem limite e **não gerava alerta**: um
  sistema feito para detectar força bruta de PIN deixava a própria tela de bloqueio
  sem essa proteção.

**O que mudou** (`Core.kt`, objeto `Pin`):
- **Não existe PIN padrão.** O app pede para definir um PIN (4 a 8 dígitos) no
  primeiro uso. Para trocar, é preciso digitar o PIN atual.
- **Salvamos só o hash:** PBKDF2-SHA256 com *salt* aleatório. A comparação é feita
  em tempo constante (`MessageDigest.isEqual`).
- **Limite de tentativas:** a partir do **5º erro seguido**, as tentativas ficam
  bloqueadas por 30 s, e esse tempo dobra a cada novo erro (até 15 min). A contagem
  fica salva, então fechar o app não zera.
- **Cada erro na tela de bloqueio gera `PIN_FAIL`**, o que alimenta a regra R1.
  O botão "Testar PIN" da tela principal segue as mesmas regras, para não virar um
  atalho para adivinhar o PIN.

**Por que 5 tentativas e não 3?** A R1 dispara com **mais de 3** falhas (padrão).
Com o bloqueio no 5º erro, a R1 dispara no 4º, com foto e GPS, **antes** de o
atacante ser travado. Se o bloqueio começasse no 3º erro, a R1 só dispararia depois
de 30 s de espera.

**Limitação honesta.** Um PIN de 4 dígitos tem só 10.000 combinações. Quem
conseguir copiar o arquivo de preferências do app (o que exige root) consegue
testar todas offline, mesmo com o hash. A proteção real contra adivinhação é o
limite de tentativas mais o alerta. O hash serve para o PIN não ficar legível em
backups ou depuração.

### (d) Login do painel sem token na URL

**Problema.** O painel abria com `https://.../?t=TOKEN`, e cada miniatura de foto
carregava `/api/v1/photos/ID?t=TOKEN`. Com isso, o token admin ficava:
- no **log de acesso do uvicorn** (uma linha por foto, a cada atualização);
- no **histórico do navegador**;
- salvo em `localStorage`, acessível a qualquer JavaScript da página.

**O que mudou.**
- O painel mostra uma **tela de login**. O token é digitado uma vez e trocado por
  um **cookie de sessão** `HttpOnly` + `Secure` + `SameSite=Strict`, válido por 12 h.
  - `HttpOnly`: o JavaScript não lê o cookie.
  - `Secure`: o cookie só é enviado por HTTPS.
  - `SameSite=Strict`: outro site não consegue disparar ações no painel em seu nome
    (proteção contra CSRF).
- O servidor **não aceita mais `?t=`**. Scripts e `curl` podem continuar usando o
  cabeçalho `X-Admin-Token`.
- Erros de login são limitados (10 a cada 10 min). Há também um botão **"Sair"**.
- O painel apaga o token que versões antigas deixaram no `localStorage`.
- No terminal, o servidor mostra o token admin separado da URL, para ser digitado
  na tela de login.

**Limitações:** as sessões ficam em memória, então reiniciar o servidor exige novo
login. O limite de tentativas é global (não é por IP): alguém errando de propósito
pode impedir o login por até 10 minutos. Para um MVP em rede local isso é aceitável.

### (e) Bloqueio mais difícil de contornar

**Problema.** A tela vermelha de bloqueio só bloqueava o botão Voltar. Os botões
Home e Recentes saíam dela, e um app comum não tem como impedir isso. Depois de
reiniciar o aparelho, nada reabria o bloqueio. O Device Admin, que é o que trava a
tela de verdade com `lockNow()`, era opcional.

**O que mudou.**
- **Device Admin obrigatório:** o app abre a tela de ativação sempre que é aberto
  sem ele e mostra um aviso em destaque (`!! DEVICE ADMIN INATIVO`).
- **Home/Recentes:** se a tela vermelha sai de cena com o aparelho bloqueado
  (`onStop`), o app chama `lockNow()`. A tela do próprio Android trava e passa a
  exigir o PIN ou a biometria do aparelho.
- **Reinício:** novo `BootReceiver`. Depois do boot, o monitoramento volta e, se o
  aparelho estava bloqueado, o bloqueio é reaplicado.
- **Desativar o Device Admin** (passo obrigatório para desinstalar o app) mostra um
  aviso e envia ao painel um alerta **`ADMIN_OFF`** (severidade ALTA).

**Arquivos:** `Engine.kt`, `LockActivity.kt`, `MainActivity.kt`, `Sentinel.kt`,
`AndroidManifest.xml`, `backend/main.py`.

**Limitações:**
- O Android 10+ restringe abrir telas a partir de segundo plano. Depois do boot, a
  tela vermelha pode não aparecer sozinha, mas o `lockNow()` funciona.
- Não há *Foreground Service*. Com o app em segundo plano por muito tempo, o
  Android ainda pode encerrar o processo (ver "trabalhos futuros").
- A foto do alerta `ADMIN_OFF` normalmente falha, porque a câmera exige o app em
  primeiro plano. O alerta chega sem foto.

---

## 2. Como rodar esta branch (do zero)

1. **Servidor** (no PC):
   ```bash
   cd backend
   pip install -r requirements.txt
   python main.py --ip 127.0.0.1
   ```
   O terminal mostra o **token admin** e o caminho do certificado.
   Se aparecer "Certificado: NOVO", copie `backend/certs/server.crt` para
   `android/app/src/main/res/raw/sentinel_cert.crt` antes de compilar o app.

2. **Celular por USB** (o mais estável para a apresentação, porque não depende do
   Wi-Fi do local):
   ```bash
   adb reverse tcp:8443 tcp:8443
   ```
   No app, a URL fica `https://127.0.0.1:8443`. Como `127.0.0.1` sempre faz parte do
   certificado, ele não precisa ser gerado de novo quando a rede muda.

3. **Compilar e instalar o app** pelo Android Studio (projeto `android/`).

4. **Primeira abertura do app:** aceite as permissões, **defina o PIN do app** e
   **ative o Device Admin**.

5. **Painel:** abra `https://127.0.0.1:8443/` e entre com o token admin.

6. **Pareamento:** no painel, clique em "Parear novo aparelho". No app, digite o
   código e toque em "Parear". O status do app deve mostrar `Pareado : sim (...)`.

---

## 3. Cuidado ao alternar entre `main` e esta branch

Na `main`, `config.json`, `certs/`, `sentinel.db` e `photos/` são versionados; nesta
branch, não. Por isso o git mexe nesses arquivos ao trocar de branch (comportamento
testado):

- **ao ir para a `main`**, o git **sobrescreve** a versão local desses arquivos com
  a que está commitada na `main`;
- **ao voltar para esta branch**, o git **apaga** esses arquivos. O servidor gera
  token e certificado novos, então é preciso recopiar o certificado para o app,
  recompilar, fazer login de novo e parear de novo.

Para não perder nada, faça um backup antes de trocar de branch e restaure depois:
```bash
mkdir -p ~/sentinel-backup && cp -r backend/config.json backend/certs backend/sentinel.db backend/photos ~/sentinel-backup/
git switch main        # ... e depois: git switch melhorias-seguranca
cp -r ~/sentinel-backup/* backend/
```

O problema desaparece quando esta branch for mesclada na `main`.

---

## 4. Roteiro de teste

Marque cada item ao testar com o celular e o PC da apresentação.

**(a) Segredos**
- [ ] `git ls-files backend` lista só código (`main.py`, `db.py`, `certs.py`,
      `requirements.txt`, `static/index.html`).
- [ ] O servidor sobe normalmente com os arquivos locais existentes.

**(b) Pareamento**
- [ ] Antes de parear, o app mostra `Pareado : NAO` e o log mostra HTTP 401.
- [ ] O código do painel funciona uma vez; usá-lo de novo dá "invalido ou expirado".
- [ ] Depois de parear: localização, alertas e comandos LOCK/UNLOCK funcionam.
- [ ] Um código digitado errado não pareia; o painel continua mostrando o aparelho
      só depois do pareamento correto.
- [ ] Um banco antigo (copiado da `main`) sobe sem erro; os aparelhos antigos
      aparecem como "nao pareado".

**(c) PIN**
- [ ] A primeira abertura pede para definir o PIN; não dá para fechar sem definir.
- [ ] O PIN não aparece em nenhum lugar da tela.
- [ ] Na tela de bloqueio, 4 PINs errados disparam a **R1**, e o alerta chega ao
      painel com foto e GPS.
- [ ] No 5º erro, a tela mostra a contagem regressiva e o botão fica desativado.
- [ ] Fechar e reabrir o app não zera a contagem.
- [ ] O PIN correto, fora do período de bloqueio, libera a tela.
- [ ] O **Desbloquear do painel** libera a tela mesmo durante o bloqueio por tempo.

**(d) Login do painel**
- [ ] `https://127.0.0.1:8443/` mostra a tela de login, sem token na URL.
- [ ] Token errado dá mensagem de erro; o certo abre o painel.
- [ ] As fotos aparecem (via cookie, sem `?t=` no endereço da imagem).
- [ ] O log do uvicorn não mostra o token em nenhuma linha.
- [ ] "Sair" volta para a tela de login.

**(e) Bloqueio**
- [ ] Sem Device Admin, o app pede a ativação ao abrir e mostra o aviso vermelho.
- [ ] Com o aparelho bloqueado, apertar Home trava a tela do Android.
- [ ] Reiniciar o celular com o bloqueio ativo: o aparelho volta bloqueado e o
      painel volta a mostrá-lo online.
- [ ] Desativar o Device Admin nas configurações do Android gera o alerta
      `ADMIN_OFF` no painel.

---

## 5. Trabalhos futuros (não incluídos aqui)

- **Detecção real em vez de simulada:** `DeviceAdminReceiver.onPasswordFailed()`
  (com `<watch-login/>` no `device_admin.xml`) para a R1, `onPasswordChanged()` para
  a R3, e `UsageStatsManager` ou `AccessibilityService` para a R2.
- **Foreground Service** para o monitoramento não ser encerrado em segundo plano.
- **Push (Firebase Cloud Messaging)** em vez de consultar o servidor a cada 3 s:
  comandos instantâneos e menos consumo de bateria.
- **Testes automatizados** das regras R1/R2/R3, que hoje existem duplicadas no app
  (Kotlin) e no servidor (Python).
- **Limpeza de dados antigos** (fotos, localizações, `seen_ids`) e criptografia das
  fotos no servidor (LGPD).
- **Limite de tentativas por IP** no login e no pareamento.
