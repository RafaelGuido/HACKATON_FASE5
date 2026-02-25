# 🛡️ STRIDE Threat Modeling com IA

Ferramenta de **Modelagem de Ameaças** automatizada que utiliza Inteligência Artificial (GPT-4o) para analisar diagramas de arquitetura de software e gerar relatórios completos baseados na metodologia **STRIDE**, com **histórico persistente** e **comparação lado a lado** de análises.

## 📋 Sobre o Projeto

Este projeto foi desenvolvido como MVP para a **FIAP Software Security** (Hackaton — Fase 5, Pós-Graduação em IA para Devs). O objetivo é validar a viabilidade de usar IA para realizar automaticamente a modelagem de ameaças a partir de diagramas de arquitetura de software.

### O que a ferramenta faz

1. **Recebe** uma imagem de diagrama de arquitetura de software
2. **Analisa** a imagem usando GPT-4o (modelo multimodal) para identificar componentes (servidores, APIs, bancos de dados, etc.) e fluxos de dados, exibindo a **acurácia estimada** da identificação
3. **Aplica** a metodologia STRIDE para cada componente e fluxo identificado
4. **Gera** um relatório completo com ameaças, vulnerabilidades e contramedidas, disponível em **Markdown** e **PDF**
5. **Persiste** as análises em banco de dados SQLite local, permitindo consulta, filtragem e exclusão pelo histórico
6. **Compara** duas análises lado a lado com métricas de delta (componentes, ameaças, severidades)

---

## 🏗️ Arquitetura da Solução

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   Interface Web │────▶│  Image Analyzer      │────▶│  GPT-4o (Vision)    │
│   (Streamlit)   │     │  (image_analyzer.py) │     │  Análise de Imagem  │
└────────┬────────┘     └──────────────────────┘     └──────────┬──────────┘
         │                                                      │
         │              ┌──────────────────────┐                │
         │              │   STRIDE Analyzer    │◀───────────────┘
         └─────────────▶│  (stride_analyzer.py)│  Componentes + Fluxos
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   GPT-4o (Text)      │
                        │   Análise STRIDE     │
                        └──────────┬───────────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 ▼                 ▼                  ▼
      ┌──────────────────┐ ┌─────────────┐ ┌─────────────────┐
      │ Relatório STRIDE │ │  SQLite DB  │ │  Comparação de  │
      │ (Markdown/PDF/   │ │ (database.py│ │  Análises       │
      │  JSON)           │ │  histórico) │ │  (lado a lado)  │
      └──────────────────┘ └─────────────┘ └─────────────────┘
```

### Fluxo Detalhado

1. **Upload da Imagem**: O usuário faz upload de um diagrama de arquitetura (PNG, JPG, JPEG, WEBP) na interface Streamlit e seleciona o modelo desejado (GPT-4o ou GPT-4o-mini).

2. **Análise Visual (GPT-4o Vision)**: A imagem é enviada para o modelo selecionado com um prompt especializado que solicita a identificação de:
   - Componentes do sistema (usuários, servidores, bancos de dados, APIs, firewalls, etc.)
   - Fluxos de dados entre componentes (protocolo, tipo de dados)
   - Tecnologias utilizadas
   - **Acurácia estimada** da identificação (confiança geral do modelo na análise)

3. **Análise STRIDE (GPT-4o Text)**: Os componentes e fluxos identificados são alimentados em uma segunda chamada ao modelo, agora com um prompt especializado em STRIDE que gera:
   - Ameaças em cada categoria STRIDE para cada componente/fluxo
   - Severidade e probabilidade de cada ameaça
   - Vulnerabilidades específicas
   - Contramedidas acionáveis
   - Recomendações prioritárias

4. **Geração do Relatório**: Os dados são formatados em um relatório disponível em **Markdown** e **PDF**, com tabelas, seções organizadas por categoria STRIDE e estatísticas. A acurácia da identificação de componentes é exibida como métrica na interface.

5. **Persistência e Histórico**: Após a análise, o usuário pode salvar os resultados (com nome e descrição) em um banco de dados SQLite local. A página de **Histórico** permite:
   - Listar e filtrar análises por nome, descrição e intervalo de datas
   - Visualizar detalhes completos de qualquer análise salva (incluindo a imagem original)
   - Excluir análises do histórico
   - **Comparar duas análises lado a lado**, com distribuição por categoria STRIDE, severidade e métricas de delta

---

## 🧠 Por que usar uma LLM pré-treinada?

Em vez de treinar um modelo do zero para detecção de objetos em diagramas, optamos por utilizar o **GPT-4o** (modelo multimodal já treinado) pelos seguintes motivos:

| Aspecto | Modelo Treinado do Zero | LLM Pré-treinada (GPT-4o) |
|---------|-------------------------|---------------------------|
| **Dataset** | Necessário coletar e anotar milhares de imagens | Não necessário — o modelo já possui conhecimento |
| **Tempo de desenvolvimento** | Semanas/meses | Horas |
| **Capacidade de generalização** | Limitada ao dataset de treino | Ampla — interpreta diagramas variados |
| **Análise semântica** | Apenas detecta componentes | Detecta componentes + entende contexto + gera análise |
| **Manutenção** | Requer retreino com novos dados | Modelo atualizado pelo provedor |
| **Custo inicial** | Alto (GPU, dados, anotação) | Baixo (apenas custo da API) |
| **Qualidade da análise STRIDE** | Regras fixas mapeadas | Análise contextual e inteligente |

A abordagem com LLM pré-treinada é ideal para um **MVP**, pois permite validar a viabilidade da feature rapidamente com alta qualidade de resultado.

---

## 🔧 Metodologia STRIDE

A **STRIDE** é uma metodologia de modelagem de ameaças criada pela Microsoft que classifica ameaças em 6 categorias:

| Letra | Ameaça | Propriedade Violada | Descrição |
|-------|--------|---------------------|-----------|
| **S** | Spoofing | Autenticação | Falsificação de identidade |
| **T** | Tampering | Integridade | Adulteração de dados |
| **R** | Repudiation | Não-repúdio | Negação de ações realizadas |
| **I** | Information Disclosure | Confidencialidade | Vazamento de informações |
| **D** | Denial of Service | Disponibilidade | Indisponibilização do serviço |
| **E** | Elevation of Privilege | Autorização | Ganho de privilégios indevidos |

---

## 🚀 Como Executar

### Pré-requisitos

- Python 3.10+
- Chave de API da OpenAI (com acesso ao GPT-4o)

### Instalação

```bash
# 1. Clone o repositório
git clone <url-do-repositorio>

# 2. Crie e ative o ambiente virtual
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure a chave da API
cp .env.example .env
# Edite o arquivo .env e insira sua OPENAI_API_KEY
```

### Execução

```bash
streamlit run app.py
```

A aplicação será aberta em `http://localhost:8501`.

### Uso

1. Configure sua **OpenAI API Key** no arquivo `.env` (veja `.env.example`)
2. Selecione o **modelo** desejado na barra lateral (GPT-4o ou GPT-4o-mini)
3. Faça **upload** de um diagrama de arquitetura de software
4. Clique em **"Analisar Arquitetura e Gerar Relatório STRIDE"**
5. Acompanhe a **acurácia estimada** da identificação de componentes exibida ao final da etapa de análise de imagem
6. **Salve a análise** no histórico (com nome e descrição opcional) para consultar depois
7. Navegue pelos resultados nas abas:
   - **Componentes**: Lista de componentes identificados e fluxos de dados
   - **Análise STRIDE**: Ameaças detalhadas com filtros por categoria e severidade
   - **Relatório Completo**: Relatório disponível para download em **Markdown** e **PDF**
   - **JSON**: Dados brutos para integração com outras ferramentas
8. Acesse o **Histórico de Análises** na barra lateral para:
   - Listar e filtrar análises salvas (por nome, descrição e datas)
   - Visualizar detalhes completos de uma análise anterior
   - **Comparar duas análises lado a lado** com métricas de delta
   - Excluir análises que não são mais necessárias

---

## 📁 Estrutura do Projeto

```
HACKATON_FASE5/
├── app.py                  # Interface Streamlit (ponto de entrada)
├── image_analyzer.py       # Módulo de análise de imagem com GPT-4o
├── stride_analyzer.py      # Módulo de análise STRIDE e geração de relatório
├── database.py             # Módulo de persistência (SQLite) para histórico
├── requirements.txt        # Dependências Python
├── .env.example            # Template para variáveis de ambiente
├── .gitignore              # Arquivos ignorados pelo Git
├── LICENSE.txt             # Licença do projeto
├── README.md               # Esta documentação
└── data/
    └── stride_history.db   # Banco de dados SQLite (gerado automaticamente)
```

### Descrição dos Módulos

- **`app.py`**: Interface web construída com Streamlit. Gerencia o upload de imagens, orquestra as chamadas para os módulos de análise, exibe os resultados em formato visual interativo, e implementa as páginas de **Nova Análise** e **Histórico** (com listagem, filtros, visualização de detalhes, comparação lado a lado e exclusão).

- **`image_analyzer.py`**: Responsável por enviar a imagem do diagrama para o modelo selecionado (GPT-4o ou GPT-4o-mini) com capacidade de visão e extrair os componentes e fluxos de dados identificados, retornando um JSON estruturado com índices de confiança individuais.

- **`stride_analyzer.py`**: Recebe os componentes e fluxos identificados e gera a análise STRIDE completa usando o modelo selecionado. Também contém a lógica para formatar o relatório em Markdown e gerar a versão em PDF (via fpdf2).

- **`database.py`**: Módulo de persistência que utiliza SQLite para armazenar o histórico de análises. Salva a imagem original (BLOB), os dados de arquitetura e STRIDE (JSON), além de metadados como nome, descrição, data, contagem de componentes, ameaças, críticas e acurácia estimada. Suporta listagem com filtros (nome, descrição, intervalo de datas) e exclusão de registros.

---

## 📊 Exemplo de Saída

### Componentes Identificados
| Componente | Tipo | Tecnologia |
|-----------|------|------------|
| Usuário | usuario | Browser |
| API Gateway | gateway | Kong/Nginx |
| Serviço de Auth | autenticacao | OAuth 2.0 |
| Banco de Dados | banco_dados | PostgreSQL |

### Exemplo de Ameaça STRIDE
- **Categoria:** Spoofing (Falsificação de Identidade)
- **Componente:** API Gateway
- **Ameaça:** Um atacante pode forjar tokens JWT para se passar por um usuário autenticado
- **Severidade:** Crítica
- **Vulnerabilidades:** Algoritmo de assinatura fraco, chave secreta exposta
- **Contramedidas:** Usar RS256, rotacionar chaves, validar claims

---

## 🛠️ Tecnologias Utilizadas

- **Python 3.10+** — Linguagem principal
- **OpenAI GPT-4o / GPT-4o-mini** — Modelos multimodais para análise de imagem e geração de texto
- **Streamlit** — Framework para interface web
- **SQLite** — Banco de dados local para persistência do histórico de análises
- **fpdf2** — Geração de relatórios em PDF
- **Pillow** — Manipulação de imagens
- **python-dotenv** — Gerenciamento de variáveis de ambiente

---

## 👨‍💻 Autores

### Grupo 86
- Rafael Guido de Jesus Toccolini(RM363067)
- Guilherme Rodrigues Santana(RM363105)
- Franklin Santos Araujo(RM363392)
