"""
Módulo de análise STRIDE para modelagem de ameaças.

A metodologia STRIDE classifica ameaças em seis categorias:
- Spoofing (Falsificação de Identidade)
- Tampering (Adulteração)
- Repudiation (Repúdio)
- Information Disclosure (Divulgação de Informações)
- Denial of Service (Negação de Serviço)
- Elevation of Privilege (Elevação de Privilégio)

Este módulo usa GPT-4o para gerar análise STRIDE detalhada
a partir dos componentes identificados na arquitetura.
"""

import json
from openai import OpenAI
from fpdf import FPDF


# Descrição detalhada de cada categoria STRIDE
STRIDE_CATEGORIES = {
    "Spoofing": {
        "nome_pt": "Falsificação de Identidade",
        "descricao": (
            "Um atacante finge ser outra entidade (usuário, sistema ou componente). "
            "Envolve o uso de credenciais falsas para obter acesso a um sistema."
        ),
        "propriedade_violada": "Autenticação",
    },
    "Tampering": {
        "nome_pt": "Adulteração",
        "descricao": (
            "Modificação maliciosa de dados. Inclui alterações não autorizadas em "
            "dados persistentes (banco de dados) ou em trânsito (rede)."
        ),
        "propriedade_violada": "Integridade",
    },
    "Repudiation": {
        "nome_pt": "Repúdio",
        "descricao": (
            "Capacidade de negar ter realizado uma ação sem que haja forma de "
            "provar o contrário. Está associada à falta de logs e auditoria."
        ),
        "propriedade_violada": "Não-repúdio",
    },
    "Information Disclosure": {
        "nome_pt": "Divulgação de Informações",
        "descricao": (
            "Exposição de informações a indivíduos não autorizados. Inclui leitura "
            "de dados em trânsito, acesso a armazenamento não protegido, etc."
        ),
        "propriedade_violada": "Confidencialidade",
    },
    "Denial of Service": {
        "nome_pt": "Negação de Serviço",
        "descricao": (
            "Tornar um sistema ou componente indisponível para seus usuários "
            "legítimos, geralmente por sobrecarga de recursos."
        ),
        "propriedade_violada": "Disponibilidade",
    },
    "Elevation of Privilege": {
        "nome_pt": "Elevação de Privilégio",
        "descricao": (
            "Um usuário não privilegiado ganha acesso privilegiado, podendo "
            "comprometer ou controlar todo o sistema."
        ),
        "propriedade_violada": "Autorização",
    },
}


SYSTEM_PROMPT_STRIDE = """Você é um especialista sênior em segurança da informação e modelagem de ameaças, com profundo conhecimento da metodologia STRIDE da Microsoft.

Sua tarefa é realizar uma análise STRIDE completa e detalhada a partir dos componentes e fluxos de dados de uma arquitetura de software.

Para CADA componente e CADA fluxo de dados relevante, analise TODAS as 6 categorias STRIDE:

1. **Spoofing (Falsificação de Identidade)**: Como um atacante poderia se passar por este componente ou por um usuário legítimo?
2. **Tampering (Adulteração)**: Como os dados neste componente ou fluxo poderiam ser adulterados?
3. **Repudiation (Repúdio)**: Como um ator poderia negar ter realizado ações neste componente?
4. **Information Disclosure (Divulgação de Informações)**: Como informações sensíveis poderiam vazar deste componente?
5. **Denial of Service (Negação de Serviço)**: Como este componente poderia ser tornado indisponível?
6. **Elevation of Privilege (Elevação de Privilégio)**: Como um atacante poderia obter acesso não autorizado através deste componente?

Para cada ameaça identificada, forneça:
- **ameaca**: Descrição clara e específica da ameaça
- **categoria_stride**: Uma das categorias (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **componente_afetado**: Nome do componente ou fluxo afetado
- **severidade**: "Crítica", "Alta", "Média" ou "Baixa"
- **probabilidade**: "Alta", "Média" ou "Baixa"
- **impacto**: Descrição do impacto se a ameaça for explorada
- **vulnerabilidades**: Lista de possíveis vulnerabilidades que poderiam ser exploradas
- **contramedidas**: Lista de contramedidas/mitigações específicas e acionáveis

Responda APENAS com JSON válido no seguinte formato:
{
  "analise_stride": [
    {
      "ameaca": "...",
      "categoria_stride": "...",
      "componente_afetado": "...",
      "severidade": "...",
      "probabilidade": "...",
      "impacto": "...",
      "vulnerabilidades": ["..."],
      "contramedidas": ["..."]
    }
  ],
  "resumo_executivo": "Resumo de alto nível das principais ameaças encontradas",
  "recomendacoes_prioritarias": ["Lista das 5 recomendações mais importantes em ordem de prioridade"]
}"""


def generate_stride_analysis(
    client: OpenAI,
    architecture_data: dict,
    model: str = "gpt-4o",
) -> dict:
    """
    Gera análise STRIDE completa a partir dos dados da arquitetura.

    Args:
        client: Cliente OpenAI configurado
        architecture_data: Dicionário com componentes e fluxos extraídos da imagem
        model: Modelo a ser utilizado

    Returns:
        Dicionário com análise STRIDE completa
    """
    arch_json = json.dumps(architecture_data, ensure_ascii=False, indent=2)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT_STRIDE},
            {
                "role": "user",
                "content": (
                    f"Realize uma análise STRIDE completa para a seguinte arquitetura de software:\n\n"
                    f"{arch_json}\n\n"
                    f"Analise cada componente e cada fluxo de dados. "
                    f"Seja específico e detalhado nas ameaças, vulnerabilidades e contramedidas. "
                    f"Responda APENAS com o JSON solicitado."
                ),
            },
        ],
        temperature=0.2,
        max_tokens=16384,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content

    if response.choices[0].finish_reason == "length":
        raise ValueError(
            "A resposta do modelo foi truncada (limite de tokens atingido). "
            "Tente com um diagrama mais simples ou reduza o número de componentes."
        )

    result = json.loads(content)

    # Enriquecer com metadados STRIDE
    for item in result.get("analise_stride", []):
        categoria = item.get("categoria_stride", "")
        if categoria in STRIDE_CATEGORIES:
            item["propriedade_violada"] = STRIDE_CATEGORIES[categoria][
                "propriedade_violada"
            ]
            item["categoria_nome_pt"] = STRIDE_CATEGORIES[categoria]["nome_pt"]

    return result


def format_stride_report_markdown(
    architecture_data: dict,
    stride_data: dict,
) -> str:
    """
    Formata os dados de análise STRIDE em um relatório Markdown.

    Args:
        architecture_data: Dados dos componentes identificados
        stride_data: Dados da análise STRIDE

    Returns:
        String com o relatório formatado em Markdown
    """
    lines = []

    # Cabeçalho
    lines.append("# Relatório de Modelagem de Ameaças — STRIDE")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Descrição geral do sistema
    desc_geral = architecture_data.get("descricao_geral", "Não disponível")
    lines.append("## 1. Descrição do Sistema")
    lines.append("")
    lines.append(desc_geral)
    lines.append("")

    # Componentes identificados
    lines.append("## 2. Componentes Identificados")
    lines.append("")
    lines.append("| # | Componente | Tipo | Tecnologia | Descrição |")
    lines.append("|---|-----------|------|------------|-----------|")
    for i, comp in enumerate(architecture_data.get("componentes", []), 1):
        nome = comp.get("nome", "N/A")
        tipo = comp.get("tipo", "N/A")
        tech = comp.get("tecnologia", "N/A")
        desc = comp.get("descricao", "N/A")
        lines.append(f"| {i} | {nome} | {tipo} | {tech} | {desc} |")
    lines.append("")

    # Fluxos de dados
    fluxos = architecture_data.get("fluxos", [])
    if fluxos:
        lines.append("## 3. Fluxos de Dados")
        lines.append("")
        lines.append("| # | Origem | Destino | Protocolo | Dados | Descrição |")
        lines.append("|---|--------|---------|-----------|-------|-----------|")
        for i, fluxo in enumerate(fluxos, 1):
            orig = fluxo.get("origem", "N/A")
            dest = fluxo.get("destino", "N/A")
            proto = fluxo.get("protocolo", "N/A")
            dados = fluxo.get("dados", "N/A")
            desc = fluxo.get("descricao", "N/A")
            lines.append(f"| {i} | {orig} | {dest} | {proto} | {dados} | {desc} |")
        lines.append("")

    # Resumo executivo
    resumo = stride_data.get("resumo_executivo", "")
    if resumo:
        lines.append("## 4. Resumo Executivo")
        lines.append("")
        lines.append(resumo)
        lines.append("")

    # Análise STRIDE detalhada
    analise = stride_data.get("analise_stride", [])
    lines.append("## 5. Análise STRIDE Detalhada")
    lines.append("")

    # Agrupar por categoria
    categorias_ordem = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]

    for categoria in categorias_ordem:
        ameacas_cat = [a for a in analise if a.get("categoria_stride") == categoria]
        if not ameacas_cat:
            continue

        info = STRIDE_CATEGORIES.get(categoria, {})
        nome_pt = info.get("nome_pt", categoria)
        prop = info.get("propriedade_violada", "N/A")

        lines.append(
            f"### 5.{categorias_ordem.index(categoria)+1}. {categoria} ({nome_pt})"
        )
        lines.append(f"**Propriedade de segurança violada:** {prop}")
        lines.append("")

        for j, ameaca in enumerate(ameacas_cat, 1):
            lines.append(f"#### Ameaça {j}: {ameaca.get('ameaca', 'N/A')}")
            lines.append(
                f"- **Componente afetado:** {ameaca.get('componente_afetado', 'N/A')}"
            )
            lines.append(f"- **Severidade:** {ameaca.get('severidade', 'N/A')}")
            lines.append(f"- **Probabilidade:** {ameaca.get('probabilidade', 'N/A')}")
            lines.append(f"- **Impacto:** {ameaca.get('impacto', 'N/A')}")
            lines.append("")

            vulns = ameaca.get("vulnerabilidades", [])
            if vulns:
                lines.append("**Vulnerabilidades:**")
                for v in vulns:
                    lines.append(f"- {v}")
                lines.append("")

            contra = ameaca.get("contramedidas", [])
            if contra:
                lines.append("**Contramedidas:**")
                for c in contra:
                    lines.append(f"- {c}")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Recomendações prioritárias
    recs = stride_data.get("recomendacoes_prioritarias", [])
    if recs:
        lines.append("## 6. Recomendações Prioritárias")
        lines.append("")
        for i, rec in enumerate(recs, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # Estatísticas
    lines.append("## 7. Estatísticas da Análise")
    lines.append("")
    lines.append(
        f"- **Total de componentes analisados:** {len(architecture_data.get('componentes', []))}"
    )
    lines.append(
        f"- **Total de fluxos de dados:** {len(architecture_data.get('fluxos', []))}"
    )
    lines.append(f"- **Total de ameaças identificadas:** {len(analise)}")
    lines.append("")

    # Contagem por categoria
    lines.append("### Distribuição por Categoria STRIDE")
    lines.append("")
    lines.append("| Categoria | Quantidade |")
    lines.append("|-----------|-----------|")
    for cat in categorias_ordem:
        count = len([a for a in analise if a.get("categoria_stride") == cat])
        nome_pt = STRIDE_CATEGORIES.get(cat, {}).get("nome_pt", cat)
        lines.append(f"| {cat} ({nome_pt}) | {count} |")
    lines.append("")

    # Contagem por severidade
    lines.append("### Distribuição por Severidade")
    lines.append("")
    lines.append("| Severidade | Quantidade |")
    lines.append("|-----------|-----------|")
    for sev in ["Crítica", "Alta", "Média", "Baixa"]:
        count = len([a for a in analise if a.get("severidade") == sev])
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    # Rodapé
    lines.append("---")
    lines.append(
        "*Relatório gerado automaticamente pela ferramenta de Modelagem de Ameaças STRIDE com IA.*"
    )
    lines.append("")

    return "\n".join(lines)


def _sanitize_latin1(text: str) -> str:
    """Remove ou substitui caracteres fora do intervalo latin-1 para uso no FPDF."""
    replacements = {
        "\u2014": "-",   # em dash
        "\u2013": "-",   # en dash
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201c": '"',   # left double quote
        "\u201d": '"',   # right double quote
        "\u2026": "...", # ellipsis
        "\u2022": "-",   # bullet
        "\u00a0": " ",   # non-breaking space
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Fallback: encode to latin-1, replacing anything still unsupported
    return text.encode("latin-1", errors="replace").decode("latin-1")


class _StridePDF(FPDF):
    """PDF customizado com cabeçalho e rodapé para relatório STRIDE."""

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, "Relatorio de Modelagem de Ameacas - STRIDE", align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Pagina {self.page_no()}/{{nb}}", align="C")


def generate_stride_report_pdf(
    architecture_data: dict,
    stride_data: dict,
) -> bytes:
    """
    Gera o relatório STRIDE em formato PDF.

    Args:
        architecture_data: Dados dos componentes identificados
        stride_data: Dados da análise STRIDE

    Returns:
        Bytes do arquivo PDF gerado
    """
    pdf = _StridePDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    def _title(text, size=16):
        pdf.set_font("Helvetica", "B", size)
        pdf.cell(0, 10, _sanitize_latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    def _subtitle(text, size=13):
        pdf.set_font("Helvetica", "B", size)
        pdf.cell(0, 8, _sanitize_latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def _body(text):
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, _sanitize_latin1(text))
        pdf.ln(2)

    def _bullet(text):
        pdf.set_font("Helvetica", "", 10)
        pdf.set_x(pdf.l_margin + 5)
        pdf.multi_cell(0, 5, _sanitize_latin1(f"- {text}"))

    # Título principal
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, _sanitize_latin1("Relatorio STRIDE"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(
        0, 8, _sanitize_latin1("Modelagem de Ameacas com IA"), align="C", new_x="LMARGIN", new_y="NEXT"
    )
    pdf.ln(10)

    # 1. Descrição do Sistema
    _title("1. Descrição do Sistema")
    desc_geral = architecture_data.get("descricao_geral", "Não disponível")
    _body(desc_geral)

    # Acurácia estimada
    acuracia = architecture_data.get("acuracia_estimada")
    if acuracia is not None:
        _body(f"Acurácia estimada da identificação de componentes: {acuracia:.0%}")

    # 2. Componentes Identificados
    _title("2. Componentes Identificados")
    componentes = architecture_data.get("componentes", [])
    for i, comp in enumerate(componentes, 1):
        nome = comp.get("nome", "N/A")
        tipo = comp.get("tipo", "N/A")
        tech = comp.get("tecnologia", "N/A")
        desc = comp.get("descricao", "N/A")
        confianca = comp.get("confianca")
        conf_str = f" (confiança: {confianca:.0%})" if confianca is not None else ""

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, _sanitize_latin1(f"{i}. {nome} [{tipo}]{conf_str}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _sanitize_latin1(f"   Tecnologia: {tech}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _sanitize_latin1(f"   Descrição: {desc}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # 3. Fluxos de Dados
    fluxos = architecture_data.get("fluxos", [])
    if fluxos:
        _title("3. Fluxos de Dados")
        for i, fluxo in enumerate(fluxos, 1):
            orig = fluxo.get("origem", "N/A")
            dest = fluxo.get("destino", "N/A")
            proto = fluxo.get("protocolo", "N/A")
            desc = fluxo.get("descricao", "N/A")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(
                0, 6, _sanitize_latin1(f"{i}. {orig} -> {dest} ({proto})"), new_x="LMARGIN", new_y="NEXT"
            )
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 5, _sanitize_latin1(f"   {desc}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    # 4. Resumo Executivo
    resumo = stride_data.get("resumo_executivo", "")
    if resumo:
        _title("4. Resumo Executivo")
        _body(resumo)

    # 5. Análise STRIDE Detalhada
    _title("5. Análise STRIDE Detalhada")
    analise = stride_data.get("analise_stride", [])
    categorias_ordem = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]

    for categoria in categorias_ordem:
        ameacas_cat = [a for a in analise if a.get("categoria_stride") == categoria]
        if not ameacas_cat:
            continue

        info = STRIDE_CATEGORIES.get(categoria, {})
        nome_pt = info.get("nome_pt", categoria)

        _subtitle(f"{categoria} ({nome_pt})")

        for j, ameaca in enumerate(ameacas_cat, 1):
            sev = ameaca.get("severidade", "N/A")
            pdf.set_font("Helvetica", "B", 10)
            pdf.multi_cell(0, 6, _sanitize_latin1(f"Ameaca {j}: {ameaca.get('ameaca', 'N/A')}"))
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(
                0,
                5,
                _sanitize_latin1(
                    f"   Componente: {ameaca.get('componente_afetado', 'N/A')}  |  "
                    f"Severidade: {sev}  |  Probabilidade: {ameaca.get('probabilidade', 'N/A')}"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            impacto = ameaca.get("impacto", "N/A")
            pdf.multi_cell(0, 5, _sanitize_latin1(f"   Impacto: {impacto}"))
            pdf.ln(1)

            vulns = ameaca.get("vulnerabilidades", [])
            if vulns:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 5, "   Vulnerabilidades:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                for v in vulns:
                    _bullet(v)

            contra = ameaca.get("contramedidas", [])
            if contra:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 5, "   Contramedidas:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                for c in contra:
                    _bullet(c)

            pdf.ln(3)

    # 6. Recomendações Prioritárias
    recs = stride_data.get("recomendacoes_prioritarias", [])
    if recs:
        _title("6. Recomendacoes Prioritarias")
        for i, rec in enumerate(recs, 1):
            pdf.set_font("Helvetica", "B", 10)
            pdf.multi_cell(0, 5, _sanitize_latin1(f"{i}. {rec}"))
            pdf.ln(1)

    # 7. Estatísticas
    _title("7. Estatisticas da Analise")
    _body(
        f"Total de componentes: {len(componentes)}\n"
        f"Total de fluxos de dados: {len(fluxos)}\n"
        f"Total de ameacas identificadas: {len(analise)}"
    )

    _subtitle("Distribuicao por Categoria STRIDE")
    for cat in categorias_ordem:
        count = len([a for a in analise if a.get("categoria_stride") == cat])
        nome_pt = STRIDE_CATEGORIES.get(cat, {}).get("nome_pt", cat)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _sanitize_latin1(f"   {cat} ({nome_pt}): {count}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    _subtitle("Distribuicao por Severidade")
    for sev in ["Crítica", "Alta", "Média", "Baixa"]:
        count = len([a for a in analise if a.get("severidade") == sev])
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _sanitize_latin1(f"   {sev}: {count}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Rodapé final
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(
        0,
        5,
        _sanitize_latin1("Relatorio gerado automaticamente pela ferramenta de Modelagem de Ameacas STRIDE com IA."),
        align="C",
    )

    return bytes(pdf.output())
