"""
STRIDE Threat Modeling — Interface Streamlit

Aplicação web para análise de ameaças em diagramas de
arquitetura de software usando a metodologia STRIDE e GPT-4o.
"""

import os
import json
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

from image_analyzer import analyze_architecture_image
from stride_analyzer import (
    generate_stride_analysis,
    format_stride_report_markdown,
    generate_stride_report_pdf,
    STRIDE_CATEGORIES,
)
from database import (
    init_db,
    save_analysis,
    list_analyses,
    get_analysis,
    delete_analysis,
)

load_dotenv()
init_db()

# ───────────────────── Configuração da Página ─────────────────────
st.set_page_config(
    page_title="STRIDE Threat Modeling",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ───────────────────── CSS Customizado ─────────────────────
st.markdown(
    """
    <style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
    }
    .stride-card {
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .metric-container {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }
    .severity-critica { color: #dc3545; font-weight: bold; }
    .severity-alta { color: #fd7e14; font-weight: bold; }
    .severity-media { color: #ffc107; font-weight: bold; }
    .severity-baixa { color: #28a745; font-weight: bold; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ───────────────────── Função Reutilizável: Exibir Resultados ─────────────────────
def render_analysis_results(architecture_data: dict, stride_data: dict):
    """Renderiza métricas e tabs de resultados de uma análise STRIDE."""
    analise = stride_data.get("analise_stride", [])

    # ─── Métricas ───
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🧩 Componentes", len(architecture_data.get("componentes", [])))
    with col2:
        st.metric("🔗 Fluxos de Dados", len(architecture_data.get("fluxos", [])))
    with col3:
        st.metric("⚠️ Ameaças", len(analise))
    with col4:
        criticas = len([a for a in analise if a.get("severidade") == "Crítica"])
        st.metric("🔴 Críticas", criticas)
    with col5:
        acuracia_val = architecture_data.get("acuracia_estimada")
        st.metric(
            "📊 Acurácia Identificação",
            f"{acuracia_val:.0%}" if acuracia_val is not None else "N/A",
        )

    # ─── Tabs ───
    tab_componentes, tab_stride, tab_relatorio, tab_json = st.tabs(
        ["🧩 Componentes", "🛡️ Análise STRIDE", "📄 Relatório Completo", "📦 JSON"]
    )

    # ─── Tab: Componentes ───
    with tab_componentes:
        st.markdown("### Componentes Identificados")

        desc_geral = architecture_data.get("descricao_geral", "")
        if desc_geral:
            st.info(f"**Descrição geral:** {desc_geral}")

        for comp in architecture_data.get("componentes", []):
            with st.expander(
                f"**{comp.get('nome', 'N/A')}** — _{comp.get('tipo', 'N/A')}_"
            ):
                st.write(f"**Descrição:** {comp.get('descricao', 'N/A')}")
                st.write(f"**Tecnologia:** {comp.get('tecnologia', 'N/A')}")
                st.write(f"**Tipo:** {comp.get('tipo', 'N/A')}")

        if architecture_data.get("fluxos"):
            st.markdown("### Fluxos de Dados")
            for fluxo in architecture_data["fluxos"]:
                st.write(
                    f"**{fluxo.get('origem', '?')}** → **{fluxo.get('destino', '?')}** "
                    f"| {fluxo.get('protocolo', 'N/A')} | {fluxo.get('descricao', '')}"
                )

    # ─── Tab: Análise STRIDE ───
    with tab_stride:
        st.markdown("### Análise STRIDE por Categoria")

        # Resumo executivo
        resumo = stride_data.get("resumo_executivo", "")
        if resumo:
            st.warning(f"**Resumo Executivo:** {resumo}")

        # Filtros
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            categorias_selecionadas = st.multiselect(
                "Filtrar por Categoria STRIDE",
                options=list(STRIDE_CATEGORIES.keys()),
                default=list(STRIDE_CATEGORIES.keys()),
            )
        with col_f2:
            severidades_selecionadas = st.multiselect(
                "Filtrar por Severidade",
                options=["Crítica", "Alta", "Média", "Baixa"],
                default=["Crítica", "Alta", "Média", "Baixa"],
            )

        # Exibir ameaças filtradas
        ameacas_filtradas = [
            a
            for a in analise
            if a.get("categoria_stride") in categorias_selecionadas
            and a.get("severidade") in severidades_selecionadas
        ]

        st.write(
            f"Exibindo **{len(ameacas_filtradas)}** de **{len(analise)}** ameaças."
        )

        for ameaca in ameacas_filtradas:
            sev = ameaca.get("severidade", "N/A")
            sev_emoji = {
                "Crítica": "🔴",
                "Alta": "🟠",
                "Média": "🟡",
                "Baixa": "🟢",
            }.get(sev, "⚪")

            cat = ameaca.get("categoria_stride", "N/A")
            cat_nome_pt = ameaca.get("categoria_nome_pt", cat)

            with st.expander(
                f"{sev_emoji} [{sev}] {cat} — {ameaca.get('ameaca', 'N/A')}"
            ):
                st.write(
                    f"**Componente afetado:** {ameaca.get('componente_afetado', 'N/A')}"
                )
                st.write(f"**Categoria:** {cat} ({cat_nome_pt})")
                st.write(
                    f"**Propriedade violada:** {ameaca.get('propriedade_violada', 'N/A')}"
                )
                st.write(f"**Severidade:** {sev}")
                st.write(f"**Probabilidade:** {ameaca.get('probabilidade', 'N/A')}")
                st.write(f"**Impacto:** {ameaca.get('impacto', 'N/A')}")

                vulns = ameaca.get("vulnerabilidades", [])
                if vulns:
                    st.markdown("**🔓 Vulnerabilidades:**")
                    for v in vulns:
                        st.write(f"- {v}")

                contra = ameaca.get("contramedidas", [])
                if contra:
                    st.markdown("**🛡️ Contramedidas:**")
                    for c in contra:
                        st.write(f"- {c}")

        # Recomendações prioritárias
        recs = stride_data.get("recomendacoes_prioritarias", [])
        if recs:
            st.markdown("### 🎯 Recomendações Prioritárias")
            for i, rec in enumerate(recs, 1):
                st.write(f"**{i}.** {rec}")

    # ─── Tab: Relatório Completo ───
    with tab_relatorio:
        report_md = format_stride_report_markdown(architecture_data, stride_data)
        st.markdown(report_md)

        st.download_button(
            label="📥 Baixar Relatório (Markdown)",
            data=report_md,
            file_name="relatorio_stride.md",
            mime="text/markdown",
            use_container_width=True,
        )

        report_pdf = generate_stride_report_pdf(architecture_data, stride_data)
        st.download_button(
            label="📥 Baixar Relatório (PDF)",
            data=report_pdf,
            file_name="relatorio_stride.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    # ─── Tab: JSON ───
    with tab_json:
        st.markdown("### Dados da Arquitetura (JSON)")
        st.json(architecture_data)

        st.markdown("### Dados da Análise STRIDE (JSON)")
        st.json(stride_data)

        # Download do JSON completo
        full_data = {
            "arquitetura": architecture_data,
            "analise_stride": stride_data,
        }
        st.download_button(
            label="📥 Baixar Dados Completos (JSON)",
            data=json.dumps(full_data, ensure_ascii=False, indent=2),
            file_name="analise_stride_completa.json",
            mime="application/json",
            use_container_width=True,
        )


# ───────────────────── Sidebar ─────────────────────
with st.sidebar:
    st.image(
        "https://img.icons8.com/fluency/96/shield.png",
        width=80,
    )
    st.title("⚙️ Configurações")

    # Navegação
    pagina = st.radio(
        "Navegação",
        ["🔍 Nova Análise", "📋 Histórico de Análises"],
        label_visibility="collapsed",
    )

    st.divider()

    # Configurações do modelo (apenas na página de nova análise)
    api_key = os.getenv("OPENAI_API_KEY", "")
    model = "gpt-4o"
    if pagina == "🔍 Nova Análise":
        model = st.selectbox(
            "Modelo",
            ["gpt-4o", "gpt-4o-mini"],
            index=0,
            help="GPT-4o oferece melhor análise de imagem. GPT-4o-mini é mais barato.",
        )

        st.divider()

    st.markdown("### 📖 Sobre a Metodologia STRIDE")
    st.markdown(
        """
        A **STRIDE** é uma metodologia de modelagem de ameaças criada
        pela Microsoft que classifica ameaças em 6 categorias:

        | Letra | Ameaça | Propriedade |
        |-------|--------|-------------|
        | **S** | Spoofing | Autenticação |
        | **T** | Tampering | Integridade |
        | **R** | Repudiation | Não-repúdio |
        | **I** | Info Disclosure | Confidencialidade |
        | **D** | Denial of Service | Disponibilidade |
        | **E** | Elev. of Privilege | Autorização |
        """
    )

    st.divider()
    st.caption("FIAP Software Security — Hackaton Fase 5")


# ═══════════════════════════════════════════════════════════════════
#  PÁGINA: NOVA ANÁLISE
# ═══════════════════════════════════════════════════════════════════
if pagina == "🔍 Nova Análise":
    # ───────────────────── Cabeçalho ─────────────────────
    st.markdown(
        """
        <div class='main-header'>
            <h1>🛡️ Modelagem de Ameaças STRIDE com IA</h1>
            <p style='font-size: 1.1em; color: #666;'>
                Faça upload de um diagrama de arquitetura de software e obtenha
                automaticamente uma análise de ameaças baseada na metodologia STRIDE.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ───────────────────── Upload de Imagem ─────────────────────
    st.markdown("## 📤 Upload do Diagrama de Arquitetura")

    uploaded_file = st.file_uploader(
        "Selecione uma imagem do diagrama de arquitetura",
        type=["png", "jpg", "jpeg", "webp"],
        help="Formatos aceitos: PNG, JPG, JPEG, WEBP",
    )

    # Detectar troca de arquivo
    if uploaded_file is not None:
        current_file_key = uploaded_file.name + str(uploaded_file.size)
        if st.session_state.get("last_uploaded_file") != current_file_key:
            st.session_state["last_uploaded_file"] = current_file_key
            st.session_state.pop("analysis_saved", None)
            st.session_state.pop("architecture_data", None)
            st.session_state.pop("stride_data", None)

    if uploaded_file:
        col_img, col_info = st.columns([2, 1])
        with col_img:
            st.image(
                uploaded_file, caption="Diagrama enviado", use_container_width=True
            )
        with col_info:
            st.markdown("### 📋 Informações do arquivo")
            st.write(f"**Nome:** {uploaded_file.name}")
            size_kb = uploaded_file.size / 1024
            st.write(f"**Tamanho:** {size_kb:.1f} KB")
            st.write(f"**Tipo:** {uploaded_file.type}")

    # ───────────────────── Botão de Análise ─────────────────────
    if uploaded_file:
        st.markdown("---")

        if st.button(
            "🔍 Analisar Arquitetura e Gerar Relatório STRIDE",
            type="primary",
            use_container_width=True,
        ):
            if not api_key:
                st.error(
                    "⚠️ API Key não encontrada. Configure a variável OPENAI_API_KEY no arquivo .env"
                )
                st.stop()

            client = OpenAI(api_key=api_key)
            image_bytes = uploaded_file.getvalue()
            image_type = uploaded_file.type

            # ─── Etapa 1: Análise da imagem ───
            with st.status("🔄 Processando análise...", expanded=True) as status:
                st.write(
                    "🖼️ **Etapa 1/2:** Analisando a imagem do diagrama com GPT-4o..."
                )

                try:
                    architecture_data = analyze_architecture_image(
                        client=client,
                        image_bytes=image_bytes,
                        image_type=image_type,
                        model=model,
                    )
                    st.write(
                        f"✅ Identificados **{len(architecture_data.get('componentes', []))} componentes** "
                        f"e **{len(architecture_data.get('fluxos', []))} fluxos de dados**."
                    )
                    acuracia = architecture_data.get("acuracia_estimada")
                    if acuracia is not None:
                        st.write(
                            f"📊 **Acurácia estimada da identificação:** {acuracia:.0%}"
                        )
                except Exception as e:
                    st.error(f"❌ Erro ao analisar imagem: {e}")
                    st.stop()

                # ─── Etapa 2: Análise STRIDE ───
                st.write("🛡️ **Etapa 2/2:** Gerando análise STRIDE...")

                try:
                    stride_data = generate_stride_analysis(
                        client=client,
                        architecture_data=architecture_data,
                        model=model,
                    )
                    total_ameacas = len(stride_data.get("analise_stride", []))
                    st.write(
                        f"✅ Identificadas **{total_ameacas} ameaças** na arquitetura."
                    )
                except Exception as e:
                    st.error(f"❌ Erro ao gerar análise STRIDE: {e}")
                    st.stop()

                status.update(
                    label="✅ Análise concluída!", state="complete", expanded=False
                )

            # Salvar no session_state
            st.session_state["architecture_data"] = architecture_data
            st.session_state["stride_data"] = stride_data
            st.session_state["image_bytes"] = image_bytes
            st.session_state["image_type"] = image_type
            st.session_state["image_name"] = uploaded_file.name
            st.session_state.pop("analysis_saved", None)

    # ───────────────────── Exibição dos Resultados ─────────────────────
    if "architecture_data" in st.session_state and "stride_data" in st.session_state:
        architecture_data = st.session_state["architecture_data"]
        stride_data = st.session_state["stride_data"]

        st.markdown("---")

        # ─── Salvar no Histórico ───
        if "analysis_saved" not in st.session_state:
            with st.expander("💾 Salvar Análise no Histórico", expanded=True):
                nome_analise = st.text_input(
                    "Nome da análise",
                    value=f"Análise - {st.session_state.get('image_name', 'sem nome')}",
                )
                descricao_analise = st.text_area(
                    "Descrição (opcional)",
                    placeholder="Descreva o contexto desta análise...",
                )
                if st.button("💾 Salvar no Histórico", type="primary"):
                    analysis_id = save_analysis(
                        nome=nome_analise,
                        descricao=descricao_analise,
                        image_bytes=st.session_state["image_bytes"],
                        image_type=st.session_state["image_type"],
                        image_name=st.session_state.get("image_name", ""),
                        architecture_data=architecture_data,
                        stride_data=stride_data,
                    )
                    st.session_state["analysis_saved"] = analysis_id
                    st.rerun()
        else:
            st.success(
                f"✅ Análise salva no histórico (ID: {st.session_state['analysis_saved']})"
            )

        st.markdown("## 📊 Resultados da Análise")
        render_analysis_results(architecture_data, stride_data)

    else:
        # Estado vazio
        st.markdown("---")
        st.markdown(
            """
            <div style='text-align: center; padding: 3rem; color: #888;'>
                <h3>👆 Faça upload de um diagrama de arquitetura para começar</h3>
                <p>A ferramenta irá analisar automaticamente a imagem, identificar os
                componentes da arquitetura e gerar um relatório STRIDE completo.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════════
#  PÁGINA: HISTÓRICO DE ANÁLISES
# ═══════════════════════════════════════════════════════════════════
else:
    st.markdown(
        """
        <div class='main-header'>
            <h1>📋 Histórico de Análises</h1>
            <p style='font-size: 1.1em; color: #666;'>
                Consulte, compare e gerencie suas análises STRIDE anteriores.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ───────────────────── Filtros ─────────────────────
    st.markdown("### 🔎 Filtros")
    col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
    with col_f1:
        data_inicio = st.date_input("Data início", value=None)
    with col_f2:
        data_fim = st.date_input("Data fim", value=None)
    with col_f3:
        nome_filtro = st.text_input(
            "Buscar por nome ou descrição",
            value="",
            placeholder="Digite para filtrar...",
        )

    analyses = list_analyses(
        nome_filtro=nome_filtro if nome_filtro else None,
        data_inicio=data_inicio.isoformat() if data_inicio else None,
        data_fim=data_fim.isoformat() if data_fim else None,
    )

    st.markdown("---")

    # ───────────────────── Confirmação de exclusão ─────────────────────
    if "hist_delete_confirm" in st.session_state:
        del_id = st.session_state["hist_delete_confirm"]
        st.warning(f"⚠️ Tem certeza que deseja excluir a análise ID **{del_id}**?")
        col_yes, col_no, _ = st.columns([1, 1, 4])
        with col_yes:
            if st.button("✅ Sim, excluir", type="primary"):
                delete_analysis(del_id)
                st.session_state.pop("hist_delete_confirm")
                if st.session_state.get("hist_view_id") == del_id:
                    st.session_state.pop("hist_view_id", None)
                compare_ids = st.session_state.get("hist_compare_ids", [])
                if del_id in compare_ids:
                    compare_ids.remove(del_id)
                    st.session_state["hist_compare_ids"] = compare_ids
                st.rerun()
        with col_no:
            if st.button("❌ Cancelar"):
                st.session_state.pop("hist_delete_confirm")
                st.rerun()

    # ───────────────────── Indicador de comparação ─────────────────────
    compare_ids = st.session_state.get("hist_compare_ids", [])
    if compare_ids:
        if len(compare_ids) == 1:
            st.info(
                f"🔄 **1 análise selecionada** para comparação (ID: {compare_ids[0]}). "
                f"Selecione mais uma."
            )
        elif len(compare_ids) == 2:
            st.info(
                f"🔄 **2 análises selecionadas** para comparação (IDs: {compare_ids[0]} e {compare_ids[1]})."
            )
            col_comp_btn, col_comp_clear, _ = st.columns([1, 1, 4])
            with col_comp_btn:
                if st.button("📊 Comparar Análises", type="primary"):
                    st.session_state["hist_show_comparison"] = True
                    st.session_state.pop("hist_view_id", None)
                    st.rerun()
            with col_comp_clear:
                if st.button("🗑️ Limpar seleção"):
                    st.session_state.pop("hist_compare_ids", None)
                    st.session_state.pop("hist_show_comparison", None)
                    st.rerun()

    # ───────────────────── Listagem ─────────────────────
    if not analyses:
        st.markdown(
            """
            <div style='text-align: center; padding: 3rem; color: #888;'>
                <h3>📭 Nenhuma análise encontrada</h3>
                <p>Faça uma nova análise e salve-a no histórico para vê-la aqui.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(f"**{len(analyses)} análise(s) encontrada(s)**")

        for analise_item in analyses:
            aid = analise_item["id"]
            is_selected = aid in compare_ids

            with st.container(border=True):
                col_info, col_metrics, col_actions = st.columns([3, 5, 2])

                with col_info:
                    nome_display = analise_item["nome"]
                    if is_selected:
                        nome_display = f"✅ {nome_display}"
                    st.markdown(f"**{nome_display}**")
                    data_str = analise_item["data_criacao"][:16].replace("T", " ")
                    st.caption(f"📅 {data_str}")
                    if analise_item["descricao"]:
                        st.caption(analise_item["descricao"][:100])

                with col_metrics:
                    mc1, mc2, mc3, mc4 = st.columns(4)
                    mc1.metric("🧩 Comp.", analise_item["num_componentes"])
                    mc2.metric("⚠️ Ameaças", analise_item["num_ameacas"])
                    mc3.metric("🔴 Críticas", analise_item["num_criticas"])
                    acuracia = analise_item["acuracia_estimada"]
                    mc4.metric(
                        "📊 Acurácia",
                        f"{acuracia:.0%}" if acuracia is not None else "N/A",
                    )

                with col_actions:
                    if st.button("👁️ Ver", key=f"view_{aid}"):
                        st.session_state["hist_view_id"] = aid
                        st.session_state.pop("hist_show_comparison", None)
                        st.rerun()
                    if st.button(
                        "✅ Selecionado" if is_selected else "🔄 Comparar",
                        key=f"comp_{aid}",
                    ):
                        current_compare = st.session_state.get("hist_compare_ids", [])
                        if aid in current_compare:
                            current_compare.remove(aid)
                        else:
                            if len(current_compare) >= 2:
                                current_compare.pop(0)
                            current_compare.append(aid)
                        st.session_state["hist_compare_ids"] = current_compare
                        st.session_state.pop("hist_show_comparison", None)
                        st.rerun()
                    if st.button("🗑️ Excluir", key=f"del_{aid}"):
                        st.session_state["hist_delete_confirm"] = aid
                        st.rerun()

    # ───────────────────── Visualização de Detalhe ─────────────────────
    if st.session_state.get("hist_view_id") and not st.session_state.get(
        "hist_show_comparison"
    ):
        analysis = get_analysis(st.session_state["hist_view_id"])
        if analysis:
            st.markdown("---")
            st.markdown(f"## 📄 Detalhes: {analysis['nome']}")
            data_str = analysis["data_criacao"][:16].replace("T", " ")
            st.caption(f"📅 Criada em: {data_str}")
            if analysis["descricao"]:
                st.info(f"📝 {analysis['descricao']}")

            # Imagem original
            st.image(
                analysis["image_bytes"],
                caption=f"Diagrama: {analysis['image_name']}",
                use_container_width=True,
            )

            # Resultados completos
            render_analysis_results(
                analysis["architecture_data"], analysis["stride_data"]
            )

    # ───────────────────── Comparação Lado a Lado ─────────────────────
    if st.session_state.get("hist_show_comparison"):
        compare_ids = st.session_state.get("hist_compare_ids", [])
        if len(compare_ids) == 2:
            analysis_a = get_analysis(compare_ids[0])
            analysis_b = get_analysis(compare_ids[1])

            if analysis_a and analysis_b:
                st.markdown("---")
                st.markdown("## 📊 Comparação de Análises")

                col_a, col_b = st.columns(2)

                for col, analysis in [(col_a, analysis_a), (col_b, analysis_b)]:
                    with col:
                        st.markdown(f"### {analysis['nome']}")
                        data_str = analysis["data_criacao"][:16].replace("T", " ")
                        st.caption(f"📅 {data_str}")

                        # Imagem
                        st.image(
                            analysis["image_bytes"],
                            caption=analysis["image_name"],
                            use_container_width=True,
                        )

                        arch = analysis["architecture_data"]
                        stride = analysis["stride_data"]
                        analise_list = stride.get("analise_stride", [])

                        # Métricas
                        m1, m2, m3 = st.columns(3)
                        m1.metric("🧩 Componentes", len(arch.get("componentes", [])))
                        m2.metric("⚠️ Ameaças", len(analise_list))
                        criticas = len(
                            [
                                a
                                for a in analise_list
                                if a.get("severidade") == "Crítica"
                            ]
                        )
                        m3.metric("🔴 Críticas", criticas)

                        # Distribuição STRIDE
                        st.markdown("**Distribuição por Categoria STRIDE:**")
                        for cat in [
                            "Spoofing",
                            "Tampering",
                            "Repudiation",
                            "Information Disclosure",
                            "Denial of Service",
                            "Elevation of Privilege",
                        ]:
                            count = len(
                                [
                                    a
                                    for a in analise_list
                                    if a.get("categoria_stride") == cat
                                ]
                            )
                            if count > 0:
                                nome_pt = STRIDE_CATEGORIES.get(cat, {}).get(
                                    "nome_pt", cat
                                )
                                st.write(f"- **{cat}** ({nome_pt}): {count}")

                        # Distribuição por severidade
                        st.markdown("**Distribuição por Severidade:**")
                        for sev in ["Crítica", "Alta", "Média", "Baixa"]:
                            count = len(
                                [a for a in analise_list if a.get("severidade") == sev]
                            )
                            if count > 0:
                                st.write(f"- **{sev}:** {count}")

                        # Top recomendações
                        recs = stride.get("recomendacoes_prioritarias", [])[:3]
                        if recs:
                            st.markdown("**Top 3 Recomendações:**")
                            for i, r in enumerate(recs, 1):
                                st.write(f"{i}. {r}")

                # ─── Resumo com Deltas ───
                st.markdown("---")
                st.markdown("### 📈 Resumo da Comparação")

                arch_a = analysis_a["architecture_data"]
                arch_b = analysis_b["architecture_data"]
                stride_a = analysis_a["stride_data"]
                stride_b = analysis_b["stride_data"]

                comp_a = len(arch_a.get("componentes", []))
                comp_b = len(arch_b.get("componentes", []))
                ameacas_a = len(stride_a.get("analise_stride", []))
                ameacas_b = len(stride_b.get("analise_stride", []))
                crit_a = len(
                    [
                        a
                        for a in stride_a.get("analise_stride", [])
                        if a.get("severidade") == "Crítica"
                    ]
                )
                crit_b = len(
                    [
                        a
                        for a in stride_b.get("analise_stride", [])
                        if a.get("severidade") == "Crítica"
                    ]
                )

                dc1, dc2, dc3 = st.columns(3)
                dc1.metric(
                    "🧩 Componentes",
                    f"{comp_a} → {comp_b}",
                    delta=comp_b - comp_a,
                )
                dc2.metric(
                    "⚠️ Ameaças",
                    f"{ameacas_a} → {ameacas_b}",
                    delta=ameacas_b - ameacas_a,
                    delta_color="inverse",
                )
                dc3.metric(
                    "🔴 Críticas",
                    f"{crit_a} → {crit_b}",
                    delta=crit_b - crit_a,
                    delta_color="inverse",
                )
