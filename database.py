"""
Módulo de persistência para histórico de análises STRIDE.

Utiliza SQLite para armazenar análises realizadas, incluindo
imagem do diagrama, dados de arquitetura e resultados STRIDE.
"""

import json
import os
import sqlite3
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "stride_history.db")


def init_db() -> None:
    """Cria o diretório de dados e a tabela de análises se não existirem."""
    os.makedirs(DB_DIR, exist_ok=True)
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                nome              TEXT NOT NULL,
                descricao         TEXT DEFAULT '',
                data_criacao      TEXT NOT NULL,
                image_bytes       BLOB NOT NULL,
                image_type        TEXT NOT NULL,
                image_name        TEXT DEFAULT '',
                architecture_data TEXT NOT NULL,
                stride_data       TEXT NOT NULL,
                num_componentes   INTEGER DEFAULT 0,
                num_fluxos        INTEGER DEFAULT 0,
                num_ameacas       INTEGER DEFAULT 0,
                num_criticas      INTEGER DEFAULT 0,
                acuracia_estimada REAL
            )
            """
        )


def _get_connection() -> sqlite3.Connection:
    """Retorna uma conexão SQLite com row_factory configurada."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_analysis(
    nome: str,
    descricao: str,
    image_bytes: bytes,
    image_type: str,
    image_name: str,
    architecture_data: dict,
    stride_data: dict,
) -> int:
    """
    Salva uma análise completa no banco de dados.

    Returns:
        ID da análise inserida.
    """
    analise_stride = stride_data.get("analise_stride", [])

    num_componentes = len(architecture_data.get("componentes", []))
    num_fluxos = len(architecture_data.get("fluxos", []))
    num_ameacas = len(analise_stride)
    num_criticas = len([a for a in analise_stride if a.get("severidade") == "Crítica"])
    acuracia_estimada = architecture_data.get("acuracia_estimada")

    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses (
                nome, descricao, data_criacao,
                image_bytes, image_type, image_name,
                architecture_data, stride_data,
                num_componentes, num_fluxos, num_ameacas,
                num_criticas, acuracia_estimada
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                nome,
                descricao,
                datetime.now().isoformat(),
                image_bytes,
                image_type,
                image_name,
                json.dumps(architecture_data, ensure_ascii=False),
                json.dumps(stride_data, ensure_ascii=False),
                num_componentes,
                num_fluxos,
                num_ameacas,
                num_criticas,
                acuracia_estimada,
            ),
        )
        return cursor.lastrowid


def list_analyses(
    nome_filtro: str | None = None,
    data_inicio: str | None = None,
    data_fim: str | None = None,
) -> list[dict]:
    """
    Lista análises com metadados leves (sem BLOB/JSON).

    Args:
        nome_filtro: Texto para busca parcial no nome ou descrição.
        data_inicio: Data mínima (ISO 8601, ex: "2026-01-01").
        data_fim: Data máxima (ISO 8601, ex: "2026-12-31").

    Returns:
        Lista de dicts com metadados de cada análise.
    """
    query = """
        SELECT id, nome, descricao, data_criacao,
               num_componentes, num_fluxos, num_ameacas,
               num_criticas, acuracia_estimada
        FROM analyses
    """
    conditions = []
    params = []

    if nome_filtro:
        conditions.append("(nome LIKE ? OR descricao LIKE ?)")
        params.extend([f"%{nome_filtro}%", f"%{nome_filtro}%"])

    if data_inicio:
        conditions.append("data_criacao >= ?")
        params.append(data_inicio)

    if data_fim:
        conditions.append("data_criacao <= ?")
        params.append(data_fim + "T23:59:59")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY data_criacao DESC"

    with _get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_analysis(analysis_id: int) -> dict | None:
    """
    Retorna uma análise completa pelo ID, com JSON deserializado.

    Returns:
        Dict completo da análise ou None se não encontrada.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["architecture_data"] = json.loads(result["architecture_data"])
    result["stride_data"] = json.loads(result["stride_data"])
    return result


def delete_analysis(analysis_id: int) -> bool:
    """
    Exclui uma análise pelo ID.

    Returns:
        True se a análise foi excluída, False se não encontrada.
    """
    with _get_connection() as conn:
        cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        return cursor.rowcount > 0
