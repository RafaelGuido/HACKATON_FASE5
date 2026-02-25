"""
Módulo de análise de imagens de arquitetura de software usando GPT-4o.

Responsável por:
- Receber imagens de diagramas de arquitetura
- Enviar para o GPT-4o (modelo multimodal) para análise visual
- Extrair componentes identificados na arquitetura
"""

import base64
import json
from openai import OpenAI


SYSTEM_PROMPT_COMPONENTS = """Você é um especialista em segurança de software e arquitetura de sistemas.

Sua tarefa é analisar a imagem de um diagrama de arquitetura de software e identificar TODOS os componentes presentes.

Para cada componente identificado, forneça:
1. **nome**: Nome descritivo do componente
2. **tipo**: Tipo do componente. Use EXATAMENTE um destes valores:
   - "usuario" (usuário/ator externo)
   - "aplicacao_web" (aplicação web/frontend)
   - "aplicacao_mobile" (aplicação móvel)
   - "api" (API/endpoint REST/GraphQL/SOAP)
   - "servidor" (servidor/serviço backend)
   - "banco_dados" (banco de dados/datastore)
   - "cache" (sistema de cache como Redis, Memcached)
   - "fila_mensagens" (fila de mensagens como RabbitMQ, Kafka, SQS)
   - "servico_externo" (serviço externo/terceiros)
   - "load_balancer" (balanceador de carga)
   - "firewall" (firewall/WAF)
   - "cdn" (CDN/Content Delivery Network)
   - "gateway" (API Gateway)
   - "autenticacao" (serviço de autenticação/IAM)
   - "storage" (armazenamento de arquivos/blob/S3)
   - "container" (container/Docker/Kubernetes)
   - "rede" (componente de rede/VPN/subnet)
   - "outro" (qualquer outro componente)
3. **descricao**: Breve descrição do papel deste componente no sistema
4. **tecnologia**: Tecnologia específica se identificável (ex: "PostgreSQL", "Node.js", "AWS S3")

Também identifique os FLUXOS DE DADOS entre componentes:
1. **origem**: Nome do componente de origem
2. **destino**: Nome do componente de destino
3. **descricao**: Descrição do fluxo (ex: "Requisição HTTP", "Query SQL")
4. **protocolo**: Protocolo utilizado se identificável (ex: "HTTPS", "TCP", "gRPC")
5. **dados**: Tipo de dados transmitidos se identificável

Responda APENAS com JSON válido no seguinte formato:
{
  "componentes": [
    {
      "nome": "...",
      "tipo": "...",
      "descricao": "...",
      "tecnologia": "...",
      "confianca": 0.95
    }
  ],
  "fluxos": [
    {
      "origem": "...",
      "destino": "...",
      "descricao": "...",
      "protocolo": "...",
      "dados": "...",
      "confianca": 0.90
    }
  ],
  "descricao_geral": "Descrição geral do sistema identificado na imagem",
  "acuracia_estimada": 0.92
}

IMPORTANTE sobre os campos de confiança:
- "confianca" (em cada componente e fluxo): um valor de 0.0 a 1.0 indicando o quão confiante você está na identificação correta daquele item. Use 1.0 quando o item está claramente visível e identificável, e valores menores quando há ambiguidade.
- "acuracia_estimada": um valor de 0.0 a 1.0 representando sua confiança geral na análise completa da imagem. Considere a clareza do diagrama, a legibilidade dos textos e a facilidade de identificar os componentes e fluxos."""


def encode_image_to_base64(image_bytes: bytes) -> str:
    """Codifica bytes de imagem para base64."""
    return base64.b64encode(image_bytes).decode("utf-8")


def analyze_architecture_image(
    client: OpenAI,
    image_bytes: bytes,
    image_type: str = "image/png",
    model: str = "gpt-4o",
) -> dict:
    """
    Analisa uma imagem de diagrama de arquitetura de software usando GPT-4o.

    Args:
        client: Cliente OpenAI configurado
        image_bytes: Bytes da imagem do diagrama
        image_type: MIME type da imagem (image/png, image/jpeg, etc.)
        model: Modelo a ser utilizado

    Returns:
        Dicionário com componentes e fluxos identificados
    """
    base64_image = encode_image_to_base64(image_bytes)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT_COMPONENTS},
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Analise esta imagem de diagrama de arquitetura de software. "
                            "Identifique todos os componentes e fluxos de dados. "
                            "Responda APENAS com o JSON solicitado."
                        ),
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{image_type};base64,{base64_image}",
                            "detail": "high",
                        },
                    },
                ],
            },
        ],
        temperature=0.1,
        max_tokens=16384,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content

    if response.choices[0].finish_reason == "length":
        raise ValueError(
            "A resposta do modelo foi truncada (limite de tokens atingido). "
            "Tente com uma imagem de diagrama mais simples."
        )

    return json.loads(content)
