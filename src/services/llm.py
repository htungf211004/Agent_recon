from langchain_openai import ChatOpenAI

from src.config import get_settings


def get_llm() -> ChatOpenAI:
    settings = get_settings()
    return ChatOpenAI(
        model=settings.model_name,
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url,
        temperature=settings.llm_temperature,
    )
