# Sample AI application fixture — used by test_python_imports.py.
# This file intentionally imports several AI/ML libraries to exercise the scanner.
# No real credentials or API calls are made.

import openai
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain
from transformers import pipeline
import deepseek
import dashscope

# Simulate openai client usage
client = openai.OpenAI()

# Simulate a LangChain chain
llm = ChatOpenAI(model="gpt-4o")

# Simulate a HuggingFace local pipeline
classifier = pipeline("text-classification")

# Simulate DeepSeek usage (Chinese AI provider)
ds_client = deepseek.Client()

# Simulate Alibaba Qwen/Tongyi via dashscope (Chinese AI provider)
dashscope.api_key = "REDACTED"
