# Análise de Segurança Web - README

Este é um aplicativo Streamlit para análise de segurança web que audita cabeçalhos HTTP, cookies e configurações de segurança.

## Funcionalidades

- Análise de cabeçalhos HTTP de segurança
- Verificação de configurações de cookies
- Análise de políticas de segurança de conteúdo (CSP)
- Classificação de vulnerabilidades por gravidade
- Geração de recomendações de correção

## Como usar

1. Insira a URL do site a ser analisado ou cole os cabeçalhos HTTP em formato JSON
2. Clique em "Analisar Segurança"
3. Revise o relatório detalhado de segurança

## Instalação local

```bash
pip install -r requirements.txt
streamlit run app_standalone.py
```

## Deploy no Streamlit Cloud

Este aplicativo está pronto para ser implantado no Streamlit Cloud. Siga as instruções em https://streamlit.io/cloud para fazer o deploy.

## Estrutura do projeto

- `app_standalone.py`: Aplicativo Streamlit principal
- `requirements.txt`: Dependências do projeto
- `.gitignore`: Arquivos a serem ignorados pelo Git

## Referências

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Security Headers](https://securityheaders.com/)
