import streamlit as st
import json
import requests
import os

# Configuração da página
st.set_page_config(
    page_title="Análise de Segurança Web",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Título e descrição
st.title("🔒 Análise de Segurança Web: Auditoria de Cabeçalhos HTTP")
st.markdown("""
Esta ferramenta realiza uma auditoria abrangente dos cabeçalhos HTTP, cookies e configurações de segurança 
de uma página web para identificar vulnerabilidades, classificá-las por gravidade e fornecer recomendações 
precisas de correção que sigam os padrões OWASP e as melhores práticas do setor.
""")

# Sidebar com informações
with st.sidebar:
    st.header("Sobre esta ferramenta")
    st.markdown("""
    ### Funcionalidades
    - Análise de cabeçalhos HTTP de segurança
    - Verificação de configurações de cookies
    - Análise de políticas de segurança de conteúdo (CSP)
    - Classificação de vulnerabilidades por gravidade
    - Geração de recomendações de correção
    
    ### Como usar
    1. Insira a URL do site a ser analisado ou cole os cabeçalhos HTTP em formato JSON
    2. Clique em "Analisar Segurança"
    3. Revise o relatório detalhado de segurança
    
    ### Referências
    - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
    - [Mozilla Observatory](https://observatory.mozilla.org/)
    - [Security Headers](https://securityheaders.com/)
    """)

# Função para analisar cabeçalhos HTTP
def analyze_headers(headers_json):
    """
    Analisa cabeçalhos HTTP e gera um relatório de segurança.
    
    Args:
        headers_json: Cabeçalhos HTTP em formato JSON.
        
    Returns:
        Relatório de auditoria de segurança.
    """
    try:
        # Analisar cabeçalhos
        headers = json.loads(headers_json)
        
        # Cabeçalhos de segurança importantes a verificar
        security_headers = {
            "Strict-Transport-Security": {
                "present": False,
                "value": None,
                "recommendation": "Adicionar o cabeçalho Strict-Transport-Security com valor 'max-age=31536000; includeSubDomains'"
            },
            "Content-Security-Policy": {
                "present": False,
                "value": None,
                "recommendation": "Implementar uma política CSP adequada para prevenir ataques XSS"
            },
            "X-Content-Type-Options": {
                "present": False,
                "value": None,
                "recommendation": "Adicionar o cabeçalho X-Content-Type-Options com valor 'nosniff'"
            },
            "X-Frame-Options": {
                "present": False,
                "value": None,
                "recommendation": "Adicionar o cabeçalho X-Frame-Options com valor 'SAMEORIGIN'"
            },
            "X-XSS-Protection": {
                "present": False,
                "value": None,
                "recommendation": "Adicionar o cabeçalho X-XSS-Protection com valor '1; mode=block'"
            },
            "Referrer-Policy": {
                "present": False,
                "value": None,
                "recommendation": "Adicionar o cabeçalho Referrer-Policy com valor 'strict-origin-when-cross-origin'"
            },
            "Permissions-Policy": {
                "present": False,
                "value": None,
                "recommendation": "Implementar uma política de permissões adequada"
            },
            "Cache-Control": {
                "present": False,
                "value": None,
                "recommendation": "Configurar Cache-Control adequadamente para conteúdo sensível"
            }
        }
        
        # Verificar cabeçalhos presentes
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()
            for security_header in security_headers:
                if security_header.lower() == header_name_lower:
                    security_headers[security_header]["present"] = True
                    security_headers[security_header]["value"] = header_value
        
        # Preparar resultado da análise
        analysis = {
            "present_headers": {},
            "missing_headers": {}
        }
        
        for header_name, header_info in security_headers.items():
            if header_info["present"]:
                analysis["present_headers"][header_name] = {
                    "value": header_info["value"]
                }
            else:
                analysis["missing_headers"][header_name] = {
                    "recommendation": header_info["recommendation"]
                }
        
        # Contar problemas
        missing_headers_count = len(analysis["missing_headers"])
        
        # Classificar problemas por gravidade
        critical_issues = []
        high_issues = []
        medium_issues = []
        low_issues = []
        
        # Classificação de gravidade para cabeçalhos ausentes
        severity_classification = {
            "Strict-Transport-Security": "Alta",
            "Content-Security-Policy": "Alta",
            "X-Content-Type-Options": "Média",
            "X-Frame-Options": "Média",
            "X-XSS-Protection": "Média",
            "Referrer-Policy": "Baixa",
            "Permissions-Policy": "Baixa",
            "Cache-Control": "Média"
        }
        
        # Classificar problemas
        for header_name, header_info in analysis["missing_headers"].items():
            severity = severity_classification.get(header_name, "Baixa")
            issue = {
                "header": header_name,
                "recommendation": header_info["recommendation"]
            }
            
            if severity == "Crítica":
                critical_issues.append(issue)
            elif severity == "Alta":
                high_issues.append(issue)
            elif severity == "Média":
                medium_issues.append(issue)
            else:
                low_issues.append(issue)
        
        # Identificar os 3 problemas mais urgentes
        urgent_issues = critical_issues + high_issues + medium_issues + low_issues
        top_3_issues = urgent_issues[:3]
        
        # Gerar relatório
        report = []
        
        # Título
        report.append("# Análise de Segurança Web: Auditoria de Cabeçalhos HTTP e Configurações\n")
        
        # 1. Resumo Executivo
        report.append("## 1. Resumo Executivo\n")
        report.append(f"- Número total de problemas encontrados: {missing_headers_count}")
        report.append(f"- Distribuição por gravidade:")
        report.append(f"  - Crítica: {len(critical_issues)}")
        report.append(f"  - Alta: {len(high_issues)}")
        report.append(f"  - Média: {len(medium_issues)}")
        report.append(f"  - Baixa: {len(low_issues)}")
        
        report.append("\n### Os 3 problemas mais urgentes que devem ser corrigidos imediatamente:\n")
        
        for i, issue in enumerate(top_3_issues):
            report.append(f"{i+1}. **{issue['header']}**: {issue['recommendation']}")
        
        report.append("\n")
        
        # 2. Cabeçalhos de Segurança Presentes
        report.append("## 2. Cabeçalhos de Segurança Presentes\n")
        
        if analysis["present_headers"]:
            for header_name, header_info in analysis["present_headers"].items():
                report.append(f"**{header_name}**")
                report.append(f"- **Presente?** Sim")
                report.append(f"- **Valor:** `{header_info['value']}`")
                report.append(f"- **Avaliação:** Adequado\n")
        else:
            report.append("Nenhum cabeçalho de segurança presente.\n")
        
        # 3. Análise Detalhada de Problemas
        report.append("## 3. Análise Detalhada de Problemas\n")
        
        # 3.1 Segurança de Cabeçalhos
        report.append("### 3.1 Segurança de Cabeçalhos\n")
        
        if analysis["missing_headers"]:
            for header_name, header_info in analysis["missing_headers"].items():
                severity = severity_classification.get(header_name, "Baixa")
                
                report.append(f"**{header_name}**")
                report.append(f"- **Presente?** Não")
                report.append(f"- **Gravidade:** {severity}")
                
                if header_name == "Strict-Transport-Security":
                    report.append(f"- **Implicações de Segurança:** A ausência deste cabeçalho permite ataques de downgrade SSL/TLS, onde um atacante pode forçar o uso de conexões HTTP não seguras.")
                    report.append(f"- **Recomendação:** {header_info['recommendation']}")
                    report.append(f"- **Exemplo de Implementação:**")
                    report.append(f"  ```")
                    report.append(f"  # Apache")
                    report.append(f"  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"")
                    report.append(f"  ")
                    report.append(f"  # Nginx")
                    report.append(f"  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;")
                    report.append(f"  ```")
                    report.append(f"- **Referência:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)")
                
                elif header_name == "X-Content-Type-Options":
                    report.append(f"- **Implicações de Segurança:** A ausência deste cabeçalho permite ataques de MIME sniffing, onde o navegador pode interpretar arquivos de forma diferente do que o servidor pretendia.")
                    report.append(f"- **Recomendação:** {header_info['recommendation']}")
                    report.append(f"- **Exemplo de Implementação:**")
                    report.append(f"  ```")
                    report.append(f"  # Apache")
                    report.append(f"  Header always set X-Content-Type-Options \"nosniff\"")
                    report.append(f"  ")
                    report.append(f"  # Nginx")
                    report.append(f"  add_header X-Content-Type-Options \"nosniff\" always;")
                    report.append(f"  ```")
                    report.append(f"- **Referência:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)")
                
                else:
                    report.append(f"- **Implicações de Segurança:** A ausência deste cabeçalho reduz a postura de segurança da aplicação.")
                    report.append(f"- **Recomendação:** {header_info['recommendation']}")
                    report.append(f"- **Referência:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)")
                
                report.append("")
        else:
            report.append("Nenhum problema de cabeçalho identificado.\n")
        
        # 3.2 Segurança de Cookies
        report.append("### 3.2 Segurança de Cookies\n")
        
        # Analisar cookies a partir dos cabeçalhos
        cookie_issues = []
        
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                # Verificar flags de segurança
                if "secure" not in header_value.lower():
                    cookie_issues.append("Cookie sem flag Secure")
                if "httponly" not in header_value.lower():
                    cookie_issues.append("Cookie sem flag HttpOnly")
                if "samesite" not in header_value.lower():
                    cookie_issues.append("Cookie sem atributo SameSite")
        
        if cookie_issues:
            for issue in cookie_issues:
                report.append(f"**{issue}**")
                report.append(f"- **Gravidade:** Alta")
                report.append(f"- **Implicações de Segurança:** Cookies sem as flags de segurança adequadas podem ser acessados por scripts maliciosos ou transmitidos em conexões não seguras.")
                report.append(f"- **Recomendação:** Adicionar as flags de segurança apropriadas a todos os cookies.")
                report.append(f"- **Exemplo de Implementação:**")
                report.append(f"  ```")
                report.append(f"  # PHP")
                report.append(f"  setcookie('nome', 'valor', ['expires' => time() + 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);")
                report.append(f"  ```")
                report.append(f"- **Referência:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)")
                report.append("")
        else:
            report.append("Nenhum problema de cookie identificado ou nenhum cookie presente.\n")
        
        # 3.3 Segurança de Conteúdo
        report.append("### 3.3 Segurança de Conteúdo\n")
        
        if "Content-Security-Policy" not in analysis["present_headers"]:
            report.append("**Política de Segurança de Conteúdo (CSP) ausente**")
            report.append("- **Presente?** Não")
            report.append("- **Gravidade:** Alta")
            report.append("- **Implicações de Segurança:** A ausência de uma Política de Segurança de Conteúdo aumenta o risco de ataques XSS e injeção de conteúdo malicioso.")
            report.append("- **Recomendação:** Implementar uma política CSP adequada para restringir as fontes de conteúdo.")
            report.append("- **Exemplo de Implementação:**")
            report.append("  ```")
            report.append("  # Apache")
            report.append("  Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' https://trusted-cdn.com; img-src 'self' data:;\"")
            report.append("  ")
            report.append("  # Nginx")
            report.append("  add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' https://trusted-cdn.com; img-src 'self' data:;\" always;")
            report.append("  ```")
            report.append("- **Referência:** [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)")
        else:
            report.append("Política de Segurança de Conteúdo (CSP) presente e configurada.\n")
        
        # 4. Recomendações Priorizadas
        report.append("## 4. Recomendações Priorizadas\n")
        
        all_issues = []
        
        # Adicionar problemas de cabeçalhos
        for header_name, header_info in analysis["missing_headers"].items():
            severity = severity_classification.get(header_name, "Baixa")
            
            # Determinar esforço e benefício
            effort = "Baixo"
            benefit = "Alto" if severity in ["Crítica", "Alta"] else "Médio"
            
            all_issues.append({
                "description": f"Adicionar cabeçalho {header_name}",
                "severity": severity,
                "effort": effort,
                "benefit": benefit
            })
        
        # Adicionar problemas de cookies
        for issue in cookie_issues:
            all_issues.append({
                "description": f"Corrigir {issue}",
                "severity": "Alta",
                "effort": "Baixo",
                "benefit": "Alto"
            })
        
        # Ordenar por gravidade, depois por esforço (do menor para o maior)
        severity_order = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3}
        effort_order = {"Baixo": 0, "Médio": 1, "Alto": 2}
        
        sorted_issues = sorted(all_issues, key=lambda x: (severity_order.get(x["severity"], 4), effort_order.get(x["effort"], 3)))
        
        # Adicionar recomendações ao relatório
        for i, issue in enumerate(sorted_issues):
            report.append(f"{i+1}. **{issue['description']}**")
            report.append(f"   - Gravidade: {issue['severity']}")
            report.append(f"   - Esforço estimado: {issue['effort']}")
            report.append(f"   - Benefício de segurança: {issue['benefit']}")
            report.append("")
        
        # 5. Considerações Adicionais
        report.append("## 5. Considerações Adicionais\n")
        
        report.append("### Possíveis impactos na funcionalidade")
        report.append("- A implementação de uma política CSP restritiva pode quebrar funcionalidades que dependem de scripts inline ou recursos de terceiros não autorizados.")
        report.append("- O cabeçalho X-Frame-Options pode impedir que seu site seja exibido em frames, o que pode afetar integrações com outros sites.")
        report.append("- Cookies com SameSite=Strict podem afetar fluxos de autenticação de terceiros.\n")
        
        report.append("### Testes recomendados após as alterações")
        report.append("- Verificar se todas as funcionalidades do site continuam operando corretamente após a implementação dos cabeçalhos de segurança.")
        report.append("- Testar fluxos de autenticação e sessão para garantir que as alterações nos cookies não causem problemas.")
        report.append("- Verificar se recursos de terceiros necessários continuam funcionando após a implementação da CSP.\n")
        
        report.append("### Ferramentas de verificação recomendadas")
        report.append("- [Mozilla Observatory](https://observatory.mozilla.org/)")
        report.append("- [Security Headers](https://securityheaders.com/)")
        report.append("- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)")
        report.append("- [OWASP ZAP](https://www.zaproxy.org/) para testes de segurança mais abrangentes")
        
        # Juntar tudo
        return "\n".join(report)
    
    except Exception as e:
        return f"Erro ao gerar relatório: {str(e)}"

# Criar abas para diferentes métodos de entrada
tab1, tab2 = st.tabs(["Analisar por URL", "Analisar Cabeçalhos JSON"])

with tab1:
    st.header("Analisar segurança por URL")
    url = st.text_input("Digite a URL do site a ser analisado (incluindo https://)", placeholder="https://exemplo.com")
    
    analyze_url_button = st.button("Analisar URL", key="analyze_url")
    
    if analyze_url_button and url:
        with st.spinner("Analisando cabeçalhos HTTP da URL..."):
            try:
                # Fazer a requisição para obter os cabeçalhos
                response = requests.get(url, allow_redirects=True)
                headers = dict(response.headers)
                
                # Converter para JSON
                headers_json = json.dumps(headers)
                
                # Executar a auditoria
                audit_report = analyze_headers(headers_json)
                
                # Exibir os cabeçalhos obtidos
                st.subheader("Cabeçalhos HTTP obtidos")
                st.json(headers)
                
                # Exibir o relatório
                st.subheader("Relatório de Auditoria de Segurança")
                st.markdown(audit_report)
                
                # Opção para download do relatório
                st.download_button(
                    label="Baixar Relatório",
                    data=audit_report,
                    file_name="relatorio_seguranca.md",
                    mime="text/markdown"
                )
            except Exception as e:
                st.error(f"Erro ao analisar a URL: {str(e)}")

with tab2:
    st.header("Analisar cabeçalhos HTTP em formato JSON")
    
    # Exemplo de cabeçalhos para ajudar o usuário
    example_headers = {
        "Server": "nginx/1.18.0",
        "Date": "Mon, 21 Apr 2025 14:30:00 GMT",
        "Content-Type": "text/html; charset=UTF-8",
        "Connection": "keep-alive",
        "X-Powered-By": "PHP/7.4.3",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache"
    }
    
    st.markdown("Insira os cabeçalhos HTTP em formato JSON:")
    
    # Botão para carregar exemplo
    if st.button("Carregar Exemplo"):
        headers_input = json.dumps(example_headers, indent=2)
    else:
        headers_input = ""
    
    # Área de texto para entrada dos cabeçalhos
    headers_input = st.text_area("Cabeçalhos HTTP (JSON)", value=headers_input, height=300)
    
    analyze_json_button = st.button("Analisar Cabeçalhos", key="analyze_json")
    
    if analyze_json_button and headers_input:
        with st.spinner("Analisando cabeçalhos HTTP..."):
            try:
                # Validar JSON
                headers = json.loads(headers_input)
                
                # Executar a auditoria
                audit_report = analyze_headers(headers_input)
                
                # Exibir o relatório
                st.subheader("Relatório de Auditoria de Segurança")
                st.markdown(audit_report)
                
                # Opção para download do relatório
                st.download_button(
                    label="Baixar Relatório",
                    data=audit_report,
                    file_name="relatorio_seguranca.md",
                    mime="text/markdown"
                )
            except json.JSONDecodeError:
                st.error("Erro: O formato JSON é inválido. Verifique a sintaxe e tente novamente.")
            except Exception as e:
                st.error(f"Erro ao analisar os cabeçalhos: {str(e)}")

# Rodapé
st.markdown("---")
st.markdown("Desenvolvido com ❤️ usando Streamlit")
