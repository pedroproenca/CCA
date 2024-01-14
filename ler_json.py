#!/usr/bin/python3
#ler_json.py

""" 
************************************************************************
Descricao: Leitura de logs json da aplicação testssl.sh
Data criacao: 4 janeiro, 2024
Data modificacao: 6 janeiro, 2024
Python Versao: 3.10.12
Comentarios:
    - Criado no âmbito da disciplina CCA
    - Lê os logs em formato json da app testssl.sh
    - Logs json e output.txt têm que estar no diretorio do ler_json.py
************************************************************************
"""

import os
import json

pasta = os.path.dirname(os.path.abspath(__file__))  
saida = os.path.join(pasta, 'output.txt')  # Nome do arquivo de saída

# Sets DE IPs
ips_ssl_3_0 = set()
ips_tls_1_0 = set()
ips_tls_1_1 = set()
ips_tls_1_2 = set()
ips_tls_1_3 = set()
ips_com_protocolo_1_2_1_3 = set()

# Lista Topo
tls_topo_1_2 = []
tls_topo_1_2 = []

##V Vulnerabilidades e Erros
ips_fallback_scsv = set()
ips_hs_failure = set()
ips_vulneravel_downgrade = set()
ips_low_severity = set()
ips_medium_severity = set()
ips_high_severity = set()
ips_warn_severity = set()
ips_erro_tls_1_3 = []
ips_cifras_vuln = set()

try:
    with open(saida, 'w') as arquivo_saida:
        nr_sites = 0
        for arquivo in os.listdir(pasta):
            if arquivo.endswith('.json'):
                nr_sites += 1
                caminho_arquivo = os.path.join(pasta, arquivo)
                with open(caminho_arquivo, 'r') as f:
                    dados = json.load(f) 
                    ## Pesquisa em cada Item
                    for item in dados:
                        ## IP de cada dominio
                        if 'ip' in item:
                            ip = item['ip'].split('/')[0].rstrip('/')
                        ## Contagem de protocolos
                        if item['id'] == 'SSLv3':
                            if item['finding'] == 'offered':
                                ips_ssl_3_0.add(ip)
                        elif item['id'] == 'TLS1':
                            if item['finding'] == 'offered (deprecated)':
                                ips_tls_1_0.add(ip)
                        elif item['id'] == 'TLS1_1':
                            if item['finding'] == 'offered (deprecated)':
                                ips_tls_1_1.add(ip)
                        elif item['id'] == 'TLS1_2':
                            if item['finding'] == 'offered':
                                ips_tls_1_2.add(ip)
                        elif item['id'] == 'TLS1_3':
                            if item['finding'] == 'offered with final':
                                ips_tls_1_3.add(ip)
                        elif 'cipherlist' in item['id']:
                            if item['severity'] != 'OK' and item['severity'] != 'INFO':
                                ips_cifras_vuln.add(ip)
                        ## Downgrade attack
                        elif item['id'] == 'fallback_SCSV':
                            if item['finding'] == 'supported':
                                ips_fallback_scsv.add(ip)
                            elif item['finding'] == 'no protocol below TLS 1.2 offered':
                                ips_com_protocolo_1_2_1_3.add(ip)
                            elif item['finding'] == 'NOT supported. Pls rerun with POODLE SSL check':
                                ips_vulneravel_downgrade.add(ip)
                            elif item['finding'] == '''some unexpected 'handshake failure' instead of 'inappropriate fallback' (likely: warning)''':
                                ips_hs_failure.add(ip)
   
        print("A iniciar escrita...")
     
        ips_so_com_protocolo_1_3 = ips_tls_1_3.difference(ips_tls_1_2) 
        ips_so_com_protocolo_1_2 = ips_com_protocolo_1_2_1_3.difference(ips_tls_1_3) 
        ips_topo_protocolo_1_2 = ips_tls_1_2.difference(ips_tls_1_3)
        conjunto_vulneraveis = ips_ssl_3_0.union(ips_tls_1_0, ips_tls_1_1)
        possivelmente_vulneraveis = sorted(list(conjunto_vulneraveis))
        ips_vulneraveis_que_nao_estao_em_tls_1_2 = conjunto_vulneraveis.difference(ips_tls_1_2) 
        ips_tls_1_3_mas_com_versoes_abaixo_de_1_2 = set(possivelmente_vulneraveis).intersection(ips_tls_1_3)
        ips_tls_1_2_mas_com_versoes_abaixo_de_1_2 = set(possivelmente_vulneraveis).intersection(ips_tls_1_2)

        ## Total de sites lidos
        arquivo_saida.write(f"\n\nTotal de domínios de IES portuguesas analisados: {nr_sites}\n\n")
        
        ## Contagem de protocolos
        arquivo_saida.write(f"\nContagem de protocolos::\n\n")
        arquivo_saida.write(f"\tQue usam SSLv3: {len(ips_ssl_3_0)} IPs\n")
        arquivo_saida.write(f"\tQue usam TLS 1.0: {len(ips_tls_1_0)} IPs\n")
        arquivo_saida.write(f"\tQue usam TLS 1.1: {len(ips_tls_1_1)} IPs\n")
        arquivo_saida.write(f"\tQue usam TLS 1.2: {len(ips_tls_1_2)} IPs\n")
        arquivo_saida.write(f"\tQue usam TLS 1.3: {len(ips_tls_1_3)} IPs\n\n")
        
        ## Sites seguros
        arquivo_saida.write(f"\nSites com versoes iguais ou superiores a 1.2:\n\n")
        arquivo_saida.write(f"\tQue apenas usam 1.2: {len(ips_so_com_protocolo_1_2)}\n")
        arquivo_saida.write(f"\t{ips_so_com_protocolo_1_2}\n\n")
        arquivo_saida.write(f"\tQue apenas usam TLS 1.3: {len(ips_so_com_protocolo_1_3)}\n")
        arquivo_saida.write(f"\t{ips_so_com_protocolo_1_3}\n\n")
        arquivo_saida.write(f"\tQue não usam versões abaixo de TLS 1.2: {len(ips_com_protocolo_1_2_1_3)} IPs\n")
        arquivo_saida.write(f"\t{ips_com_protocolo_1_2_1_3}\n\n")
        
        ## Protocolos mais altos do domínio
        arquivo_saida.write(f"\nProtocolos mais altos de cada domínio:\n\n")
        arquivo_saida.write(f"\tTLS 1.2: {len(ips_topo_protocolo_1_2)}\n")
        arquivo_saida.write(f"\t{ips_topo_protocolo_1_2}\n\n")
        arquivo_saida.write(f"\tTLS 1.3: {len(ips_tls_1_3)}\n")
        arquivo_saida.write(f"\t{ips_tls_1_3}\n\n")
        
        ## Sites com erros ou possivelmente vulneraveis
        arquivo_saida.write(f"\nSites com erros e/ou possivelmente vulneraveis:\n\n")
        arquivo_saida.write(f"\tCom cifras inseguras: {len(ips_cifras_vuln)}\n")
        arquivo_saida.write(f"\t{ips_cifras_vuln}\n\n\n")      
        arquivo_saida.write(f"\tCom versões abaixo de TLS 1.2: {len(possivelmente_vulneraveis)}\n")
        arquivo_saida.write(f"\t{possivelmente_vulneraveis}\n\n\n")
        arquivo_saida.write(f"\t\tQue têm TLS 1.3 mas versoes abaixo de 1.2: {len(ips_tls_1_3_mas_com_versoes_abaixo_de_1_2)}\n")
        arquivo_saida.write(f"\t\t{ips_tls_1_3_mas_com_versoes_abaixo_de_1_2}\n\n")
        arquivo_saida.write(f"\t\tQue têm TLS 1.2 mas versoes abaixo de 1.2: {len(ips_tls_1_2_mas_com_versoes_abaixo_de_1_2)}\n")
        arquivo_saida.write(f"\t\t{ips_tls_1_2_mas_com_versoes_abaixo_de_1_2}\n\n")
        arquivo_saida.write(f"\t\tQue usam SSL3.0, TLS 1.0, TLS 1.1 que não usam TLS 1.2: {len(ips_vulneraveis_que_nao_estao_em_tls_1_2)}\n")
        arquivo_saida.write(f"\t\t{ips_vulneraveis_que_nao_estao_em_tls_1_2}\n\n")
        arquivo_saida.write(f"\t\tVulnerável a downgrade: {len(ips_vulneravel_downgrade)} IPs\n")
        arquivo_saida.write(f"\t\t{ips_vulneravel_downgrade}\n\n")
        arquivo_saida.write(f"\t\tErro de Handshake: {len(ips_hs_failure)} IPs\n")
        arquivo_saida.write(f"\t\t{ips_hs_failure}\n\n")

        
        print(f"...escrita em {saida} realizada com sucesso!")
        
except Exception as e:
    print(f"Erro na escrita...{e}")