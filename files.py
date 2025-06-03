#!/usr/bin/env python3
"""
Gerador de dados de teste para o simulador de memória virtual
Cria arquivos addresses.txt e backing_store.bin para teste
"""

import random
import struct
import os

def create_addresses_file():
    """Cria arquivo addresses.txt com endereços de teste"""
    addresses = [
        19986,    # Exemplo do enunciado
        1024,     # Início da página 0 (4KB pages)
        2048,     # Página 0, offset 2048
        4096,     # Início da página 1
        8192,     # Início da página 2
        16384,    # Início da página 4
        32768,    # Início da página 8
        65535,    # Endereço máximo para 16 bits
        # Alguns endereços aleatórios para 16 bits
        *[random.randint(0, 65535) for _ in range(5)],
        # Endereços para teste de 32 bits (exemplo, supondo page size 4KB)
        0x12345678, # Exemplo 32 bits
        0xFF00FF00, # Exemplo 32 bits
        *[random.randint(0, 0xFFFFFFFF) for _ in range(5)] # Endereços aleatórios 32 bits
    ]
    
    with open('addresses.txt', 'w') as f:
        f.write("# Arquivo de endereços para teste do simulador\n")
        f.write("# Cada linha contém um endereço virtual\n")
        f.write("# Suporta decimal, hexadecimal (0x) e binário (0b)\n\n")
        
        for addr in addresses:
            f.write(f"{addr}\n")
            
        f.write("\n# Endereços em hexadecimal\n")
        for i in range(5):
            addr = random.randint(0, 65535) # Mais alguns 16-bit hex
            f.write(f"0x{addr:X}\n")
        for i in range(3):
            addr = random.randint(0, 0xFFFFFFFF) # Mais alguns 32-bit hex
            f.write(f"0x{addr:X}\n")

    print("Arquivo 'addresses.txt' criado com sucesso!")

def create_backing_store_file(filename="backing_store.bin", num_pages_total_virtual_space=2**20, page_size_bytes=4096):
    """
    Cria um arquivo binário de backing store.
    O tamanho é baseado em um espaço de endereço virtual grande (ex: 20 bits para número de página = 2^20 páginas)
    para garantir que qualquer página (L1+L2 para 32 bits) possa ser teoricamente encontrada.
    Para um sistema de 32 bits com páginas de 4KB (12 bits offset), temos 20 bits para o número da página.
    Limitaremos o tamanho do arquivo para algo mais gerenciável para a simulação, e.g., 256MB.
    Max virtual pages = 2^(32-12) = 2^20.
    Max backing store size = 2^20 * 4KB = 4TB. Isso é muito grande.
    Let's create a smaller backing store, e.g., for 2^10 = 1024 pages (4MB).
    This means virtual page numbers requested beyond 1023 will "miss" the backing store if not careful.
    The simulator should handle requests for pages not present in a finite backing_store.bin.
    For this assignment, we will make it large enough to cover typical test cases.
    Let's make it cover 2^8 = 256 pages. 256 * 4096 = 1MB.
    """
    num_pages_to_create = 256 # Simulating 256 pages in the backing store
    actual_total_size = num_pages_to_create * page_size_bytes
    data = bytearray(actual_total_size)
    print(f"Criando '{filename}' com {num_pages_to_create} páginas de {page_size_bytes}B cada. Total: {actual_total_size / (1024):.2f} KB.")
    
    for i in range(actual_total_size):
        # Padrão: valor do byte = (endereço_no_backing_store) % 256
        data[i] = i % 256 
    
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"Arquivo '{filename}' criado com sucesso ({actual_total_size} bytes)!")
    except IOError as e:
        print(f"Erro ao criar o arquivo '{filename}': {e}")


def create_test_script():
    """Cria script de teste para demonstrar funcionalidades"""
    script = f'''#!/bin/bash
# Script de teste para o simulador de memória virtual

echo "=== Testando Simulador de Memória Virtual (16-bit, 4KB page) ==="
EXE_CMD="python3 virtual_memory_translate.py" # Assume python3 está no PATH

echo -e "\\n1. Teste com endereço único (exemplo do enunciado, 16-bit):"
$EXE_CMD 19986 16 4096

echo -e "\\n2. Teste com endereço hexadecimal (16-bit):"
$EXE_CMD 0x4E12 16 4096

echo -e "\\n3. Teste com arquivo de endereços (configurações mistas serão definidas no simulador ou por linha de comando):"
# O simulador usará os padrões (16-bit, 4KB) se não especificado para cada linha no arquivo.
# Para testar diferentes configs com o arquivo, o simulador precisaria de mais lógica
# ou o arquivo de endereços precisaria especificar a configuração por linha.
# Por simplicidade, testaremos o arquivo com uma configuração padrão.
$EXE_CMD addresses.txt 16 4096 

echo -e "\\n4. Teste com endereço inválido (16-bit):"
$EXE_CMD 100000 16 4096 # 65535 é o máx para 16-bit

echo -e "\\n=== Testando Simulador de Memória Virtual (32-bit, 4KB page, Hierárquico) ==="
echo -e "\\n5. Teste com endereço único (32-bit):"
$EXE_CMD 0x12345678 32 4096

echo -e "\\n6. Teste com endereço fora do backing_store simulado (32-bit):"
# (256 pages * 4096 B/page) = 0x100000. Endereço 0x100000 é o início da página 256.
# Se backing_store tem 256 páginas (0-255), esta página não estará no arquivo.
$EXE_CMD 0x100000 32 4096 # Equivalente à página 256, offset 0.

echo -e "\\n7. Teste com arquivo de endereços (32-bit, 4KB page):"
$EXE_CMD addresses.txt 32 4096

echo -e "\\n=== Testes concluídos ==="
'''
    
    with open('test_simulator.sh', 'w') as f:
        f.write(script)
    
    # Torna o script executável (no Linux/Mac)
    if os.name != 'nt': # Não aplicável diretamente no Windows CMD, mas bom para WSL/Git Bash
        os.chmod('test_simulator.sh', 0o755)
    
    print("Script de teste 'test_simulator.sh' criado!")

def main():
    """Função principal"""
    print("Gerando arquivos de teste para o simulador de memória virtual...")
    
    create_addresses_file()
    # Usando 4KB page size para o backing store, como é comum e usado no exemplo de 32-bit
    create_backing_store_file(page_size_bytes=4096) 
    create_test_script()
    
    print("\\nArquivos criados:")
    print("- addresses.txt: Endereços para teste")
    print("- backing_store.bin: Dados simulados da memória de apoio (backing store)")
    print("- test_simulator.sh: Script de teste")
    print("\\nPara executar os testes, rode: ./test_simulator.sh (no Linux/Mac ou Git Bash no Windows)")
    print("Ou execute manualmente, por exemplo:")
    print("  python3 virtual_memory_translate.py 19986 16 4096")
    print("  python3 virtual_memory_translate.py addresses.txt 32 4096")

if __name__ == "__main__":
    main()