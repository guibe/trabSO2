#!/usr/bin/env python3
"""
Gerador de dados de teste para o simulador de memória virtual
Cria arquivos addresses.txt e data_memory.txt para teste
"""

import random
import struct

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
        # Alguns endereços aleatórios
        *[random.randint(0, 65535) for _ in range(10)]
    ]
    
    with open('addresses.txt', 'w') as f:
        f.write("# Arquivo de endereços para teste do simulador\n")
        f.write("# Cada linha contém um endereço virtual\n")
        f.write("# Suporta decimal, hexadecimal (0x) e binário (0b)\n\n")
        
        for addr in addresses:
            f.write(f"{addr}\n")
            
        # Adiciona alguns endereços em hexadecimal
        f.write("\n# Endereços em hexadecimal\n")
        for i in range(5):
            addr = random.randint(0, 65535)
            f.write(f"0x{addr:X}\n")
    
    print("Arquivo 'addresses.txt' criado com sucesso!")

def create_data_memory_file():
    """Cria arquivo data_memory.txt com dados simulados"""
    # Cria dados para simular memória física
    # 256KB de dados (64 páginas de 4KB cada)
    total_size = 256 * 1024
    data = bytearray(total_size)
    
    # Preenche com padrão interessante para facilitar debug
    for i in range(total_size):
        page = i // 4096
        offset = i % 4096
        # Cria padrão: byte = (página * 7 + offset) % 256
        data[i] = (page * 7 + offset) % 256
    
    with open('data_memory.txt', 'wb') as f:
        f.write(data)
    
    print("Arquivo 'data_memory.txt' criado com sucesso!")

def create_test_script():
    """Cria script de teste para demonstrar funcionalidades"""
    script = '''#!/bin/bash
# Script de teste para o simulador de memória virtual

echo "=== Testando Simulador de Memória Virtual ==="

echo -e "\n1. Teste com endereço único (exemplo do enunciado):"
python3 virtual_memory_translate.py 19986

echo -e "\n2. Teste com endereço hexadecimal:"
python3 virtual_memory_translate.py 0x4E12

echo -e "\n3. Teste com arquivo de endereços:"
python3 virtual_memory_translate.py addresses.txt

echo -e "\n4. Teste com endereço inválido:"
python3 virtual_memory_translate.py 100000

echo -e "\n=== Testes concluídos ==="
'''
    
    with open('test_simulator.sh', 'w') as f:
        f.write(script)
    
    # Torna o script executável (no Linux/Mac)
    import os
    os.chmod('test_simulator.sh', 0o755)
    
    print("Script de teste 'test_simulator.sh' criado!")

def main():
    """Função principal"""
    print("Gerando arquivos de teste para o simulador de memória virtual...")
    
    create_addresses_file()
    create_data_memory_file()
    create_test_script()
    
    print("\nArquivos criados:")
    print("- addresses.txt: Endereços para teste")
    print("- data_memory.txt: Dados simulados da memória")
    print("- test_simulator.sh: Script de teste")
    print("\nPara testar:")
    print("1. Execute: python3 virtual_memory_translate.py 19986")
    print("2. Ou execute: python3 virtual_memory_translate.py addresses.txt")
    print("3. Ou execute: ./test_simulator.sh")

if __name__ == "__main__":
    main()