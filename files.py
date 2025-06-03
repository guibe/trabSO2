#!/usr/bin/env python3

import random
import struct
import os

def create_addresses_file():
    """Cria arquivo addresses.txt com endereços de teste"""
    addresses = [
        19986,    #Exemplo do enunciado
        1024,     #Início pg 0 (4KB)
        2048,     #Pg 0, offset 2048
        4096,     #Início da pg 1
        8192,     #Início da pg 2
        16384,    #Início da pg 4
        32768,    #Início da pg 8
        65535,    #16 bits - MAX
        #endereços random para 16 bits
        *[random.randint(0, 65535) for _ in range(5)],
        #Endereços de teste pra 32 bits (page size 4KB)
        0x12345678, 
        0xFF00FF00, 
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
            addr = random.randint(0, 65535)
            f.write(f"0x{addr:X}\n")
        for i in range(3):
            addr = random.randint(0, 0xFFFFFFFF) 
            f.write(f"0x{addr:X}\n")

    print("Arquivo 'addresses.txt' criado com sucesso! :3")

def create_backing_store_file(filename="backing_store.bin", num_pages_total_virtual_space=2**20, page_size_bytes=4096):

    num_pages_to_create = 256 #Simulando 256 pg no backing store
    actual_total_size = num_pages_to_create * page_size_bytes
    data = bytearray(actual_total_size)
    print(f"Criando '{filename}' com {num_pages_to_create} páginas de {page_size_bytes}B cada. Total: {actual_total_size / (1024):.2f} KB.")
    
    for i in range(actual_total_size):
        #byte = (endereço_no_backing_store) % 256
        data[i] = i % 256 
    
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"Arquivo '{filename}' criado com sucesso ({actual_total_size} bytes)!")
    except IOError as e:
        print(f"Erro ao criar o arquivo '{filename}': {e}")


def create_test_script():
    """Cria script de teste para mostrar funcionalidades"""
    script = f'''#!/bin/bash

echo "=== Testando Simulador de Memória Virtual (16-bit, 4KB page) ==="
EXE_CMD="python3 virtual_memory_translate.py" # Assume python3 está no PATH

echo -e "\\n1. Teste com endereço único (16-bit):"
$EXE_CMD 19986 16 4096

echo -e "\\n2. Teste com endereço hexadecimal (16-bit):"
$EXE_CMD 0x4E12 16 4096

echo -e "\\n3. Teste com arquivo de endereços (configurações definir no simulador ou por linha de comando):"
# O simulador usa os padrões 16-bit, 4KB se n especificado.
$EXE_CMD addresses.txt 16 4096 

echo -e "\\n4. Teste com endereço inválido (16-bit):"
$EXE_CMD 100000 16 4096 # 65535 é o máx para 16-bit

echo -e "\\n=== Testando Simulador de Memória Virtual (32-bit, 4KB page, Hierárquico) ==="
echo -e "\\n5. Teste com endereço único (32-bit):"
$EXE_CMD 0x12345678 32 4096

echo -e "\\n6. Teste com endereço fora do backing_store simulado (32-bit):"
# (256 pages * 4096 B/page) = 0x100000. Endereço 0x100000 é o início da pg 256.
# Se backing_store tem 256 pg, esta pg não estará no arquivo (começa com 0).
$EXE_CMD 0x100000 32 4096 # Equivalente a pg 256, offset 0.

echo -e "\\n7. Teste com arquivo de endereços (32-bit, 4KB page):"
$EXE_CMD addresses.txt 32 4096

echo -e "\\n=== Testes concluídos ==="
'''
    
    with open('test_simulator.sh', 'w') as f:
        f.write(script)
    
    print("Script de teste 'test_simulator.sh' criado! :D")

def main():
   
    print("Gerando arquivos de teste para o simulador...")
    
    create_addresses_file()
    #Usando 4KB page size para o backing store, como e usado no exemplo de 32-bit
    create_backing_store_file(page_size_bytes=4096) 
    create_test_script()
    
    print("\\nArquivos criados:")
    print("- addresses.txt: Endereços para teste")
    print("- backing_store.bin: Dados simulados da memória de apoio (backing store)")
    print("- test_simulator.sh: Script de teste")
    print("\\nPara executar os testes, rode: ./test_simulator.sh (Git Bash no Windows)")
    print("Ou manualmente, ex:")
    print("  python3 virtual_memory_translate.py 19986 16 4096")
    print("  python3 virtual_memory_translate.py addresses.txt 32 4096")

if __name__ == "__main__":
    main()