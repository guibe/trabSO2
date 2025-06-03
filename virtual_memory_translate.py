#!/usr/bin/env python3

import sys
import os
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

class PageTableEntry:
    def __init__(self):
        self.valid = False
        self.accessed = False
        self.dirty = False
        self.physical_frame = 0

class TLBEntry:
    def __init__(self, virtual_page: int, physical_frame: int):
        self.virtual_page = virtual_page
        self.physical_frame = physical_frame

class VirtualMemorySimulator:
    
    def __init__(self, address_bits: int = 16, page_size: int = 4096):
        self.address_bits = address_bits
        self.page_size = page_size
        self.offset_bits = self._calculate_offset_bits(page_size)
        self.page_bits = address_bits - self.offset_bits
        self.max_pages = 2 ** self.page_bits
        self.offset_mask = page_size - 1
        self.page_mask = ((1 << self.page_bits) - 1) << self.offset_bits
        
        self.page_table: List[PageTableEntry] = [PageTableEntry() for _ in range(32)]
        self.tlb: OrderedDict[int, int] = OrderedDict()
        self.tlb_max_size = 16
        self.physical_memory: Dict[int, int] = {}
        
        self.tlb_hits = 0
        self.tlb_misses = 0
        self.page_hits = 0
        self.page_faults = 0
        
        self._load_data_memory()
        self._load_backing_store()
    
    def _calculate_offset_bits(self, page_size: int) -> int:
        bits = 0
        size = page_size
        while size > 1:
            size //= 2
            bits += 1
        return bits
    
    def _load_data_memory(self):
        try:
            if os.path.exists('data_memory.txt'):
                with open('data_memory.txt', 'r') as f:
                    for i, line in enumerate(f):
                        value = int(line.strip())
                        self.physical_memory[i] = value
            else:
                print("Aviso: data_memory.txt não encontrado. Gerando dados de exemplo.")
                for i in range(65536):
                    self.physical_memory[i] = (i * 7 + 13) % 256
        except Exception as e:
            print(f"Erro ao carregar data_memory.txt: {e}")
            for i in range(65536):
                self.physical_memory[i] = (i * 7 + 13) % 256
    
    def _load_backing_store(self):
        pass
    
    def _extract_page_and_offset(self, virtual_address: int) -> Tuple[int, int]:
        if self.address_bits == 32 and self.page_size == 4096:
            level1_bits = 10
            level2_bits = 10
            offset_bits = 12
            
            offset = virtual_address & ((1 << offset_bits) - 1)
            level2_page = (virtual_address >> offset_bits) & ((1 << level2_bits) - 1)
            level1_page = (virtual_address >> (offset_bits + level2_bits)) & ((1 << level1_bits) - 1)
            
            page_number = (level1_page << level2_bits) | level2_page
        else:
            page_number = (virtual_address & self.page_mask) >> self.offset_bits
            offset = virtual_address & self.offset_mask
        
        return page_number, offset
    
    def _tlb_lookup(self, page_number: int) -> Optional[int]:
        if page_number in self.tlb:
            physical_frame = self.tlb[page_number]
            del self.tlb[page_number]
            self.tlb[page_number] = physical_frame
            self.tlb_hits += 1
            return physical_frame
        else:
            self.tlb_misses += 1
            return None
    
    def _page_table_lookup(self, page_number: int) -> Tuple[bool, int]:
        if page_number >= len(self.page_table):
            return False, 0
        
        entry = self.page_table[page_number]
        
        if entry.valid:
            entry.accessed = True
            self.page_hits += 1
            return True, entry.physical_frame
        else:
            self.page_faults += 1
            return False, 0
    
    def _handle_page_fault(self, page_number: int) -> int:
        physical_frame = page_number
        
        if page_number < len(self.page_table):
            entry = self.page_table[page_number]
            entry.valid = True
            entry.accessed = True
            entry.physical_frame = physical_frame
        
        return physical_frame
    
    def _update_tlb(self, page_number: int, physical_frame: int):
        if len(self.tlb) >= self.tlb_max_size:
            self.tlb.popitem(last=False)
        
        self.tlb[page_number] = physical_frame
    
    def translate_address(self, virtual_address: int) -> Dict:
        result = {
            'virtual_address': virtual_address,
            'virtual_address_hex': f"0x{virtual_address:X}",
            'actions': [],
            'physical_address': 0,
            'value': 0
        }
        
        try:
            max_address = (1 << self.address_bits) - 1
            if virtual_address < 0 or virtual_address > max_address:
                result['actions'].append(f"ERRO: Endereço inválido (0-{max_address})")
                return result
            
            page_number, offset = self._extract_page_and_offset(virtual_address)
            result['page_number'] = page_number
            result['offset'] = offset
            
            binary_addr = format(virtual_address, f'0{self.address_bits}b')
            page_binary = binary_addr[:self.page_bits]
            offset_binary = binary_addr[self.page_bits:]
            result['binary_representation'] = f"{page_binary} {offset_binary}"
            
            physical_frame = self._tlb_lookup(page_number)
            
            if physical_frame is not None:
                result['actions'].append("TLB hit")
            else:
                result['actions'].append("TLB miss")
                
                page_found, physical_frame = self._page_table_lookup(page_number)
                
                if page_found:
                    result['actions'].append("Page hit")
                else:
                    result['actions'].append("Page fault")
                    result['actions'].append("Carregado da backing store")
                    physical_frame = self._handle_page_fault(page_number)
                
                self._update_tlb(page_number, physical_frame)
            
            physical_address = (physical_frame << self.offset_bits) | offset
            result['physical_address'] = physical_address
            
            if physical_address in self.physical_memory:
                result['value'] = self.physical_memory[physical_address]
            else:
                result['value'] = 0
                result['actions'].append("Aviso: Posição de memória não inicializada")
        
        except Exception as e:
            result['actions'].append(f"ERRO: {str(e)}")
        
        return result
    
    def print_statistics(self):
        """Imprime estatísticas do simulador"""
        total_tlb = self.tlb_hits + self.tlb_misses
        total_pages = self.page_hits + self.page_faults
        
        print("\n=== ESTATÍSTICAS ===")
        print(f"TLB Hits: {self.tlb_hits}")
        print(f"TLB Misses: {self.tlb_misses}")
        if total_tlb > 0:
            print(f"TLB Hit Rate: {(self.tlb_hits/total_tlb)*100:.2f}%")
        
        print(f"Page Hits: {self.page_hits}")
        print(f"Page Faults: {self.page_faults}")
        if total_pages > 0:
            print(f"Page Hit Rate: {(self.page_hits/total_pages)*100:.2f}%")

def parse_address(addr_str: str) -> int:
    """Converte string de endereço para inteiro (suporta decimal e hexadecimal)"""
    addr_str = addr_str.strip()
    if addr_str.startswith('0x') or addr_str.startswith('0X'):
        return int(addr_str, 16)
    elif addr_str.startswith('0b') or addr_str.startswith('0B'):
        return int(addr_str, 2)
    else:
        return int(addr_str)

def print_result(result: Dict):
    """Imprime resultado da tradução de endereço"""
    print(f"\nEndereço virtual: {result['virtual_address']} ({result['virtual_address_hex']})")
    
    if 'binary_representation' in result:
        print(f"Representação binária: {result['binary_representation']}")
    
    if 'page_number' in result:
        print(f"Número da página: {result['page_number']}")
        print(f"Deslocamento: {result['offset']}")
    
    if 'physical_address' in result:
        print(f"Endereço físico: {result['physical_address']}")
    
    print("Ações tomadas:")
    for action in result['actions']:
        print(f"  - {action}")
    
    if 'value' in result and not any("ERRO" in action for action in result['actions']):
        print(f"Valor lido: {result['value']}")

def main():
    """Função principal"""
    if len(sys.argv) < 2:
        print("Uso: python virtual_memory_simulator.py <endereço|arquivo>")
        print("Exemplos:")
        print("  python virtual_memory_simulator.py 19986")
        print("  python virtual_memory_simulator.py 0x4E12")
        print("  python virtual_memory_simulator.py addresses.txt")
        return
    
    # Configurações padrão (podem ser ajustadas)
    address_bits = 16
    page_size = 4096
    
    # Permite configuração via argumentos extras
    if len(sys.argv) >= 4:
        address_bits = int(sys.argv[2])
        page_size = int(sys.argv[3])
    
    simulator = VirtualMemorySimulator(address_bits, page_size)
    
    print(f"=== SIMULADOR DE MEMÓRIA VIRTUAL ===")
    print(f"Bits de endereço: {address_bits}")
    print(f"Tamanho da página: {page_size} bytes")
    print(f"Bits de offset: {simulator.offset_bits}")
    print(f"Bits de página: {simulator.page_bits}")
    print(f"Número máximo de páginas: {simulator.max_pages}")
    
    input_arg = sys.argv[1]
    
    # Verifica se é um arquivo
    if os.path.isfile(input_arg):
        print(f"\nLendo endereços do arquivo: {input_arg}")
        try:
            with open(input_arg, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # Ignora linhas vazias e comentários
                        try:
                            address = parse_address(line)
                            result = simulator.translate_address(address)
                            print(f"\n--- Linha {line_num} ---")
                            print_result(result)
                        except ValueError as e:
                            print(f"\nLinha {line_num}: Erro ao processar '{line}': {e}")
        except FileNotFoundError:
            print(f"Erro: Arquivo '{input_arg}' não encontrado.")
            return
        except Exception as e:
            print(f"Erro ao processar arquivo: {e}")
            return
    else:
        # Trata como endereço único
        try:
            address = parse_address(input_arg)
            result = simulator.translate_address(address)
            print_result(result)
        except ValueError as e:
            print(f"Erro: Endereço inválido '{input_arg}': {e}")
            return
    
    # Mostra estatísticas
    simulator.print_statistics()

if __name__ == "__main__":
    main()