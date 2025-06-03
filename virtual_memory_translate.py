#!/usr/bin/env python3

import sys
import os
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Union

PAGE_SIZE_256B = 256
PAGE_SIZE_1KB = 1024
PAGE_SIZE_4KB = 4096

BACKING_STORE_FILENAME = "backing_store.bin"

class PageTableEntry:
    def __init__(self):
        self.valid = False
        self.accessed = False
        self.dirty = False # [cite: 2]
        self.physical_frame: int = -1 # Frame físico que esta página ocupa
        self.virtual_page_mapped: int = -1 # Qual página virtual está mapeada por esta PTE

class TLBEntry: # Not explicitly in PDF Page 2 structure, but implied by "Simular TLB"
    def __init__(self, virtual_page: int, physical_frame: int):
        self.virtual_page = virtual_page
        self.physical_frame = physical_frame
        # LRU is handled by OrderedDict

class VirtualMemorySimulator:
    
    def __init__(self, address_bits: int = 16, page_size_bytes: int = PAGE_SIZE_4KB):
        if not isinstance(address_bits, int) or not (16 <= address_bits <= 32):
            raise ValueError("Tamanho do endereço virtual deve ser entre 16 e 32 bits.") # [cite: 1]
        if page_size_bytes not in [PAGE_SIZE_256B, PAGE_SIZE_1KB, PAGE_SIZE_4KB]: # [cite: 1]
             # Adicionado 2KB como opção intermediária comum, embora não explicitamente listado como "1KB à 4KB"
            if page_size_bytes != 2048 :
                 raise ValueError("Tamanho da página inválido. Permitido: 256B, 1KB, 2KB, 4KB.")


        self.address_bits = address_bits
        self.page_size_bytes = page_size_bytes
        
        self.offset_bits = self._calculate_offset_bits(page_size_bytes)
        
        # Para paginação hierárquica
        self.hierarchical_paging = (self.address_bits == 32 and self.page_size_bytes == PAGE_SIZE_4KB) # [cite: 1]
        if self.hierarchical_paging:
            self.level1_bits = 10
            self.level2_bits = 10
            # offset_bits já calculado (deve ser 12 para 4KB)
            if self.offset_bits + self.level1_bits + self.level2_bits != 32:
                raise ValueError("Configuração de bits para paginação hierárquica inconsistente.")
            self.page_bits = self.level1_bits + self.level2_bits # Total de bits para a parte da página combinada
        else:
            self.page_bits = address_bits - self.offset_bits
            if self.page_bits <= 0:
                raise ValueError("Configuração de bits de página/offset inválida.")

        self.max_virtual_pages = 2 ** self.page_bits 
        self.offset_mask = page_size_bytes - 1
        # Mask para o número da página (combinado, se hierárquico)
        self.page_mask = ((1 << self.page_bits) - 1) << self.offset_bits
        
        # Tabela de Páginas (32 entradas) [cite: 2]
        self.page_table_size = 32
        self.page_table: List[PageTableEntry] = [PageTableEntry() for _ in range(self.page_table_size)]
        
        # TLB com capacidade de 16 entradas, política LRU [cite: 2]
        self.tlb: OrderedDict[int, int] = OrderedDict() # virtual_page_num -> physical_frame_num
        self.tlb_max_size = 16
        
        # Memória Física Simulada (RAM) - armazena bytes de páginas carregadas
        # Chave: endereço físico do byte, Valor: byte (int 0-255)
        self.physical_memory: Dict[int, int] = {} 
        
        self.tlb_hits = 0
        self.tlb_misses = 0
        self.page_hits = 0
        self.page_faults = 0
        
        # Para LRU simples em page_table se todas as entradas estiverem accessed=True (não exigido, mas bom ter)
        # self.pte_access_clock_hand = 0


    def _calculate_offset_bits(self, size: int) -> int:
        bits = 0
        if size == 0: return 0
        temp_size = size
        while temp_size > 1:
            if temp_size % 2 != 0:
                raise ValueError("Tamanho da página deve ser uma potência de 2.")
            temp_size //= 2
            bits += 1
        if 2**bits != size:
             raise ValueError("Tamanho da página deve ser uma potência de 2.")
        return bits
    
    def _extract_page_and_offset(self, virtual_address: int) -> Tuple[Union[int, Tuple[int,int]], int, int]:
        offset = virtual_address & self.offset_mask
        
        if self.hierarchical_paging:
            # Endereço de 32 bits, página de 4KB, hierárquico de 2 níveis (10 bits cada) [cite: 1]
            l2_page_idx = (virtual_address >> self.offset_bits) & ((1 << self.level2_bits) - 1)
            l1_page_idx = (virtual_address >> (self.offset_bits + self.level2_bits)) & ((1 << self.level1_bits) - 1)
            # O número de página combinado é usado para a lógica interna da TLB e da tabela de páginas simplificada
            combined_page_number = (l1_page_idx << self.level2_bits) | l2_page_idx
            return (l1_page_idx, l2_page_idx), offset, combined_page_number
        else:
            page_number = (virtual_address & self.page_mask) >> self.offset_bits
            return page_number, offset, page_number

    def _tlb_lookup(self, combined_page_number: int) -> Optional[int]:
        if combined_page_number in self.tlb:
            physical_frame = self.tlb[combined_page_number]
            # Mover para o fim (MRU) para política LRU
            del self.tlb[combined_page_number]
            self.tlb[combined_page_number] = physical_frame 
            self.tlb_hits += 1
            return physical_frame
        else:
            self.tlb_misses += 1
            return None
    
    def _page_table_lookup(self, combined_page_number: int) -> Tuple[bool, int]:
        # Mapeia o combined_page_number para um índice na nossa tabela de páginas de 32 entradas
        pte_index = combined_page_number % self.page_table_size
        entry = self.page_table[pte_index]
        
        # Verifica se esta PTE está mapeando a página virtual correta
        if entry.valid and entry.virtual_page_mapped == combined_page_number:
            entry.accessed = True # [cite: 2]
            self.page_hits += 1
            return True, entry.physical_frame
        else:
            # Se for válida mas para outra página, ou inválida, é um page fault para esta combined_page_number
            self.page_faults += 1
            return False, -1 # Retorna -1 para indicar que o frame não foi encontrado / é inválido
    
    def _handle_page_fault(self, combined_page_number: int) -> int:
        # Determina qual PageTableEntry usar (e, por consequência, qual physical_frame)
        # Simplificação: physical_frame_number = pte_index. A PTE[i] gerencia o frame físico i.
        target_pte_index = combined_page_number % self.page_table_size
        physical_frame_to_use = target_pte_index 

        entry = self.page_table[target_pte_index]

        # Se a PTE estava mapeando outra página válida, essa página antiga é "evitada"
        # (Não há write-back para bit sujo nesta simulação simplificada)
        if entry.valid and entry.virtual_page_mapped != combined_page_number:
            # Limpar dados antigos da memória física para este frame
            old_physical_start_addr = entry.physical_frame * self.page_size_bytes
            for i in range(self.page_size_bytes):
                self.physical_memory.pop(old_physical_start_addr + i, None)
        
        # Carregar página do backing store [cite: 2]
        page_offset_in_backing_store = combined_page_number * self.page_size_bytes
        
        try:
            with open(BACKING_STORE_FILENAME, 'rb') as bs_file:
                bs_file.seek(page_offset_in_backing_store)
                page_data = bs_file.read(self.page_size_bytes)
                
                if not page_data:
                    # Se a página não existir no backing store (ex: endereço muito alto)
                    # Preencher com zeros ou um padrão de erro
                    # print(f"Aviso: Página {combined_page_number} não encontrada em {BACKING_STORE_FILENAME}. Usando zeros.")
                    page_data = b'\x00' * self.page_size_bytes 
                elif len(page_data) < self.page_size_bytes:
                    # print(f"Aviso: Página {combined_page_number} parcialmente lida de {BACKING_STORE_FILENAME}. Preenchendo com zeros.")
                    page_data += b'\x00' * (self.page_size_bytes - len(page_data))

        except FileNotFoundError:
            # print(f"ERRO: Arquivo {BACKING_STORE_FILENAME} não encontrado. Usando zeros para a página {combined_page_number}.")
            page_data = b'\x00' * self.page_size_bytes
        except Exception as e:
            # print(f"ERRO ao ler {BACKING_STORE_FILENAME} para página {combined_page_number}: {e}. Usando zeros.")
            page_data = b'\x00' * self.page_size_bytes

        # Carregar dados da página na memória física simulada
        physical_start_address = physical_frame_to_use * self.page_size_bytes
        for i, byte_val in enumerate(page_data):
            self.physical_memory[physical_start_address + i] = byte_val
            
        # Atualizar PageTableEntry
        entry.valid = True # [cite: 2]
        entry.accessed = True # [cite: 2]
        entry.dirty = False # Nova página carregada não está suja [cite: 2]
        entry.physical_frame = physical_frame_to_use
        entry.virtual_page_mapped = combined_page_number
        
        return physical_frame_to_use
    
    def _update_tlb(self, combined_page_number: int, physical_frame: int):
        if len(self.tlb) >= self.tlb_max_size:
            self.tlb.popitem(last=False) # Remove o LRU (o primeiro)
        
        self.tlb[combined_page_number] = physical_frame # Adiciona o novo, que se torna o MRU

    def translate_address(self, virtual_address: int) -> Dict:
        result = {
            'virtual_address': virtual_address,
            'virtual_address_hex': f"0x{virtual_address:X}",
            'actions': [],
            'page_representation': "", # Para número(s) da(s) página(s)
            'offset': -1,
            'physical_address': -1,
            'value': "ERRO" # Default
        }
        
        max_address = (1 << self.address_bits) - 1
        if not (0 <= virtual_address <= max_address): # [cite: 1]
            result['actions'].append(f"ERRO: Endereço virtual {virtual_address} (0x{virtual_address:X}) fora dos limites (0-{max_address}).") # [cite: 2]
            return result
            
        page_info, offset, combined_page_number = self._extract_page_and_offset(virtual_address)
        result['offset'] = offset

        if self.hierarchical_paging:
            l1_idx, l2_idx = page_info
            result['page_representation'] = f"L1 PPN: {l1_idx}, L2 PPN: {l2_idx} (Combinado: {combined_page_number})"
        else:
            result['page_representation'] = f"PPN: {page_info} (Combinado: {combined_page_number})"

        binary_addr = format(virtual_address, f'0{self.address_bits}b')
        if self.hierarchical_paging:
             # L1(10) L2(10) Offset(12)
            page_binary_l1 = binary_addr[:self.level1_bits]
            page_binary_l2 = binary_addr[self.level1_bits : self.level1_bits + self.level2_bits]
            offset_binary = binary_addr[self.level1_bits + self.level2_bits:]
            result['binary_representation'] = f"L1: {page_binary_l1} L2: {page_binary_l2} Offset: {offset_binary}"
        else:
            page_binary = binary_addr[:self.page_bits]
            offset_binary = binary_addr[self.page_bits:]
            result['binary_representation'] = f"Página: {page_binary} Offset: {offset_binary}"
        
        physical_frame = self._tlb_lookup(combined_page_number)
        
        if physical_frame is not None:
            result['actions'].append("TLB hit") # [cite: 2]
        else:
            result['actions'].append("TLB miss") # [cite: 2]
            page_found_in_pt, physical_frame_from_pt = self._page_table_lookup(combined_page_number)
            
            if page_found_in_pt:
                result['actions'].append("Page hit") # [cite: 2]
                physical_frame = physical_frame_from_pt
            else:
                result['actions'].append("Page fault") # [cite: 2]
                physical_frame = self._handle_page_fault(combined_page_number)
                result['actions'].append(f"Carregado da backing store ({BACKING_STORE_FILENAME}) para Frame Físico {physical_frame}") # [cite: 2]
            
            self._update_tlb(combined_page_number, physical_frame)
        
        physical_address = (physical_frame * self.page_size_bytes) + offset
        result['physical_address'] = physical_address
        
        # Lê o valor da memória física simulada
        # O PDF diz "Valor lido da memória (arquivo data_memory.txt)" [cite: 1]
        # mas com on-demand paging, o valor é lido do que foi carregado na RAM simulada.
        if physical_address in self.physical_memory:
            result['value'] = self.physical_memory[physical_address]
        else:
            # Isso não deveria acontecer se a página foi carregada corretamente
            result['value'] = "ERRO - Posição de memória física não inicializada após carregamento"
            result['actions'].append(f"Alerta: Endereço físico {physical_address} não encontrado na RAM simulada.")
    
        return result

    def print_statistics(self):
        total_tlb_accesses = self.tlb_hits + self.tlb_misses
        total_page_table_accesses = self.page_hits + self.page_faults # Note: page_faults also access page table
        
        print("\n=== ESTATÍSTICAS ===")
        print(f"TLB Hits: {self.tlb_hits}")
        print(f"TLB Misses: {self.tlb_misses}")
        if total_tlb_accesses > 0:
            print(f"TLB Hit Rate: {(self.tlb_hits / total_tlb_accesses) * 100:.2f}%")
        
        print(f"Page Hits (após TLB miss): {self.page_hits}")
        print(f"Page Faults (após TLB miss e Page Table miss): {self.page_faults}")
        # Taxa de acerto da tabela de páginas (para acessos que perderam na TLB)
        accesses_to_pt = self.tlb_misses 
        if accesses_to_pt > 0 :
            print(f"Page Table Hit Rate (dado TLB Miss): {(self.page_hits / accesses_to_pt) * 100:.2f}%")


def parse_address(addr_str: str) -> int:
    addr_str = addr_str.strip().lower()
    if addr_str.startswith('0x'):
        return int(addr_str, 16)
    elif addr_str.startswith('0b'):
        return int(addr_str, 2)
    else:
        return int(addr_str)

def print_result(result: Dict):
    print(f"\nEndereço virtual: {result['virtual_address']} ({result['virtual_address_hex']})")
    
    if 'binary_representation' in result:
        print(f"Representação binária: {result['binary_representation']}")
    
    print(f"Número(s) da(s) página(s): {result['page_representation']}")
    print(f"Deslocamento: {result['offset']}")
    
    if result['physical_address'] != -1:
        print(f"Endereço físico: {result['physical_address']} (0x{result['physical_address']:X})")
    
    print("Ações tomadas:")
    for action in result['actions']:
        print(f"  - {action}")
    
    if not any("ERRO" in action.upper() for action in result['actions']):
         print(f"Valor lido: {result['value']}")


def main():
    if len(sys.argv) < 2:
        print("Uso: python virtual_memory_translate.py <endereço | arquivo> [bits_endereço] [tam_página_bytes]")
        print("Exemplos:")
        print("  python virtual_memory_translate.py 19986")
        print("  python virtual_memory_translate.py 0x4E12 16 4096")
        print("  python virtual_memory_translate.py addresses.txt 32 4096")
        print(f"  (Padrão: 16 bits, {PAGE_SIZE_4KB}B page size)")
        print(f"  Tamanhos de página válidos: 256, 1024, 2048, 4096 bytes.")
        return

    input_arg = sys.argv[1]
    
    address_bits = 16
    page_size_bytes = PAGE_SIZE_4KB

    if len(sys.argv) >= 3:
        try:
            address_bits = int(sys.argv[2])
        except ValueError:
            print(f"Erro: 'bits_endereço' inválido: {sys.argv[2]}. Usando padrão {address_bits}.")
    if len(sys.argv) >= 4:
        try:
            page_size_bytes = int(sys.argv[3])
        except ValueError:
            print(f"Erro: 'tam_página_bytes' inválido: {sys.argv[3]}. Usando padrão {page_size_bytes}.")

    try:
        simulator = VirtualMemorySimulator(address_bits, page_size_bytes)
    except ValueError as e:
        print(f"Erro ao inicializar o simulador: {e}")
        return
        
    print(f"=== SIMULADOR DE MEMÓRIA VIRTUAL ===")
    print(f"Configuração: Bits de endereço: {simulator.address_bits}, Tamanho da página: {simulator.page_size_bytes} bytes")
    if simulator.hierarchical_paging:
        print(f"Paginação: Hierárquica de 2 Níveis (L1: {simulator.level1_bits} bits, L2: {simulator.level2_bits} bits, Offset: {simulator.offset_bits} bits)")
    else:
        print(f"Paginação: Nível Único (Página: {simulator.page_bits} bits, Offset: {simulator.offset_bits} bits)")
    print(f"Máximo de páginas virtuais (combinadas): {simulator.max_virtual_pages}")
    print(f"Tamanho da Tabela de Páginas (entradas simuladas): {simulator.page_table_size}")
    print(f"Tamanho da TLB: {simulator.tlb_max_size} entradas")
    print(f"Backing Store: {BACKING_STORE_FILENAME}")

    if os.path.isfile(input_arg):
        print(f"\nLendo endereços do arquivo: {input_arg}")
        try:
            with open(input_arg, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            address = parse_address(line)
                            result = simulator.translate_address(address)
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print_result(result)
                        except ValueError as e:
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print(f"ERRO ao processar endereço: {e}")
                        except Exception as e:
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print(f"ERRO inesperado: {e}")
        except FileNotFoundError:
            print(f"Erro: Arquivo '{input_arg}' não encontrado.")
            return
    else:
        try:
            address = parse_address(input_arg)
            result = simulator.translate_address(address)
            print_result(result)
        except ValueError as e:
            print(f"Erro: Endereço inválido '{input_arg}': {e}")
            return
        except Exception as e:
            print(f"ERRO inesperado ao processar '{input_arg}': {e}")
            return
            
    simulator.print_statistics()

if __name__ == "__main__":
    main()