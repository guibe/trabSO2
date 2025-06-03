#!/usr/bin/env python3

import sys
import os
from collections import OrderedDict # implementaçao de LRU no TLB
from typing import Dict, List, Optional, Tuple, Union # anotaçoes de tipo

# tamanhos de pagina possiveis
PAGE_SIZE_256B = 256
PAGE_SIZE_1KB = 1024
PAGE_SIZE_4KB = 4096


class PageTableEntry:
    """representa uma entrada na tabela de paginas (PTE)
    Cada entrada tem metadados do mapeamento de uma pagina virtual pra um frame fisico
    """
    def __init__(self):
        self.valid = False             # true se a PTE tem mapeamento valido
        self.accessed = False          # true se a pagina foi acessada recentemente
        self.dirty = False             # true se a pagina foi modificada
        self.physical_frame: int = -1 # frame fisico onde a pagina ta carregada (-1 se não carregada)
        self.virtual_page_mapped: int = -1 # numero da pagina virtual que a PTE esta atualmente mapeando
                                        
class TLBEntry:
    # representa uma entrada no TLB
    def __init__(self, virtual_page: int, physical_frame: int):
        self.virtual_page = virtual_page     # numero da pagina virtual
        self.physical_frame = physical_frame # numero do frame fisico correspondente
        # o LRU é gerenciado pela estrutura OrderedDict no simulador

class VirtualMemorySimulator:
    """
    Classe principal que orquestra a simulação da tradução de endereços virtuais para físicos.
    Gerencia a TLB, a Tabela de Páginas, a Memória Física simulada e as estatísticas.
    """
    def __init__(self, address_bits: int = 16, page_size_bytes: int = PAGE_SIZE_4KB):
        """
        Inicializa o simulador com as configurações de tamanho do endereço virtual e tamanho da página.
        Valida os parâmetros e calcula os bits de offset, página, e máscaras necessárias.
        Configura a TLB (16 entradas, LRU) e a Tabela de Páginas (32 entradas).
        Define se a paginação hierárquica será usada (para endereços de 32 bits com páginas de 4KB). 
        """
        # Validação dos parâmetros de entrada baseados nos requisitos do projeto.
        if not isinstance(address_bits, int) or not (16 <= address_bits <= 32):
            raise ValueError("Tamanho do endereço virtual deve ser entre 16 e 32 bits.")
        if page_size_bytes not in [PAGE_SIZE_256B, PAGE_SIZE_1KB, PAGE_SIZE_4KB]:
                 raise ValueError("Tamanho da página inválido. Permitido: 256B, 1KB, 4KB.")

        self.address_bits = address_bits
        self.page_size_bytes = page_size_bytes
        
        self.offset_bits = self._calculate_offset_bits(page_size_bytes)
        
        self.hierarchical_paging = (self.address_bits == 32 and self.page_size_bytes == PAGE_SIZE_4KB)
        if self.hierarchical_paging:
            self.level1_bits = 10
            self.level2_bits = 10
            if self.offset_bits + self.level1_bits + self.level2_bits != 32:
                raise ValueError("Configuração de bits para paginação hierárquica inconsistente.")
            self.page_bits = self.level1_bits + self.level2_bits
        else:
            self.page_bits = address_bits - self.offset_bits
            if self.page_bits <= 0:
                raise ValueError("Configuração de bits de página/offset inválida.")

        self.max_virtual_pages = 2 ** self.page_bits
        self.offset_mask = page_size_bytes - 1
        self.page_mask = ((1 << self.page_bits) - 1) << self.offset_bits
        
        self.page_table_size = 32
        self.page_table: List[PageTableEntry] = [PageTableEntry() for _ in range(self.page_table_size)]
        
        self.tlb: OrderedDict[int, int] = OrderedDict() # LRU no TLB
        self.tlb_max_size = 16
        
        self.physical_memory: Dict[int, int] = {} # simula a RAM, armazenando bytes
        
        self.tlb_hits = 0
        self.tlb_misses = 0
        self.page_hits = 0
        self.page_faults = 0
        
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
            l2_page_idx = (virtual_address >> self.offset_bits) & ((1 << self.level2_bits) - 1)
            l1_page_idx = (virtual_address >> (self.offset_bits + self.level2_bits)) & ((1 << self.level1_bits) - 1)
            combined_page_number = (l1_page_idx << self.level2_bits) | l2_page_idx
            return (l1_page_idx, l2_page_idx), offset, combined_page_number
        else:
            page_number = (virtual_address & self.page_mask) >> self.offset_bits
            return page_number, offset, page_number

    def _tlb_lookup(self, combined_page_number: int) -> Optional[int]:
        #verifica se uma traduçao (pagina virtual -> frame fisico) esta na TLB
        if combined_page_number in self.tlb:
            physical_frame = self.tlb[combined_page_number]
            del self.tlb[combined_page_number] # remove para readicionar no final (MRU)
            self.tlb[combined_page_number] = physical_frame 
            self.tlb_hits += 1
            return physical_frame
        else:
            self.tlb_misses += 1
            return None
    
    def _page_table_lookup(self, combined_page_number: int) -> Tuple[bool, int]:
        """Verifica se uma tradução está na Tabela de Páginas.
        Usa o número combinado da página para encontrar a entrada na tabela de 32 PTEs simuladas.
        Retorna (True, physical_frame) se for page hit, ou (False, -1) se for page fault.
        Atualiza o bit de acesso da PTE em caso de hit.
        """
        pte_index = combined_page_number % self.page_table_size # Mapeia para uma das 32 entradas.
        entry = self.page_table[pte_index]
        
        if entry.valid and entry.virtual_page_mapped == combined_page_number:
            entry.accessed = True 
            self.page_hits += 1
            return True, entry.physical_frame
        else:
            self.page_faults += 1
            return False, -1
    
    def _handle_page_fault(self, combined_page_number: int) -> int:
        """Trata uma falta de página (page fault).
        Carrega a página necessária do `backing_store.bin` para a memória física simulada.
        Atualiza a PageTableEntry correspondente (valid, accessed, physical_frame, etc.).
        Se a PTE escolhida já estava em uso por outra página, essa página é "evitada" (sem write-back).
        Retorna o número do frame físico onde a página foi carregada.
        """
        target_pte_index = combined_page_number % self.page_table_size
        physical_frame_to_use = target_pte_index # Simplificação: PTE[i] gerencia o frame físico i.

        entry = self.page_table[target_pte_index]

        if entry.valid and entry.virtual_page_mapped != combined_page_number:
            old_physical_start_addr = entry.physical_frame * self.page_size_bytes
            for i in range(self.page_size_bytes):
                self.physical_memory.pop(old_physical_start_addr + i, None)
        
        page_offset_in_backing_store = combined_page_number * self.page_size_bytes
        page_data = b'\x00' * self.page_size_bytes # Padrão se houver erro ou página não encontrada.
        try:
            with open("backing_store.bin", 'rb') as bs_file:
                bs_file.seek(page_offset_in_backing_store)
                read_data = bs_file.read(self.page_size_bytes)
                if read_data: # Se algo foi lido
                    page_data = read_data.ljust(self.page_size_bytes, b'\x00') # Preenche se for menor
        except FileNotFoundError:
            pass # page_data permanece como zeros
        except Exception:
            pass # page_data permanece como zeros

        physical_start_address = physical_frame_to_use * self.page_size_bytes
        for i, byte_val in enumerate(page_data):
            self.physical_memory[physical_start_address + i] = byte_val
            
        entry.valid = True
        entry.accessed = True
        entry.dirty = False
        entry.physical_frame = physical_frame_to_use
        entry.virtual_page_mapped = combined_page_number
        
        return physical_frame_to_use
    
    def _update_tlb(self, combined_page_number: int, physical_frame: int):
        """Atualiza a TLB com uma nova tradução (página virtual -> frame físico).
        Se a TLB estiver cheia, remove o item menos recentemente usado (LRU).
        """
        if len(self.tlb) >= self.tlb_max_size:
            self.tlb.popitem(last=False) # Remove o primeiro item (LRU).
        self.tlb[combined_page_number] = physical_frame # Adiciona/atualiza, tornando-o o MRU.

    def translate_address(self, virtual_address: int) -> Dict:
        """
        Método principal que realiza a tradução do endereço virtual para físico.
        Segue o fluxo: TLB lookup -> Page Table lookup -> Page Fault handling (se necessário).
        Retorna um dicionário com todos os detalhes da tradução para exibição.
        """
        result = { # Dicionário para armazenar os resultados.
            'virtual_address': virtual_address,
            'virtual_address_hex': f"0x{virtual_address:X}",
            'actions': [],
            'page_representation': "",
            'offset': -1,
            'physical_address': -1,
            'value': "ERRO"
        }
        
        max_address = (1 << self.address_bits) - 1
        if not (0 <= virtual_address <= max_address): # Validação do endereço. 
            result['actions'].append(f"ERRO: Endereço virtual {virtual_address} (0x{virtual_address:X}) fora dos limites (0-{max_address}).") #
            return result
            
        page_info, offset, combined_page_number = self._extract_page_and_offset(virtual_address)
        result['offset'] = offset

        if self.hierarchical_paging:
            l1_idx, l2_idx = page_info
            result['page_representation'] = f"L1 PPN: {l1_idx}, L2 PPN: {l2_idx} (Combinado: {combined_page_number})"
        else:
            result['page_representation'] = f"PPN: {page_info} (Combinado: {combined_page_number})"

        binary_addr = format(virtual_address, f'0{self.address_bits}b') # Representação binária. 
        if self.hierarchical_paging:
            page_binary_l1 = binary_addr[:self.level1_bits]
            page_binary_l2 = binary_addr[self.level1_bits : self.level1_bits + self.level2_bits]
            offset_binary = binary_addr[self.level1_bits + self.level2_bits:]
            result['binary_representation'] = f"L1: {page_binary_l1} L2: {page_binary_l2} Offset: {offset_binary}"
        else:
            page_binary = binary_addr[:self.page_bits]
            offset_binary = binary_addr[self.page_bits:]
            result['binary_representation'] = f"Página: {page_binary} Offset: {offset_binary}"
        
        physical_frame = self._tlb_lookup(combined_page_number) # Consulta a TLB.
        
        if physical_frame is not None:
            result['actions'].append("TLB hit") 
        else: # TLB Miss.
            result['actions'].append("TLB miss") 
            page_found_in_pt, physical_frame_from_pt = self._page_table_lookup(combined_page_number) # Consulta Tabela de Páginas.
            
            if page_found_in_pt: # Page Hit na Tabela de Páginas.
                result['actions'].append("Page hit") 
                physical_frame = physical_frame_from_pt
            else: # Page Fault.
                result['actions'].append("Page fault") 
                physical_frame = self._handle_page_fault(combined_page_number) # Trata o Page Fault.
                result['actions'].append(f"Carregado da backing store ({"backing_store.bin"}) para Frame Físico {physical_frame}")
            
            self._update_tlb(combined_page_number, physical_frame) # Atualiza a TLB.
        
        physical_address = (physical_frame * self.page_size_bytes) + offset # Calcula endereço físico.
        result['physical_address'] = physical_address
        
        # Lê o valor da memória física simulada. O PDF  pede "Valor lido da memória (arquivo data_memory.txt)",
        # mas aqui o valor vem da RAM simulada, que é preenchida pelo backing store.
        if physical_address in self.physical_memory:
            result['value'] = self.physical_memory[physical_address]
        else:
            result['value'] = "ERRO - Posição de memória física não inicializada"
            result['actions'].append(f"Alerta: Endereço físico {physical_address} não encontrado na RAM simulada.")
    
        return result

    def print_statistics(self):
        """Imprime as estatísticas acumuladas da simulação (TLB hits/misses, Page hits/faults)."""
        total_tlb_accesses = self.tlb_hits + self.tlb_misses
        
        print("\n=== ESTATÍSTICAS ===")
        print(f"TLB Hits: {self.tlb_hits}")
        print(f"TLB Misses: {self.tlb_misses}")
        if total_tlb_accesses > 0:
            print(f"TLB Hit Rate: {(self.tlb_hits / total_tlb_accesses) * 100:.2f}%")
        
        print(f"Page Hits (após TLB miss): {self.page_hits}")
        print(f"Page Faults (após TLB miss e Page Table miss): {self.page_faults}")
        accesses_to_pt = self.tlb_misses 
        if accesses_to_pt > 0 : # Taxa de acerto da tabela de páginas para os acessos que não encontraram na TLB.
            print(f"Page Table Hit Rate (dado TLB Miss): {(self.page_hits / accesses_to_pt) * 100:.2f}%")

# --- Funções Auxiliares Globais ---

def parse_address(addr_str: str) -> int:
    """Converte uma string de endereço (decimal, hexadecimal '0x', ou binário '0b') para inteiro."""
    addr_str = addr_str.strip().lower()
    if addr_str.startswith('0x'):
        return int(addr_str, 16)
    elif addr_str.startswith('0b'):
        return int(addr_str, 2)
    else:
        return int(addr_str)

def print_result(result: Dict):
    """Formata e imprime o dicionário de resultado da tradução de um endereço."""
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

# --- Função Principal ---
def main():
    """
    Ponto de entrada do script. Processa argumentos da linha de comando,
    inicializa o simulador e executa a tradução de endereços.
    Pode processar um único endereço ou um arquivo de endereços. 
    """
    # Verifica se os argumentos mínimos foram fornecidos.
    if len(sys.argv) < 2:
        print("Uso: python virtual_memory_translate.py <endereço | arquivo> [bits_endereço] [tam_página_bytes]")
        # ... (mensagens de exemplo de uso)
        return

    input_arg = sys.argv[1] # Endereço ou nome do arquivo.
    
    # Configurações padrão, podem ser sobrescritas por argumentos da linha de comando.
    address_bits = 16
    page_size_bytes = PAGE_SIZE_4KB

    if len(sys.argv) >= 3: # Se bits_endereço foi fornecido.
        try:
            address_bits = int(sys.argv[2])
        except ValueError:
            print(f"Erro: 'bits_endereço' inválido: {sys.argv[2]}. Usando padrão {address_bits}.")
    if len(sys.argv) >= 4: # Se tam_página_bytes foi fornecido.
        try:
            page_size_bytes = int(sys.argv[3])
        except ValueError:
            print(f"Erro: 'tam_página_bytes' inválido: {sys.argv[3]}. Usando padrão {page_size_bytes}.")

    try:
        simulator = VirtualMemorySimulator(address_bits, page_size_bytes) # Cria o simulador.
    except ValueError as e:
        print(f"Erro ao inicializar o simulador: {e}")
        return
        
    # Imprime a configuração do simulador.
    print(f"=== SIMULADOR DE MEMÓRIA VIRTUAL ===")
    # ... (impressão detalhada da configuração)
    print(f"Backing Store: {"backing_store.bin"}")

    # Processa o input (arquivo de endereços ou endereço unico)
    if os.path.isfile(input_arg):
        print(f"\nLendo endereços do arquivo: {input_arg}")
        try:
            with open(input_arg, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'): # ignora comentarios
                        try:
                            address = parse_address(line)
                            result = simulator.translate_address(address)
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print_result(result)
                        except ValueError as e: # erro na conversao do endereço
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print(f"ERRO ao processar endereço: {e}")
                        except Exception as e: # outro erro
                            print(f"\n--- Arquivo linha {line_num} ({line}) ---")
                            print(f"ERRO inesperado: {e}")
        except FileNotFoundError:
            print(f"Erro: Arquivo '{input_arg}' não encontrado.")
            return
    else: # endereço unico
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
            
    simulator.print_statistics() # estatisticas finais da simulaçao

if __name__ == "__main__":
    main()