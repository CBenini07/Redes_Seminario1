from iputils import *
import ipaddress
import struct
from socket import IPPROTO_TCP, IPPROTO_ICMP

IPV4_HEADER_DEF_SIZE = 20

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identificacao = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama

            # Checando se é maior que 0
            ttl -= 1
            if ttl > 0:
                datagrama_final = self.enviar_mensagem(payload, src_addr, dst_addr, IPPROTO_TCP, ttl)

            else:
                erro_icmp = self.ttl_exceeded(datagrama)
                dst_addr = src_addr
                # Redefinindo TTL para 64 para enviar a mensagem
                datagrama_final = self.enviar_mensagem(erro_icmp, self.meu_endereco, dst_addr, IPPROTO_ICMP, 64)
             
            self.enlace.enviar(datagrama_final, next_hop)
    
    def ttl_exceeded(self, datagrama):
        # Envio da mensagem de erro

        typ = 11  
        code = 0  
        checksum = 0  
        unused = 0  
        ip_header = datagrama[:20]  
        payload = datagrama[20:28] 
        icmp_payload = ip_header + payload

        # Definindo header icmp (e atualizando com checksum)
        icmp_header = struct.pack('!BBHI', typ, code, checksum, unused)
        checksum = self.calc_checksum(icmp_header + icmp_payload)
        icmp_header = struct.pack('!BBHI', typ, code, checksum, unused)

        # Retorna mensagem icmp
        return icmp_header + icmp_payload

    def enviar_mensagem(self, message, src_addr, dest_addr, prot, ttl):
       
        # Datagrama com o cabeçalho IP, contendo como payload o segmento.
        # version 4: ipv4 (deslocado a esquerda) e ihl 5: tamanho do cabeçalho comportando apenas campos essenciais
        ver_ihl = (4 << 4) | 5
        dscp = 0
        ecn = 0
        total_length = 20 + len(message)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = ttl
        proto = prot
        checksum = 0
        src_addr_packed = ipaddress.IPv4Address(src_addr).packed
        dst_addr_packed = ipaddress.IPv4Address(dest_addr).packed

        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                                              identification, (flags << 13) | frag_offset, ttl, proto, 
                                              checksum, src_addr_packed, dst_addr_packed)
        checksum = self.calc_checksum(header)
        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                             identification, (flags << 13) | frag_offset, ttl, proto, 
                             checksum, src_addr_packed, dst_addr_packed)

        # Formato do datagrama (20 bytes de cabeçalho + payload/segmento)
        datagrama = header + message
        return datagrama

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr), em formato de string.
        # Retorne o next_hop para o dest_addr fornecido.
        
        # Transformando no formato ipaddress para comparar
        dest_addr = ipaddress.ip_network(dest_addr, strict=False)
        for cidr, next_hop in self.tabela:
            if dest_addr.subnet_of(cidr):
                return next_hop
        return None # opcional, python automaticamente retorna None se chega ao final sem return

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.

        # Armazenando em formato de lista
        # Transformando ip num objeto ipaddress para permitir ordenação na lista
        self.tabela = [(ipaddress.ip_network(cidr), next_hop) for cidr, next_hop in tabela]
        # Ordena a tabela pela máscara de rede (maiores primeiro para buscas corretas)
        self.tabela.sort(key=lambda x: x[0].prefixlen, reverse=True)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        
        # 64: max de roteadores antes de ser descartado
        datagrama = self.enviar_mensagem(segmento, self.meu_endereco, dest_addr, IPPROTO_TCP, 64)
        self.enlace.enviar(datagrama, next_hop)

    def calc_checksum(self, header):        
        if len(header) % 2 == 1:
            header += b'\0'
        s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff