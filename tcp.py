import asyncio
from tcputils import *
from os import urandom
from collections import deque
from math import ceil
import time

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            return

        payload = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(
                self, id_conexao, seq_no, ack_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            ack_no = seq_no + 1
            header = make_header(dst_port, src_port, seq_no, ack_no, FLAGS_SYN + FLAGS_ACK)
            segment = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segment, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None
        # self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timeout)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        # self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.expected_seq_no = seq_no + 1
        self.seq_enviar = int(urandom(2).hex(), 16)
        self.my_len_seq_no = ack_no
        self.seg_sended_queue = deque()
        self.seg_sended_length = 0
        self.seg_waiting_queue = deque()
        self.win_size = 1 * MSS
        self.alreadyChecked = False
        self.SampleRTT = 1
        self.EstimatedRTT = self.SampleRTT
        self.DevRTT = self.SampleRTT/2
        self.TimeoutInterval = 1

    def _timeout(self):
        self.timer = None
        self.win_size /= 2

        if len(self.seg_sended_queue):
            _, segment, addr, len_dados = self.seg_sended_queue.popleft()
            self.seg_sended_queue.appendleft((0, segment, addr, len_dados))
            self.servidor.rede.enviar(segment, addr)
            self.timer = asyncio.get_event_loop().call_later(
                self.TimeoutInterval, self._timeout)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
            self.my_len_seq_no = ack_no
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segment = make_header(
                dst_port, src_port, self.seq_enviar, self.expected_seq_no + 1, flags)
            response = fix_checksum(segment, dst_addr, src_addr)
            self.servidor.rede.enviar(response, src_addr)
        elif (seq_no == self.expected_seq_no):
            self.expected_seq_no += (len(payload) if payload else 0)
            self.callback(self, payload)
            self.my_len_seq_no = ack_no
            if (flags & FLAGS_ACK == FLAGS_ACK):
                if (len(payload) > 0):
                    src_addr, src_port, dst_addr, dst_port = self.id_conexao
                    segment = make_header(
                        dst_port, src_port, self.seq_enviar, self.expected_seq_no, flags)
                    response = fix_checksum(segment, dst_addr, src_addr)
                    self.servidor.rede.enviar(response, src_addr)

                a = self.seg_sended_length > 0

                if (self.timer != None):
                    self.timer.cancel()
                    self.timer = None

                    while len(self.seg_sended_queue):
                        firstTime, segmento, _, len_dados = self.seg_sended_queue.popleft()
                        self.seg_sended_length -= len_dados
                        _, _, seq, _, _, _, _, _ = read_header(segmento)

                        if seq == ack_no:
                            break

                    if firstTime != 0:
                        self.SampleRTT = time.time() - firstTime
                        if self.alreadyChecked == False:
                            self.alreadyChecked = True
                            self.EstimatedRTT = self.SampleRTT
                            self.DevRTT = self.SampleRTT/2
                        else:
                            self.EstimatedRTT = (
                                1 - 0.125) * self.EstimatedRTT + 0.125 * self.SampleRTT
                            self.DevRTT = (1 - 0.25) * self.DevRTT + 0.25 * \
                                abs(self.SampleRTT - self.EstimatedRTT)
                        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT


                b = self.seg_sended_length == 0
                if a == True and b == True:
                    self.win_size += MSS
                while len(self.seg_waiting_queue):
                    response, src_addr, len_dados = self.seg_waiting_queue.popleft()

                    if self.seg_sended_length + len_dados > self.win_size:
                        self.seg_waiting_queue.appendleft(
                            (response, src_addr, len_dados))
                        break

                    self.seg_sended_length += len_dados
                    self.servidor.rede.enviar(response, src_addr)
                    self.seg_sended_queue.append(
                        (time.time(), response, src_addr, len_dados))

                if len(self.seg_sended_queue):
                    self.timer = asyncio.get_event_loop().call_later(
                        self.TimeoutInterval, self._timeout)                    

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        size = ceil(len(dados)/MSS)
        for i in range(size):
            self.seq_enviar = self.my_len_seq_no
            segment = make_header(
                dst_port, src_port, self.seq_enviar, self.expected_seq_no, flags=FLAGS_ACK)
            segment += (dados[i*MSS:min((i+1)*MSS, len(dados))])
            len_dados = len(dados[i*MSS:min((i+1)*MSS, len(dados))])
            self.my_len_seq_no += len_dados
            response = fix_checksum(segment, dst_addr, src_addr)

            if (self.seg_sended_length + len_dados <= self.win_size):
                self.servidor.rede.enviar(response, src_addr)
                self.seg_sended_queue.append(
                    (time.time(), response, src_addr, len_dados))
                self.seg_sended_length += len_dados  # += len(response)
                if (self.timer == None):
                    self.timer = asyncio.get_event_loop().call_later(
                        self.TimeoutInterval, self._timeout)
            else:
                self.seg_waiting_queue.append((response, src_addr, len_dados))

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        self.seq_enviar = self.my_len_seq_no
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segment = make_header(
            dst_port, src_port, self.seq_enviar, self.expected_seq_no + 1, FLAGS_FIN)
        response = fix_checksum(segment, dst_addr, src_addr)
        self.servidor.rede.enviar(response, src_addr)