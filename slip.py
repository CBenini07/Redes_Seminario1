class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        """
        Implementação do envio de quadros conforme o protocolo SLIP (RFC 1055).
        Adiciona os delimitadores de início e fim e faz o escape de bytes especiais.
        """
        # Definição dos bytes especiais do protocolo SLIP
        END = b'\xC0'  # Delimitador de quadro
        ESC = b'\xDB'  # Byte de escape
        ESC_END = b'\xDB\xDC'  # Representação de 0xC0 dentro do datagrama
        ESC_ESC = b'\xDB\xDD'  # Representação de 0xDB dentro do datagrama
        
        # Substituir os bytes especiais no datagrama para evitar ambiguidades
        datagrama = datagrama.replace(ESC, ESC_ESC).replace(END, ESC_END)
        
        # Adicionar os delimitadores de início e fim ao datagrama
        quadro = END + datagrama + END
        
        # Enviar o quadro formatado pela linha serial
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        """
        Método para receber e reconstruir quadros SLIP corretamente.

        - Os bytes podem chegar de forma fragmentada ou juntos.
        - Deve reconstruir os quadros completos e chamar `self.callback(datagrama)`.
        - Descartar datagramas vazios (quadros que só contêm 0xC0).
        - Lidar com as sequências de escape 0xDB 0xDC → 0xC0 e 0xDB 0xDD → 0xDB.
        """

        END = b'\xC0'  # Delimitador de quadro
        ESC = b'\xDB'  # Byte de escape
        ESC_END = b'\xDB\xDC'  # Representação escapada de 0xC0
        ESC_ESC = b'\xDB\xDD'  # Representação escapada de 0xDB

        # Buffer para armazenar os dados recebidos até formar um quadro completo
        if not hasattr(self, "buffer"):
            self.buffer = b""

        # Adicionar os novos dados ao buffer
        self.buffer += dados

        while END in self.buffer:
            # Separar o primeiro quadro completo
            quadro, _, self.buffer = self.buffer.partition(END)

            # Ignorar quadros vazios
            if not quadro:
                continue

            # Tratar as sequências de escape dentro do quadro
            quadro = quadro.replace(ESC_END, END).replace(ESC_ESC, ESC)

            # Repassar o quadro processado à camada superior
            try:
                if self.callback:
                    self.callback(quadro)
            except Exception as e:
                import traceback
                traceback.print_exc()

