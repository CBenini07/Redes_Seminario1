#!/usr/bin/env python3
import asyncio
from camadafisica import ZyboSerialDriver
from tcp import Servidor        # copie o arquivo do T2
from ip import IP               # copie o arquivo do T3
from slip import CamadaEnlace   # copie o arquivo do T4
import re
from platform import system
import gc

## Implementação da camada de aplicação

# Este é um exemplo de um programa que faz eco, ou seja, envia de volta para
# o cliente tudo que for recebido em uma conexão.
# Função para logar mensagens no console
def log(msg, *args, **kwargs):
    print('[LOG]::', msg, *args, **kwargs)

# Define o terminador de mensagem com base no sistema operacional
# MSG_TERMINATOR = b'\n' if system() == 'Darwin' else b'\r\n'
MSG_TERMINATOR = b'\r\n'

# Tabelas para armazenar conexões, usuários e canais
CONNS_TABLE = {}  # Armazena mensagens pendentes :: { 'id_conn': 'mensagem' }
USERS_TO_ID_TABLE = {}  # Mapeia apelidos para IDs de conexão :: { 'apelido': 'id_conn' }
CHANNEL_NAME_TO_USER_LST_TABLE = {}  # Mapeia canais para listas de usuários :: { 'canal': ['apelido0', 'apelido1', ...]}

# Função para obter o apelido de um usuário a partir de sua conexão
def get_nick_from_conn(conn):
    try:
        for nick, conn_id in USERS_TO_ID_TABLE.items():
            if conn_id == id(conn):
                return nick
    except:
        return '*'

# Função para obter um objeto a partir de seu ID
def get_object_by_id(id_):
    for obj in gc.get_objects():
        if id(obj) == id_:
            return obj

# Função para validar um nome de usuário
def validar_nome(nome):
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

# Função para criar uma mensagem formatada
def msg(txt):
    m = bytes(txt, 'utf-8') + MSG_TERMINATOR
    log(f'[MSG CREATED]{m}')
    return m

# Função para lidar com a saída de um usuário
def sair(conexao):
    log(conexao, 'conexão fechada')

    curr_usr = get_nick_from_conn(conexao)
    for chnl_name, usr_lst in CHANNEL_NAME_TO_USER_LST_TABLE.items():
        if curr_usr in usr_lst:
            for usr in usr_lst:
                if usr != curr_usr:
                    get_object_by_id(USERS_TO_ID_TABLE[usr]).enviar(msg(f':{curr_usr} QUIT :Connection closed'))
            CHANNEL_NAME_TO_USER_LST_TABLE[chnl_name].remove(curr_usr)

    del USERS_TO_ID_TABLE[curr_usr]
    conexao.fechar()

# Função para garantir que a mensagem está completa e remover o terminador
def get_full_msg_no_terminator(conexao, dados):
    data = dados.split(b'\n')
    msgs_data = []
    for i, item in enumerate(data):
        if i == len(data) - 1:
            msgs_data.append(item)
        else:
            msgs_data.append(item + b'\n')

    if not msgs_data[-1]:
        msgs_data = msgs_data[:-1]

    msgs = []

    for msg_data in msgs_data:
        if id(conexao) not in CONNS_TABLE:
            CONNS_TABLE[id(conexao)] = b''

        CONNS_TABLE[id(conexao)] += msg_data

        if msg_data.endswith(b'\n'):
            msgs.append((conexao, CONNS_TABLE[id(conexao)]))
            del CONNS_TABLE[id(conexao)]

    for i, msg in enumerate(msgs):
        msgs[i] = (msg[0], msg[1][:-2])

    return msgs

# Função para processar dados recebidos de uma conexão
def dados_recebidos(conexao, dados):
    log('[OBJ RCV]', conexao, dados)

    if dados == b'':
        return sair(conexao)

    for msg_tuple in get_full_msg_no_terminator(conexao, dados):
        conexao, dados = msg_tuple

        try:
            cmd, payload = dados.split(b' ', 1)
        except:
            cmd, payload = dados.split(b' ', 1)[0], None

        cmd = cmd.upper()

        if cmd == b'PING':
            conexao.enviar(msg(f':server PONG server :{payload.decode()}'))

        if cmd == b'NICK':
            orig_payload = payload
            payload = bytes(payload.decode("utf-8").lower(), 'utf-8')
            old_nick = get_nick_from_conn(conexao)
            if not validar_nome(payload):
                if not id(conexao) in USERS_TO_ID_TABLE.values():
                    apelido_atual = '*'
                return conexao.enviar(msg(f':server 432 {apelido_atual} {orig_payload.decode("utf-8")} :Erroneous nickname'))

            if payload.decode("utf-8") in USERS_TO_ID_TABLE:
                log('NICK ALREADY EXISTS')
                old_nick = get_nick_from_conn(conexao)
                old_nick = old_nick if old_nick is not None else '*'
                return conexao.enviar(msg(f':server 433 {old_nick} {orig_payload.decode("utf-8")} :Nickname is already in use'))

            if old_nick in USERS_TO_ID_TABLE.keys():
                del USERS_TO_ID_TABLE[old_nick]
                new_nick = payload.decode("utf-8")
                USERS_TO_ID_TABLE[new_nick] = id(conexao)

                for channel_name, usrs_in_channel in CHANNEL_NAME_TO_USER_LST_TABLE.items():
                    if old_nick in usrs_in_channel:
                        CHANNEL_NAME_TO_USER_LST_TABLE[channel_name].remove(old_nick)
                        CHANNEL_NAME_TO_USER_LST_TABLE[channel_name].append(new_nick)

                return conexao.enviar(msg(f':{old_nick} NICK {new_nick}'))

            USERS_TO_ID_TABLE[payload.decode("utf-8")] = id(conexao)
            conexao.enviar(msg(f':server 001 {payload.decode("utf-8")} :Welcome'))
            conexao.enviar(msg(f':server 422 {payload.decode("utf-8")} :MOTD File is missing'))

        if cmd == b'PRIVMSG':
            tgt, msg_bytes = payload.split(b' :', 1)
            tgt = tgt.decode("utf-8")
            try:
                if not tgt.startswith('#'):
                    tgt_conn_id = USERS_TO_ID_TABLE[tgt.lower()]
                    get_object_by_id(tgt_conn_id).enviar(
                        msg(f':{get_nick_from_conn(conexao)} PRIVMSG {tgt} :{msg_bytes.decode("utf-8")}')
                    )
                else:
                    curr_usr = get_nick_from_conn(conexao)
                    for usr in CHANNEL_NAME_TO_USER_LST_TABLE[tgt.lower()]:
                        tgt_conn_id = USERS_TO_ID_TABLE[usr.lower()]
                        tgt_nick_obj = get_object_by_id(tgt_conn_id)

                        if not tgt_nick_obj == conexao:
                            tgt_nick_obj.enviar(msg(f':{curr_usr} PRIVMSG {tgt} :{msg_bytes.decode("utf-8")}'))

            except KeyError as err:
                log('[ERR]Key not found (tgt):', err)

        if cmd == b'JOIN':
            payload = bytes(payload.decode("utf-8").lower(), 'utf-8')
            if not payload.startswith(b'#'):
                return conexao.enviar(
                    msg(f':server 403 {payload.decode("utf-8")} :No such channel')
                )

            channel_name = payload.decode("utf-8")
            if channel_name not in CHANNEL_NAME_TO_USER_LST_TABLE:
                CHANNEL_NAME_TO_USER_LST_TABLE[channel_name] = []

            curr_usr = get_nick_from_conn(conexao)
            if curr_usr not in CHANNEL_NAME_TO_USER_LST_TABLE[channel_name]:
                CHANNEL_NAME_TO_USER_LST_TABLE[channel_name].append(curr_usr)

            for usr in CHANNEL_NAME_TO_USER_LST_TABLE[channel_name]:
                get_object_by_id(USERS_TO_ID_TABLE[usr]).enviar(msg(f':{curr_usr} JOIN :{channel_name}'))

            channel_usrs_lst = CHANNEL_NAME_TO_USER_LST_TABLE[channel_name]
            channel_usrs_lst.sort()
            full_usr_str = " ".join(channel_usrs_lst)

            n = 512 - len(f':server 353 {curr_usr} = {channel_name} :') - len(MSG_TERMINATOR)
            chunks = [full_usr_str[i:i+n] for i in range(0, len(full_usr_str), n)]
            conexao.enviar(msg(f':server 353 {curr_usr} = {channel_name} :{" ".join(chunks)}'))
            return conexao.enviar(msg(f':server 366 {curr_usr} {channel_name} :End of /NAMES list.'))

        if cmd == b'PART':
            payload = bytes(payload.decode("utf-8").lower(), 'utf-8')
            channel_name = payload.decode("utf-8").split(' :')[0]
            if not payload.startswith(b'#'):
                return conexao.enviar(
                    msg(f':server 403 {payload.decode("utf-8")} :No such channel')
                )

            curr_usr = get_nick_from_conn(conexao)
           
            for usr in CHANNEL_NAME_TO_USER_LST_TABLE[channel_name]:
                get_object_by_id(USERS_TO_ID_TABLE[usr]).enviar(msg(f':{curr_usr} PART {channel_name}'))

            CHANNEL_NAME_TO_USER_LST_TABLE[channel_name].remove(curr_usr)

# Função para lidar com novas conexões
def conexao_aceita(conexao):
    log(conexao, 'nova conexão')
    conexao.registrar_recebedor(dados_recebidos)
## Integração com as demais camadas

nossa_ponta = '192.168.200.4'
outra_ponta = '192.168.200.3'
porta_tcp = 7000

driver = ZyboSerialDriver()
linha_serial = driver.obter_porta(0)

enlace = CamadaEnlace({outra_ponta: linha_serial})
rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])
servidor = Servidor(rede, porta_tcp)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
asyncio.get_event_loop().run_forever()
