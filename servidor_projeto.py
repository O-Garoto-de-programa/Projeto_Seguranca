import socket
from ecdsa import VerifyingKey, SigningKey
import hashlib
import os
import json
import time
import requests

p = 23
g = 5

# Nome de usuário GitHub do servidor
username_server = "ServerSeguranca2025"


# Carrega a chave privada do Servidor a partir de um arquivo PEM
with open("./chaves_ECDSA/servidor.pem", "rb") as f:
    try:
        sk_server = SigningKey.from_pem(f.read())
    except Exception as e:
        print(f"Erro ao carregar a chave privada ECDSA do servidor: {e}")
        exit(1)


# Obtém a chave pública do cliente a partir de um Gist no GitHub
url = "https://gist.githubusercontent.com/ClientSeguranca2025/80c2087b9eb60d9c933c85d4d49c59e0/raw/f88a2a3ccb9482d3607e7379952eb51735f87517/cliente_public.pem"
response = requests.get(url)
chave_publica_cliente = response.content

try:
    vk = VerifyingKey.from_pem(chave_publica_cliente)
except Exception as e:
    print(f"Erro ao carregar a chave pública ECDSA do cliente: {e}")
    exit(1)


# Gerar chaves b,B do Diffie Helllman
def gerar_chaves_DH(p, g):
        b_bytes = os.urandom(32)  # A chave privada é gerada aleatoriamente
        b = int.from_bytes(b_bytes, 'big')  # Converte a chave privada de bytes para inteiro
        B = pow(g, b, p)
        return b, B


def gerar_assinatura_ecdsa(sk, mensagem):  # Chave privada ECDSA
    sig = sk.sign_deterministic(mensagem.encode(), hashfunc=hashlib.sha256)  # Assina a mensagem
    return sig


def verificar_assinatura_ecdsa(vk, mensagem, assinatura):
    try:
        if vk.verify(assinatura, mensagem, hashfunc=hashlib.sha256):
            print("  OK - Verificação bem Sucedida\n")
            return True
    except Exception as e:
        print(f" ERRO - Falha na Verificação da mensagem: {e}\n")
        return False
        

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 8080))
    server_socket.listen(1)
    print("Servidor aguardando conexão...")

    client_socket, addr = server_socket.accept()
    print(f"Conexão estabelecida com o cliente: {addr}\n")
    time.sleep(3)


    # Recebe a mensagem do cliente com A, assinatura e username
    data = client_socket.recv(1024)
    mensagem_assinada_cliente = json.loads(data.decode())
    print("MENSAGEM RECEBIDA DO CLIENTE!!!")


    # Extrai A, assinatura e username da mensagem do cliente
    A = int(mensagem_assinada_cliente["A"])
    sig_A = bytes.fromhex(mensagem_assinada_cliente["assinatura_A"])
    username_cliente = mensagem_assinada_cliente["username_cliente"]
    print(f"  A: {A}")
    print(f"  Assinatura Cliente: {sig_A}")
    print(f"  Username Cliente: {username_cliente}\n")
    time.sleep(2)

    # Verifica a assinatura ECDSA do cliente
    print(f"VERIFICANDO ASSINATURA ECDSA DO CLIENTE: {username_cliente}...")
    time.sleep(1)
    if not verificar_assinatura_ecdsa(vk, f"{A} {username_cliente}".encode(), sig_A):
        client_socket.close()
        print(f"\nConexão fechada com o cliente.")
        return
    time.sleep(3)

    # Gera chaves b, B do Diffie-Hellman
    print("Gerando Chaves b, B do Diffie-Hellman...")
    b, B = gerar_chaves_DH(p, g)
    time.sleep(2)
    print(f"Chave Pública B: {B}\n")
    time.sleep(2)

    # Assina e envia a mensagem para o cliente
    print("Assinando a mensagem pra enviar para o Cliente...")
    mensagem = f"{B} {username_server}"
    sig_B = gerar_assinatura_ecdsa(sk_server, mensagem)
    mensagem_assinada_servidor = {
        "B": B,
        "assinatura_B": sig_B.hex(),
        "username_servidor": username_server
    }
    time.sleep(3)
    client_socket.send(json.dumps(mensagem_assinada_servidor).encode())
    print("MENSAGEM ASSINADA ENVIADA PARA O CLIENTE!!!\n")
    time.sleep(2)

    #Calcula a chave Secreta compartilhada S
    S = pow(A, b, p)
    print("___________________________________________________\n")
    print(f"Chave Secreta compartilhada S: {S}\n")


    client_socket.close()
    print(f"\nConexão fechada com o cliente.")

if __name__ == "__main__":
    main()