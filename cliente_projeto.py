import socket
import hashlib
import os
from ecdsa import SigningKey, VerifyingKey
import json
import time
import requests

# Parâmetros de Diffie-Hellman
p = 23 # Número primo
g = 5 # Gerador

# Nome de usuário GitHub do cliente
username_cliente = "ClientSeguranca2025"

# Carrega a chave privada do cliente a partir de um arquivo PEM
with open("./chaves_ECDSA/cliente.pem", "rb") as f:
    sk_client = SigningKey.from_pem(f.read())


# Obtém a chave pública do servidor a partir de um Gist no GitHub
url = "https://gist.githubusercontent.com/ServerSeguranca2025/32a5c42318b9f1611d31a8c51caa75c3/raw/090b5fb6fa3e42e3a9e1165a496b08d688d4169e/server_public.pem"
response = requests.get(url)
chave_publica_servidor = response.content

try:
    vk = VerifyingKey.from_pem(chave_publica_servidor)
except Exception as e:
    print(f"Erro ao carregar a chave pública ECDSA do servidor: {e}")
    exit(1)

# Gera a chave pública do cliente a partir da chave privada
def gerar_chaves_DH(p, g):
    a_bytes = os.urandom(32)
    a = int.from_bytes(a_bytes, 'big')
    A = pow(g, a, p)
    return a, A


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




# Função principal do cliente
def main():

    # Cria o socket do cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8080))


    # Gera as chaves Diffie-Hellman
    print("Gerando Chaves a, A do Diffie-Hellman...")
    a, A = gerar_chaves_DH(p, g)
    time.sleep(2)
    print(f"Chave Pública A: {A}\n")
    time.sleep(2)

    #assina e envia mensagem para o servidor
    print("Assinando a mensagem pra enviar para o Servidor...")
    mensagem = f"{A} {username_cliente}"
    sig_A = gerar_assinatura_ecdsa(sk_client, mensagem) 
    mensagem_assinada_cliente = {
        "A": A,
        "assinatura_A": sig_A.hex(),
        "username_cliente": username_cliente
    }
    time.sleep(3)
    #enviar a mensagem assinada para o servidor
    client_socket.send(json.dumps(mensagem_assinada_cliente).encode())
    print("MENSAGEM ASSINADA ENVIADA PARA O SERVIDOR!!!\n")


    # Espera pela resposta do servidor
    print("___________________________________________________\n")
    print("ESPERANDO RESPOSTA DO SERVIDOR...\n")
    print("___________________________________________________\n")


    #recebe a mensagem do servidor
    data = client_socket.recv(1024)
    mensagem_assinada_servidor = json.loads(data.decode())
    print("MENSAGEM RECEBIDA DO SERVIDOR!!!")

    # Extrai B, assinatura_B e username da mensagem do servidor
    B = int(mensagem_assinada_servidor["B"])
    sig_B = bytes.fromhex(mensagem_assinada_servidor["assinatura_B"])
    username_servidor = mensagem_assinada_servidor["username_servidor"]
    print(f"  B: {B}")
    print(f"  Assinatura Servidor: {sig_B}")
    print(f"  Username Servidor: {username_servidor}\n")
    time.sleep(3)


# Verifica a assinatura ECDSA do servidor
    print(f"VERIFICANDO ASSINATURA ECDSA DO SERVIDOR: {username_servidor}...")
    time.sleep(1)
    if not verificar_assinatura_ecdsa(vk, f"{B} {username_servidor}".encode(), sig_B):
        client_socket.close()
        print(f"\nConexão fechada com o servidor.")
        return
    time.sleep(3)

    #Calcula a chave Secreta compartilhada S
    S = pow(B, a, p)
    print("___________________________________________________\n")
    print(f"Chave Secreta compartilhada S: {S}\n")

    client_socket.close()
    print(f"Conexão fechada com o servidor.")

if __name__ == "__main__":
    main()

