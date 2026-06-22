import os
import json
import time
import secrets
import smtplib
from base64 import b64encode, b64decode
from email.message import EmailMessage

from flask import Flask, render_template, request
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


load_dotenv()

app = Flask(__name__)

PASTA_DADOS = "data"
PASTA_COFRE = "vault"

ARQUIVO_DADOS = os.path.join(PASTA_DADOS, "encrypted_data.json")
ARQUIVO_COFRE = os.path.join(PASTA_COFRE, "secret_vault.json")
ARQUIVO_CODIGO = os.path.join(PASTA_COFRE, "access_code.json")
ARQUIVO_POLITICA_ACESSO = os.path.join(PASTA_COFRE, "access_policy.json")


def garantir_pastas():
    os.makedirs(PASTA_DADOS, exist_ok=True)
    os.makedirs(PASTA_COFRE, exist_ok=True)


def gerar_chave_aes():
    return AESGCM.generate_key(bit_length=256)


def salvar_chave_no_cofre(chave_aes):
    garantir_pastas()

    chave_base64 = b64encode(chave_aes).decode("utf-8")

    cofre = {
        "nome": "local-secret-vault-demo",
        "algoritmo": "AES-256-GCM",
        "aes_key": chave_base64
    }

    with open(ARQUIVO_COFRE, "w", encoding="utf-8") as arquivo:
        json.dump(cofre, arquivo, indent=4, ensure_ascii=False)


def buscar_chave_no_cofre():
    with open(ARQUIVO_COFRE, "r", encoding="utf-8") as arquivo:
        cofre = json.load(arquivo)

    chave_base64 = cofre["aes_key"]
    return b64decode(chave_base64)


def salvar_email_autorizado(email):
    garantir_pastas()

    politica = {
        "email_autorizado": email.strip().lower()
    }

    with open(ARQUIVO_POLITICA_ACESSO, "w", encoding="utf-8") as arquivo:
        json.dump(politica, arquivo, indent=4, ensure_ascii=False)


def carregar_email_autorizado():
    with open(ARQUIVO_POLITICA_ACESSO, "r", encoding="utf-8") as arquivo:
        politica = json.load(arquivo)

    return politica["email_autorizado"].strip().lower()


def criptografar_dados(dado_original, chave_aes):
    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)

    dado_em_bytes = json.dumps(dado_original, ensure_ascii=False).encode("utf-8")

    dado_criptografado = aesgcm.encrypt(
        nonce,
        dado_em_bytes,
        None
    )

    return {
        "nonce": b64encode(nonce).decode("utf-8"),
        "dado_criptografado": b64encode(dado_criptografado).decode("utf-8")
    }


def descriptografar_dados(pacote_criptografado, chave_aes):
    aesgcm = AESGCM(chave_aes)

    nonce = b64decode(pacote_criptografado["nonce"])
    dado_criptografado = b64decode(pacote_criptografado["dado_criptografado"])

    dado_original = aesgcm.decrypt(
        nonce,
        dado_criptografado,
        None
    )

    return json.loads(dado_original.decode("utf-8"))


def salvar_json(nome_arquivo, conteudo):
    garantir_pastas()

    with open(nome_arquivo, "w", encoding="utf-8") as arquivo:
        json.dump(conteudo, arquivo, indent=4, ensure_ascii=False)


def carregar_json(nome_arquivo):
    with open(nome_arquivo, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def formatar_json(conteudo):
    return json.dumps(conteudo, indent=4, ensure_ascii=False)


def gerar_codigo_acesso():
    return str(secrets.randbelow(900000) + 100000)


def salvar_codigo_acesso(email, codigo):
    garantir_pastas()

    codigo_temporario = {
        "email": email.strip().lower(),
        "codigo": codigo,
        "expira_em": int(time.time()) + 300
    }

    with open(ARQUIVO_CODIGO, "w", encoding="utf-8") as arquivo:
        json.dump(codigo_temporario, arquivo, indent=4, ensure_ascii=False)


def validar_codigo_acesso(codigo):
    with open(ARQUIVO_CODIGO, "r", encoding="utf-8") as arquivo:
        codigo_salvo = json.load(arquivo)

    codigo_digitado = codigo.strip()

    if int(time.time()) > codigo_salvo["expira_em"]:
        return False

    if codigo_digitado != codigo_salvo["codigo"]:
        return False

    return True


def apagar_codigo_acesso():
    if os.path.exists(ARQUIVO_CODIGO):
        os.remove(ARQUIVO_CODIGO)


def enviar_email_codigo(destinatario, codigo):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)

    if smtp_password:
        smtp_password = smtp_password.replace(" ", "")

    if not smtp_host or not smtp_user or not smtp_password:
        raise Exception("Configuração de e-mail incompleta no arquivo .env.")

    mensagem = EmailMessage()
    mensagem["Subject"] = "Código de acesso - AES Secure Demo"
    mensagem["From"] = email_from
    mensagem["To"] = destinatario

    mensagem.set_content(
        f"""
Olá,

Seu código temporário de acesso é:

{codigo}

Este código expira em 5 minutos.

AES Secure Demo
"""
    )

    with smtplib.SMTP(smtp_host, smtp_port) as servidor:
        servidor.starttls()
        servidor.login(smtp_user, smtp_password)
        servidor.send_message(mensagem)


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        dado_criptografado=None,
        dado_recuperado=None,
        mensagem=None,
        erro=None
    )


@app.route("/criptografar", methods=["POST"])
def criptografar():
    nome = request.form.get("nome")
    documento = request.form.get("documento")
    informacao = request.form.get("informacao")
    email_autorizado = request.form.get("email_autorizado")

    if not nome or not documento or not informacao or not email_autorizado:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Preencha todos os campos para criptografar."
        )

    dado_original = {
        "nome": nome,
        "documento": documento,
        "informacao": informacao
    }

    chave_aes = gerar_chave_aes()

    salvar_chave_no_cofre(chave_aes)
    salvar_email_autorizado(email_autorizado)

    pacote_criptografado = criptografar_dados(
        dado_original,
        chave_aes
    )

    salvar_json(ARQUIVO_DADOS, pacote_criptografado)

    return render_template(
        "index.html",
        dado_criptografado=formatar_json(pacote_criptografado),
        dado_recuperado=None,
        mensagem="Dados criptografados com sucesso. A chave AES foi salva no cofre local e o e-mail autorizado foi registrado.",
        erro=None
    )


@app.route("/enviar_codigo", methods=["POST"])
def enviar_codigo():
    email = request.form.get("email_acesso")

    if not email:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Informe o e-mail autorizado para receber o código."
        )

    try:
        email_autorizado = carregar_email_autorizado()

        if email.strip().lower() != email_autorizado:
            return render_template(
                "index.html",
                dado_criptografado=None,
                dado_recuperado=None,
                mensagem=None,
                erro="E-mail não autorizado para acessar este dado."
            )

        codigo = gerar_codigo_acesso()
        salvar_codigo_acesso(email, codigo)
        enviar_email_codigo(email, codigo)

        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem="Código temporário enviado para o e-mail autorizado.",
            erro=None
        )

    except FileNotFoundError:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Nenhum dado criptografado ou e-mail autorizado foi encontrado. Criptografe algo primeiro."
        )

    except Exception as erro:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro=f"Não foi possível enviar o código por e-mail. Verifique o arquivo .env. Detalhe: {erro}"
        )


@app.route("/descriptografar", methods=["POST"])
def descriptografar():
    codigo = request.form.get("codigo_acesso")

    if not codigo:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Informe o código temporário para acessar o dado."
        )

    try:
        codigo_valido = validar_codigo_acesso(codigo)

        if not codigo_valido:
            return render_template(
                "index.html",
                dado_criptografado=None,
                dado_recuperado=None,
                mensagem=None,
                erro="Código inválido ou expirado."
            )

        dado_criptografado = carregar_json(ARQUIVO_DADOS)
        chave_aes = buscar_chave_no_cofre()

        dado_recuperado = descriptografar_dados(
            dado_criptografado,
            chave_aes
        )

        apagar_codigo_acesso()

        return render_template(
            "index.html",
            dado_criptografado=formatar_json(dado_criptografado),
            dado_recuperado=formatar_json(dado_recuperado),
            mensagem="Acesso validado. A aplicação buscou a chave AES no cofre local e descriptografou o dado.",
            erro=None
        )

    except FileNotFoundError:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Nenhum dado criptografado, chave ou código foi encontrado. Criptografe algo e solicite um código primeiro."
        )

    except Exception:
        return render_template(
            "index.html",
            dado_criptografado=None,
            dado_recuperado=None,
            mensagem=None,
            erro="Não foi possível descriptografar. O arquivo pode ter sido alterado ou a chave não está disponível."
        )


if __name__ == "__main__":
    app.run(debug=True)