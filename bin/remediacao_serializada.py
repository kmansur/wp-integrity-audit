"""Remediação restrita de opções PHP serializadas do WordPress, sem executar PHP.

Somente arrays e valores escalares são aceitos. Objetos e referências são bloqueados.
"""
from __future__ import annotations

import hashlib
import re

class SerializacaoInsegura(ValueError):
    """Estrutura serializada não suportada ou inconsistente."""

class LeitorPHP:
    def __init__(self, dados: bytes):
        if len(dados) > 2_000_000:
            raise SerializacaoInsegura("Valor serializado excede 2 MiB")
        self.dados = dados
        self.pos = 0
        self.nos = 0

    def ler(self, tamanho: int) -> bytes:
        if tamanho < 0 or tamanho > len(self.dados) - self.pos:
            raise SerializacaoInsegura("Comprimento serializado inválido")
        fatia = self.dados[self.pos:self.pos + tamanho]
        self.pos += tamanho
        return fatia

    def numero(self, fim: bytes) -> int:
        i = self.dados.find(fim, self.pos)
        if i < 0 or i - self.pos > 20:
            raise SerializacaoInsegura("Inteiro serializado inválido")
        bruto = self.ler(i - self.pos)
        self.ler(len(fim))
        if not re.fullmatch(rb"-?(?:0|[1-9][0-9]*)", bruto):
            raise SerializacaoInsegura("Formato numérico inválido")
        return int(bruto)

    def valor(self, nivel: int = 0):
        self.nos += 1
        if nivel > 32 or self.nos > 50000:
            raise SerializacaoInsegura("Profundidade ou número de elementos excedido")
        tipo = self.ler(2)
        if tipo == b"N;":
            return None
        if tipo == b"b:":
            dado = self.ler(2)
            if dado not in (b"0;", b"1;"):
                raise SerializacaoInsegura("Booleano inválido")
            return dado == b"1;"
        if tipo == b"i:":
            return self.numero(b";")
        if tipo == b"d:":
            i = self.dados.find(b";", self.pos)
            if i < 0 or i - self.pos > 64:
                raise SerializacaoInsegura("Float inválido")
            raw = self.ler(i - self.pos)
            self.ler(1)
            if not re.fullmatch(rb"-?(?:[0-9]+(?:\.[0-9]+)?(?:E[+-]?[0-9]+)?|INF|NAN)", raw):
                raise SerializacaoInsegura("Float inválido")
            return ("float", raw)
        if tipo == b"s:":
            tamanho = self.numero(b':"')
            texto = self.ler(tamanho)
            if self.ler(2) != b'";':
                raise SerializacaoInsegura("Terminador de string inválido")
            return texto
        if tipo == b"a:":
            quantidade = self.numero(b":{")
            if quantidade > 50000:
                raise SerializacaoInsegura("Array excessivo")
            pares = []
            chaves = set()
            for _ in range(quantidade):
                chave = self.valor(nivel + 1)
                if type(chave) not in (int, bytes) or chave in chaves:
                    raise SerializacaoInsegura("Chave inválida ou duplicada")
                chaves.add(chave)
                pares.append((chave, self.valor(nivel + 1)))
            if self.ler(1) != b"}":
                raise SerializacaoInsegura("Array não terminado")
            return ("array", pares)
        raise SerializacaoInsegura("Objeto, referência ou tipo PHP não permitido")

    def completo(self):
        resultado = self.valor()
        if self.pos != len(self.dados) or serializar(resultado) != self.dados:
            raise SerializacaoInsegura("Serialização não canônica ou dados adicionais")
        return resultado


def serializar(valor) -> bytes:
    if valor is None:
        return b"N;"
    if type(valor) is bool:
        return b"b:1;" if valor else b"b:0;"
    if type(valor) is int:
        return b"i:" + str(valor).encode("ascii") + b";"
    if type(valor) is bytes:
        return b"s:" + str(len(valor)).encode("ascii") + b':"' + valor + b'";'
    if type(valor) is tuple and len(valor) == 2 and valor[0] == "float":
        return b"d:" + valor[1] + b";"
    if type(valor) is tuple and len(valor) == 2 and valor[0] == "array":
        pares = valor[1]
        return (b"a:" + str(len(pares)).encode("ascii") + b":{" +
                b"".join(serializar(chave) + serializar(item) for chave, item in pares) + b"}")
    raise SerializacaoInsegura("Tipo não serializável com segurança")


def remover_hook_cron(dados: bytes, hook: str) -> tuple[bytes, int]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", hook):
        raise SerializacaoInsegura("Hook inválido")
    obj = LeitorPHP(dados).completo()
    if not isinstance(obj, tuple) or obj[0] != "array":
        raise SerializacaoInsegura("Cron não é um array")
    novo = []
    total = 0
    for timestamp, valor in obj[1]:
        if timestamp == b"version":
            novo.append((timestamp, valor))
            continue
        if not isinstance(valor, tuple) or valor[0] != "array":
            raise SerializacaoInsegura("Cron contém agendamento inesperado")
        eventos = []
        for chave, registros in valor[1]:
            if chave == hook.encode("utf-8"):
                total += len(registros[1]) if isinstance(registros, tuple) and registros[0] == "array" else 1
            else:
                eventos.append((chave, registros))
        if eventos:
            novo.append((timestamp, ("array", eventos)))
    return serializar(("array", novo)), total


def desativar_plugin(dados: bytes, plugin: str) -> tuple[bytes, int]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_./-]{1,150}\.php", plugin) or ".." in plugin.split("/"):
        raise SerializacaoInsegura("Identificador do plugin inválido")
    obj = LeitorPHP(dados).completo()
    if not isinstance(obj, tuple) or obj[0] != "array" or any(type(k) is not int or type(v) is not bytes for k, v in obj[1]):
        raise SerializacaoInsegura("Lista de plugins não é uma lista serializada simples")
    restante = [v for _, v in obj[1] if v != plugin.encode("utf-8")]
    return serializar(("array", list(enumerate(restante)))), len(obj[1]) - len(restante)


def sha256_bytes(dados: bytes) -> str:
    return hashlib.sha256(dados).hexdigest()
