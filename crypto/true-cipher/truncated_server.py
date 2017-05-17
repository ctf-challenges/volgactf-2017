#!/usr/bin/env python
# -*- coding: ascii -*-
from __future__ import print_function
import os
import sys
import base64
from fractions import Fraction
import numpy.polynomial.polynomial as poly
from gmpy2 import invert
from ks import private, public, xn, flag


"""
    Parameters
"""

p = 3
q = 128
N = 167
df = 61
dg = 20
dr = 18

HELLO_MESSAGE = "Hello %user%!\nIf you want to encrypt your message, send\n\
    encrypt <base64(plaintext)>\nIf you want to decrypt your message, send\n\
    decrypt <base64(ciphertext)>\n"


"""
    Crypto utils
"""


def to_ring(f, m):
    res = []
    for i in range(len(f)):
        res.append(f[i] % m)
    return res


def subpoly(f, g, m):
    return to_ring(poly.polysub(f, g), m)


def sumpoly(f, g, m):
    return to_ring(poly.polyadd(f, g), m)


def divpoly(f, g, m):
    fx = []
    gx = []
    for i in range(len(f)):
        fx.append(Fraction(int(f[i]), 1))
    for i in range(len(g)):
        gx.append(Fraction(int(g[i]), 1))
    div = poly.polydiv(fx, gx)
    div0 = div[0] # f // g
    div1 = div[1] # f % g
    for i in range(len(div0)):
        fract = str(div0[i]).split('/')
        if len(fract) == 2:
            a = int(fract[0])
            b = int(fract[1])
            div0[i] = a * int(invert(b, m))
        div0[i] = int(div0[i] % m)
    for i in range(len(div1)):
        fract = str(div1[i]).split('/')
        if len(fract) == 2:
            a = int(fract[0])
            b = int(fract[1])
            div1[i] = a * int(invert(b, m))
        div1[i] = int(div1[i] % m)
    return (div0, div1)


def mulpoly(f, g, m, xn):
    mul = poly.polymul(f, g)
    div = divpoly(mul, xn, m)[1]
    return to_ring(div, m)


def m2poly(m):
    return list(map(int, list(''.join(map(lambda x: bin(ord(x))[2:].zfill(8), m)))))


def poly2m(pol):
    res = ""
    b = [int(i) for i in pol]
    while len(res) != 16:
        ch = 0
        pw = 7
        for _ in range(8):
            ch += b.pop(0) * (2**pw)
            pw -= 1
        res += chr(ch)
    return res


def mtopoly(m):
    return list(map(ord, m))


def polytom(pol):
    return ''.join(map(lambda x: chr(int(x)), pol))


def pad(m):
    return m + "\x20" * (16 - (len(m) % 16))


"""
    Cipher
"""


class TRUECipher:
    def __init__(self, p, q, N):
        self.p = p
        self.q = q
        self.N = N
        self.pub = public
        self.xn = xn
        self.f = private[0]
        self.fp = private[1]

    def encrypt(self, m, r):
        mul = mulpoly(r, self.pub, self.q, self.xn)
        e = sumpoly(mul, m, self.q)
        return e

    def decrypt(self, e):
        a = mulpoly(self.f, e, self.q, self.xn)
        a_ret = [i for i in a]
        for i in range(len(a)):
            if a[i] > int(self.q / 2):
                a[i] -= self.q
        b = to_ring(a, self.p)
        m = mulpoly(self.fp, b, self.p, self.xn)
        for i in range(len(m)):
            if m[i] > int(self.p / 2):
                m[i] -= self.p
        if len(m) < self.N:
            m.extend([0 for _ in range(self.N - len(m))])
        return m, a_ret

    def check_ciphertext(self, flag_messages, dec):
        for fm in flag_messages:
            fm = base64.b64decode(fm)
            fc = mtopoly(fm)
            fdec = self.decrypt(fc)
            try:
                a = poly2m(fdec[0])
                b = poly2m(dec[0])
            except Exception:
                a = fdec[0]
                b = dec[0]
            if a == b:
                eprint('DEBUG: decrypted user\'s poly: {0}'.format(dec[0]))
                eprint('DEBUG: matched flag\'s poly: {0}\n'.format(fdec[0]))
                eprint('DEBUG: decrypted user\'s message: {0}'.format(b))
                eprint('DEBUG: matched flag\'s message part: {0}\n'.format(a))
                raise Cheater('The oracle refuses to decrypt this message!')


"""
    Communication utils
"""


def read_message():
    return sys.stdin.readline()


def send_message(message):
    sys.stdout.write('{0}\r\n'.format(message))
    sys.stdout.flush()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


"""
    main
"""


class WrongCommandFormat(Exception):
    pass


class UnrecognizedCommand(Exception):
    pass


class TextFormatException(Exception):
    pass


class Cheater(Exception):
    pass


if __name__ == '__main__':
    try:
        # get the message
        send_message(HELLO_MESSAGE)
        send_message('command: ')
        m = read_message().strip()
        mes = m.split(' ')
        if len(mes) != 2:
            raise WrongCommandFormat('Wrong command format')

        # init the cipher handle
        cipher = TRUECipher(p, q, N)

        # process the received message
        cmd = mes[0].strip()
        m = mes[1].strip()
        eprint('Accepted command: {0} {1}'.format(cmd, m))
        if cmd == 'encrypt':
            m = base64.b64decode(m)
            m = pad(m)
            send_message('Message has {0} blocks'.format(len(m) // 16))
            r = [0 for _ in range(N)]
            while r.count(1) != dr:
                idx = ord(os.urandom(1)) % N
                if (r[idx] != 1) and (r[idx] != -1):
                    r[idx] = 1
            while r.count(-1) != dr:
                idx = ord(os.urandom(1)) % N
                if (r[idx] != 1) and (r[idx] != -1):
                    r[idx] = -1
            for i in range(0, len(m), 16):
                plain = m[i:i + 16]
                send_message('Block {0}'.format(i // 16 + 1))
                enc = cipher.encrypt(m2poly(plain), r)
                try:
                    ctext = polytom(enc)
                    send_message('Ciphertext (in base64): {0}'.format(base64.b64encode(ctext)))
                except Exception:
                    send_message('Ciphertext (as polynomial): {0}'.format(enc))

        elif cmd == 'decrypt':
            m = base64.b64decode(m)
            c = mtopoly(m)
            dec = cipher.decrypt(c)
            cipher.check_ciphertext(flag, dec)
            send_message('a = {0}'.format(dec[1]))
            try:
                plain = poly2m(dec[0])
                send_message('Plaintext: {0}'.format(plain))
            except Exception:
                send_message('Plaintext (as polynomial): {0}'.format(dec[0]))

        else:
            raise UnrecognizedCommand('Unknown command {0}'.format(cmd))

    except WrongCommandFormat as ex:
        eprint('Wrong command format error: {0}'.format(ex))
        send_message(str(ex))

    except UnrecognizedCommand as ex:
        eprint('Unrecognized command error: {0}'.format(ex))
        send_message(str(ex))

    except Cheater as ex:
        eprint('Cheater error: {0}'.format(ex))
        send_message(str(ex))

    except Exception as ex:
        eprint('Internal server error: {0}'.format(ex))
        send_message('Internal server error')

    finally:
        eprint('Done')
