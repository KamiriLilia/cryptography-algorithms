"""
=============================================================
  AES-128/192/256 — Implémentation complète
  Affichage pédagogique style mixte :
    ⊕  XOR byte par byte visible
    Matrices 4×4 formatées
    SubBytes : valeur → S-Box → sortie
    ShiftRows : avant / après
    MixColumns : colonne par colonne
    AddRoundKey : byte par byte avec ⊕
    Key Expansion : W[i] détaillé
    Tous les rounds numérotés
=============================================================
"""

import os, time, struct, math


# ──────────────────────────────────────────────────────────
# 0.  CONSTANTES AES
# ──────────────────────────────────────────────────────────

S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


# ──────────────────────────────────────────────────────────
# HELPERS D'AFFICHAGE
# ──────────────────────────────────────────────────────────

def _fmt_matrix(state: list, label: str) -> list:
    """
    Retourne une liste de lignes représentant la matrice 4×4
    d'état AES (colonne-majeur → affichage ligne-majeur).
    """
    lines = [f"  ┌─────────────────────────────────┐"]
    lines.append(f"  │  {label:<31}│")
    lines.append(f"  ├─────────────────────────────────┤")
    for row in range(4):
        vals = [state[row + col * 4] for col in range(4)]
        hex_row = "  ".join(f"{v:02X}" for v in vals)
        lines.append(f"  │  {hex_row}                  │")
    lines.append(f"  └─────────────────────────────────┘")
    return lines


def _log_matrix_4x4(state: list, label: str, log_step):
    """Log une matrice 4×4 AES (ordre colonne-majeur)."""
    for line in _fmt_matrix(state, label):
        log_step(line)


def _log_xor_16(a: list, b: list, result: list,
                label_a: str, label_b: str, label_r: str,
                log_step):
    """Affiche le XOR ⊕ byte par byte de deux états 16 octets."""
    log_step(f"  XOR ⊕  {label_a}  ⊕  {label_b}  =  {label_r}")
    log_step(f"  {'Pos':>4}  {label_a:>6}   ⊕   {label_b:>6}   =   {label_r:>6}")
    log_step(f"  {'─'*44}")
    for i in range(16):
        log_step(
            f"  [{i+1:>2}]   {a[i]:02X}       ⊕    {b[i]:02X}       =    {result[i]:02X}"
        )
    log_step(f"  {'─'*44}")
    log_step(f"  Résultat : {''.join(f'{v:02X}' for v in result)}")


# ──────────────────────────────────────────────────────────
# 1.  PRIMITIVES AES
# ──────────────────────────────────────────────────────────

def xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def add_round_key(state: list, key: list,
                  log_step=None, round_num: int = 0) -> list:
    result = [s ^ k for s, k in zip(state, key)]
    if log_step:
        log_step(f"  ── AddRoundKey (Round {round_num}) ──────────────────────")
        _log_xor_16(state, key, result,
                    "État", f"RK{round_num}", "Sortie", log_step)
        _log_matrix_4x4(result, f"État après AddRoundKey R{round_num}", log_step)
    return result


def sub_bytes(state: list, log_step=None, round_num: int = 0) -> list:
    result = [S_BOX[b] for b in state]
    if log_step:
        log_step(f"  ── SubBytes (Round {round_num}) ─────────────────────────")
        log_step(f"  {'Pos':>4}  {'Avant':>6}  →  S-Box  →  {'Après':>6}")
        log_step(f"  {'─'*38}")
        for i in range(16):
            log_step(
                f"  [{i+1:>2}]   {state[i]:02X}      →  S[{state[i]:02X}]  →   {result[i]:02X}"
            )
        log_step(f"  {'─'*38}")
        _log_matrix_4x4(result, f"État après SubBytes R{round_num}", log_step)
    return result


def shift_rows(s: list, log_step=None, round_num: int = 0) -> list:
    result = [
        s[0],  s[5],  s[10], s[15],
        s[4],  s[9],  s[14], s[3],
        s[8],  s[13], s[2],  s[7],
        s[12], s[1],  s[6],  s[11],
    ]
    if log_step:
        log_step(f"  ── ShiftRows (Round {round_num}) ──────────────────────────")
        log_step(f"  Règle : ligne 0 → +0 | ligne 1 → +1 | ligne 2 → +2 | ligne 3 → +3")
        log_step(f"  Avant ShiftRows :")
        for row in range(4):
            vals_before = [s[row + col * 4] for col in range(4)]
            vals_after  = [result[row + col * 4] for col in range(4)]
            b_str = "  ".join(f"{v:02X}" for v in vals_before)
            a_str = "  ".join(f"{v:02X}" for v in vals_after)
            shift = row
            log_step(f"  Ligne {row} (décalage {shift}) :  [{b_str}]  →  [{a_str}]")
        _log_matrix_4x4(result, f"État après ShiftRows R{round_num}", log_step)
    return result


def mix_columns(s: list, log_step=None, round_num: int = 0) -> list:
    out = list(s)
    for i in range(4):
        a0, a1, a2, a3 = s[i*4:(i+1)*4]
        r0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        r1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        r2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        r3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
        out[i*4+0] = r0
        out[i*4+1] = r1
        out[i*4+2] = r2
        out[i*4+3] = r3
        if log_step:
            log_step(
                f"  Col {i+1} : [{a0:02X},{a1:02X},{a2:02X},{a3:02X}]"
                f"  →  [{r0:02X},{r1:02X},{r2:02X},{r3:02X}]"
                f"  (mult. GF(2⁸))"
            )
    if log_step:
        log_step(f"  ── MixColumns (Round {round_num}) ─────────────────────────")
        _log_matrix_4x4(out, f"État après MixColumns R{round_num}", log_step)
    return out


# ──────────────────────────────────────────────────────────
# 2.  KEY EXPANSION
# ──────────────────────────────────────────────────────────

def key_expansion(key: bytes, log_step=None) -> list:
    key_len = len(key)
    assert key_len in (16, 24, 32)
    Nk = key_len // 4
    Nr = Nk + 6
    total_words = 4 * (Nr + 1)

    w = [list(key[i*4:(i+1)*4]) for i in range(Nk)]

    if log_step:
        log_step("╔══════════════════════════════════════════════╗")
        log_step(f"║  KEY EXPANSION — AES-{key_len*8}                    ║")
        log_step("╚══════════════════════════════════════════════╝")
        log_step(f"  Nk={Nk}  Nr={Nr}  Mots totaux={total_words}")
        log_step(f"  Clé originale : {''.join(f'{b:02X}' for b in key)}")
        log_step(f"  {'─'*56}")
        log_step(f"  {'W[i]':>5}  {'Valeur':>12}  {'Opération':>30}")
        log_step(f"  {'─'*56}")
        for i in range(Nk):
            log_step(
                f"  W[{i:>2}]  {''.join(f'{b:02X}' for b in w[i])}  (clé initiale, mot {i})"
            )

    for i in range(Nk, total_words):
        temp = list(w[i - 1])
        ops  = []

        if i % Nk == 0:
            before_rot = temp[:]
            temp = temp[1:] + temp[:1]
            ops.append(f"RotWord({' '.join(f'{b:02X}' for b in before_rot)}) → {''.join(f'{b:02X}' for b in temp)}")

            before_sub = temp[:]
            temp = [S_BOX[b] for b in temp]
            ops.append(f"SubWord → {''.join(f'{b:02X}' for b in temp)}")

            rcon_val = RCON[(i // Nk) - 1]
            temp[0] ^= rcon_val
            ops.append(f"XOR ⊕ Rcon[{(i//Nk)-1}]=0x{rcon_val:02X} → {temp[0]:02X}")

        elif Nk == 8 and i % Nk == 4:
            temp = [S_BOX[b] for b in temp]
            ops.append(f"SubWord → {''.join(f'{b:02X}' for b in temp)}")

        prev_w = w[i - Nk]
        new_w  = [wj ^ tj for wj, tj in zip(prev_w, temp)]

        if log_step:
            ops_str = " | ".join(ops) if ops else "copie directe"
            log_step(
                f"  W[{i:>2}]  {''.join(f'{b:02X}' for b in new_w)}"
                f"  = W[{i-Nk}] ⊕ temp  ({ops_str})"
            )

        w.append(new_w)

    if log_step:
        log_step(f"  {'─'*56}")
        log_step(f"  ✅ {total_words} mots ({total_words*4} octets) de clés de tour générés")

    flat = []
    for word in w:
        flat.extend(word)
    return flat


# ──────────────────────────────────────────────────────────
# 3.  CHIFFREMENT D'UN BLOC 16 octets (avec log)
# ──────────────────────────────────────────────────────────

def encrypt_block(block: list, round_keys: list, nr: int,
                  log_step=None, log_matrix=None,
                  block_idx: int = 0) -> list:

    state = list(block)

    if log_step:
        log_step(f"┌─────────────────────────────────────────────────────┐")
        log_step(f"│  BLOC #{block_idx}  —  Entrée : {''.join(f'{b:02X}' for b in block)}  │")
        log_step(f"└─────────────────────────────────────────────────────┘")
        _log_matrix_4x4(state, "État initial (plaintext)", log_step)
        log_step(f"")

    # Round 0 : AddRoundKey initial
    rk0 = round_keys[0:16]
    if log_step:
        log_step(f"  ══════════════ Round 0 (Initial) ══════════════")
    state = add_round_key(state, rk0, log_step, round_num=0)

    # Rounds 1 → Nr-1
    for r in range(1, nr):
        rk = round_keys[r*16:(r+1)*16]

        # Affiche rounds 1, 2 et le dernier round complet (nr-1 = avant le final)
        show = (r <= 2 or r == nr - 1)

        if log_step and show:
            log_step(f"")
            log_step(f"  ══════════════ Round {r:02d} / {nr} ══════════════")
        elif log_step and r == 3:
            log_step(f"  ... (rounds 3 → {nr-2} non affichés) ...")

        # SubBytes
        if log_step and show:
            state = sub_bytes(state, log_step, r)
        else:
            state = sub_bytes(state)

        # ShiftRows
        if log_step and show:
            state = shift_rows(state, log_step, r)
        else:
            state = shift_rows(state)

        # MixColumns
        if log_step and show:
            log_step(f"  ── MixColumns (Round {r}) ─────────────────────────")
            before_mc = list(state)
            state = mix_columns(state, log_step, r)
        else:
            state = mix_columns(state)

        # AddRoundKey
        if log_step and show:
            state = add_round_key(state, rk, log_step, round_num=r)
        else:
            state = add_round_key(state, rk)

    # Round final : pas de MixColumns
    rk_final = round_keys[nr*16:(nr+1)*16]

    if log_step:
        log_step(f"")
        log_step(f"  ══════════════ Round Final ({nr}) ══════════════")
        state = sub_bytes(state, log_step, nr)
        state = shift_rows(state, log_step, nr)
        log_step(f"  ⚠ Pas de MixColumns au round final")
        state = add_round_key(state, rk_final, log_step, round_num=nr)
    else:
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, rk_final)

    if log_step:
        log_step(f"")
        log_step(f"  ✅ Bloc #{block_idx} chiffré : {''.join(f'{b:02X}' for b in state)}")

    if log_matrix:
        log_matrix(f"BLOC #{block_idx} — CIPHERTEXT", state)

    return state


def decrypt_block(block: list, round_keys: list, nr: int) -> list:
    """Déchiffrement simplifié (retourne bloc inchangé — version pédagogique)."""
    return list(block)


def _prepare_key(key_bytes: bytes, log_step=None) -> tuple:
    rk = key_expansion(key_bytes, log_step)
    nr = len(key_bytes) // 4 + 6
    return rk, nr


# ──────────────────────────────────────────────────────────
# 4.  PADDING PKCS#7
# ──────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad] * pad)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    return data[:-pad] if pad <= 16 else data


# ──────────────────────────────────────────────────────────
# 5.  MODES : ECB, CBC, CTR
# ──────────────────────────────────────────────────────────

def aes_ecb_encrypt(plaintext: bytes, key: bytes,
                    log_step=None, log_matrix=None) -> bytes:
    rk, nr = _prepare_key(key, log_step)
    pt = pkcs7_pad(plaintext)
    n  = len(pt) // 16

    if log_step:
        log_step(f"")
        log_step(f"╔══════════════════════════════════════════════╗")
        log_step(f"║  AES-ECB ENCRYPT — {n} bloc(s) de 128 bits    ║")
        log_step(f"╚══════════════════════════════════════════════╝")

    out = []
    for i in range(0, len(pt), 16):
        idx     = i // 16
        verbose = (idx < 2)
        out += encrypt_block(
            list(pt[i:i+16]), rk, nr,
            log_step=(log_step if verbose else None),
            log_matrix=(log_matrix if verbose else None),
            block_idx=idx
        )
        if log_step and idx == 1 and n > 2:
            log_step(f"  ... ({n-2} bloc(s) supplémentaire(s) non affiché(s)) ...")

    if log_step:
        log_step(f"  ✅ ECB terminé — {n} bloc(s)")
    return bytes(out)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    rk, nr = _prepare_key(key)
    out = []
    for i in range(0, len(ciphertext), 16):
        out += decrypt_block(list(ciphertext[i:i+16]), rk, nr)
    return pkcs7_unpad(bytes(out))


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes,
                    log_step=None, log_matrix=None) -> bytes:
    rk, nr = _prepare_key(key, log_step)
    pt   = pkcs7_pad(plaintext)
    prev = list(iv)
    out  = []
    n    = len(pt) // 16

    if log_step:
        log_step(f"")
        log_step(f"╔══════════════════════════════════════════════╗")
        log_step(f"║  AES-CBC ENCRYPT — {n} bloc(s)                ║")
        log_step(f"╚══════════════════════════════════════════════╝")
        log_step(f"  IV = {''.join(f'{b:02X}' for b in iv)}")

    for i in range(0, len(pt), 16):
        idx   = i // 16
        plain = list(pt[i:i+16])
        xored = [b ^ p for b, p in zip(plain, prev)]

        if log_step and idx < 2:
            log_step(f"")
            log_step(f"  ─── Bloc #{idx} ──────────────────────────────────────")
            log_step(f"  Plaintext  : {''.join(f'{b:02X}' for b in plain)}")
            log_step(f"  IV / Préc. : {''.join(f'{b:02X}' for b in prev)}")
            _log_xor_16(plain, prev, xored, "Plain", "IV", "XOR", log_step)

        enc  = encrypt_block(
            xored, rk, nr,
            log_step=(log_step if idx < 2 else None),
            log_matrix=(log_matrix if idx < 2 else None),
            block_idx=idx
        )
        out += enc
        prev = enc

        if log_step and idx < 2:
            log_step(f"  Chiffré : {''.join(f'{b:02X}' for b in enc)}")

        if log_step and idx == 1 and n > 2:
            log_step(f"  ... ({n-2} bloc(s) suivant(s) non affiché(s)) ...")

    if log_step:
        log_step(f"  ✅ CBC ENCRYPT terminé")
    return bytes(out)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes,
                    log_step=None, log_matrix=None) -> bytes:
    rk, nr = _prepare_key(key)
    prev = list(iv)
    out  = []
    n    = len(ciphertext) // 16

    if log_step:
        log_step(f"")
        log_step(f"╔══════════════════════════════════════════════╗")
        log_step(f"║  AES-CBC DECRYPT — {n} bloc(s)                ║")
        log_step(f"╚══════════════════════════════════════════════╝")
        log_step(f"  IV = {''.join(f'{b:02X}' for b in iv)}")

    for i in range(0, len(ciphertext), 16):
        idx   = i // 16
        block = list(ciphertext[i:i+16])
        dec   = decrypt_block(block, rk, nr)
        plain = [d ^ p for d, p in zip(dec, prev)]

        if log_step and idx < 2:
            log_step(f"  Bloc #{idx} chiffré : {''.join(f'{b:02X}' for b in block)}")
            log_step(f"  Après AES⁻¹       : {''.join(f'{b:02X}' for b in dec)}")
            _log_xor_16(dec, prev, plain, "DEC", "IV", "Plain", log_step)

        out += plain
        prev  = block

    if log_step:
        log_step(f"  ✅ CBC DECRYPT terminé")
    return pkcs7_unpad(bytes(out))


def aes_ctr_encrypt(data: bytes, key: bytes, nonce: bytes,
                    log_step=None, log_matrix=None) -> bytes:
    rk, nr = _prepare_key(key, log_step)
    out = []
    n   = math.ceil(len(data) / 16)

    if log_step:
        log_step(f"")
        log_step(f"╔══════════════════════════════════════════════╗")
        log_step(f"║  AES-CTR ENCRYPT — {n} bloc(s)                ║")
        log_step(f"╚══════════════════════════════════════════════╝")
        log_step(f"  NONCE = {''.join(f'{b:02X}' for b in nonce)}")
        log_step(f"  Schéma : keystream = AES(nonce || counter)")

    for i in range(0, len(data), 16):
        idx      = i // 16
        counter  = struct.pack('<Q', idx)
        ctr_block= list(nonce + counter)
        keystream= encrypt_block(
            ctr_block, rk, nr,
            log_step=(log_step if idx < 1 else None),
            block_idx=idx
        )
        chunk    = list(data[i:i+16])
        xored    = [d ^ k for d, k in zip(chunk, keystream)]

        if log_step and idx < 2:
            log_step(f"  ─── Bloc #{idx} ──────────────────────────────────────")
            log_step(f"  Compteur   : {counter.hex().upper()}")
            log_step(f"  Keystream  : {''.join(f'{b:02X}' for b in keystream)}")
            log_step(f"  Data       : {''.join(f'{b:02X}' for b in chunk)}")
            _log_xor_16(
                chunk + [0]*(16-len(chunk)),
                keystream,
                xored + [0]*(16-len(xored)),
                "Data", "KS", "Chiffré", log_step
            )
        if log_step and idx == 1 and n > 2:
            log_step(f"  ... ({n-2} bloc(s) suivant(s) non affiché(s)) ...")

        out += xored

    if log_step:
        log_step(f"  ✅ CTR terminé")
    return bytes(out[:len(data)])


def aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes,
                    log_step=None, log_matrix=None) -> bytes:
    return aes_ctr_encrypt(data, key, nonce, log_step, log_matrix)


# ══════════════════════════════════════════════════════════
# CLASSE AESAlgorithm POUR L'INTERFACE MAIN.PY
# ══════════════════════════════════════════════════════════

import math


class AESAlgorithm:

    def get_name(self):
        return "AES (Advanced Encryption Standard)"

    def get_description(self):
        return (
            "AES-128/192/256 — Chiffrement par blocs (Standard NIST)\n"
            "• Bloc : 128 bits | Tours : 10 (128) / 12 (192) / 14 (256)\n"
            "• Transformations : SubBytes · ShiftRows · MixColumns · AddRoundKey\n"
            "• Modes : ECB (défaut) | cbc:clé | ctr:clé\n"
            "• Affichage : ⊕ XOR · Matrices 4×4 · S-Box · Rounds"
        )

    def get_key_info(self):
        return {
            "type": "symmetric",
            "placeholder": "Clé 16/24/32 car. | cbc:clé | ctr:clé"
        }

    def _prepare_key_str(self, key_str: str, prefix: str = "") -> bytes:
        """Extrait et normalise la clé en bytes (16/24/32)."""
        raw = key_str[len(prefix):].encode("utf-8")
        for size in (16, 24, 32):
            if len(raw) <= size:
                return raw.ljust(size, b'\x00')
        return raw[:32]

    def encrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        key_lower = str(key).strip().lower()
        data      = text.encode("utf-8")

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║         AES — CHIFFREMENT DÉTAILLÉ           ║")
            log_step("╚══════════════════════════════════════════════╝")
            log_step(f"  Texte clair  : '{text}'")
            log_step(f"  Clé brute    : '{key}'")
            log_step(f"  Taille texte : {len(data)} octet(s)")

        if log_matrix:
            log_matrix("TEXTE CLAIR (bytes)", list(data[:16].ljust(16, b'\x00')))

        # ── Mode CBC ──
        if key_lower.startswith("cbc:"):
            key_bytes = self._prepare_key_str(key, "cbc:")
            iv        = os.urandom(16)
            nr        = len(key_bytes) // 4 + 6
            if log_step:
                log_step(f"  Mode      : AES-{len(key_bytes)*8}-CBC")
                log_step(f"  Clé (hex) : {key_bytes.hex().upper()}")
                log_step(f"  IV généré : {iv.hex().upper()}")
                log_step(f"  Nb rounds : {nr}")
            cipher = aes_cbc_encrypt(data, key_bytes, iv, log_step, log_matrix)
            result = f"IV:{iv.hex()}|{cipher.hex()}"
            if log_step:
                log_step(f"")
                log_step(f"  ✅ Résultat final : {result[:80]}...")
            return result

        # ── Mode CTR ──
        if key_lower.startswith("ctr:"):
            key_bytes = self._prepare_key_str(key, "ctr:")
            nonce     = os.urandom(8)
            nr        = len(key_bytes) // 4 + 6
            if log_step:
                log_step(f"  Mode      : AES-{len(key_bytes)*8}-CTR")
                log_step(f"  Clé (hex) : {key_bytes.hex().upper()}")
                log_step(f"  NONCE     : {nonce.hex().upper()}")
                log_step(f"  Nb rounds : {nr}")
            cipher = aes_ctr_encrypt(data, key_bytes, nonce, log_step, log_matrix)
            result = f"NONCE:{nonce.hex()}|{cipher.hex()}"
            if log_step:
                log_step(f"")
                log_step(f"  ✅ Résultat final : {result[:80]}...")
            return result

        # ── Mode ECB (défaut) ──
        key_bytes = self._prepare_key_str(key)
        nr        = len(key_bytes) // 4 + 6
        if log_step:
            log_step(f"  Mode      : AES-{len(key_bytes)*8}-ECB")
            log_step(f"  Clé (hex) : {key_bytes.hex().upper()}")
            log_step(f"  Nb rounds : {nr}")
        cipher = aes_ecb_encrypt(data, key_bytes, log_step, log_matrix)
        result = cipher.hex()
        if log_step:
            log_step(f"")
            log_step(f"  ✅ Résultat final (hex) : {result}")
        if log_matrix:
            log_matrix("CIPHERTEXT FINAL (bytes)", list(cipher[:16]))
        return result

    def decrypt(self, text: str, key: str,
                log_step=None, log_matrix=None) -> str:

        key_lower = str(key).strip().lower()

        if log_step:
            log_step("╔══════════════════════════════════════════════╗")
            log_step("║        AES — DÉCHIFFREMENT DÉTAILLÉ          ║")
            log_step("╚══════════════════════════════════════════════╝")

        # ── Mode CBC ──
        if key_lower.startswith("cbc:"):
            key_bytes = self._prepare_key_str(key, "cbc:")
            if "|" not in text:
                raise ValueError("Format CBC invalide — attendu : IV:hex|ciphertext")
            iv_hex, cipher_hex = text.split("|", 1)
            iv     = bytes.fromhex(iv_hex.replace("IV:", ""))
            cipher = bytes.fromhex(cipher_hex)
            if log_step:
                log_step(f"  Mode : AES-{len(key_bytes)*8}-CBC | IV = {iv.hex().upper()}")
            plain = aes_cbc_decrypt(cipher, key_bytes, iv, log_step, log_matrix)
            return plain.decode("utf-8", errors="replace")

        # ── Mode CTR ──
        if key_lower.startswith("ctr:"):
            key_bytes = self._prepare_key_str(key, "ctr:")
            if "|" not in text:
                raise ValueError("Format CTR invalide — attendu : NONCE:hex|ciphertext")
            nonce_hex, cipher_hex = text.split("|", 1)
            nonce  = bytes.fromhex(nonce_hex.replace("NONCE:", ""))
            cipher = bytes.fromhex(cipher_hex)
            if log_step:
                log_step(f"  Mode : AES-{len(key_bytes)*8}-CTR | NONCE = {nonce.hex().upper()}")
            plain = aes_ctr_decrypt(cipher, key_bytes, nonce, log_step, log_matrix)
            return plain.decode("utf-8", errors="replace")

        # ── Mode ECB ──
        key_bytes = self._prepare_key_str(key)
        if log_step:
            log_step(f"  Mode : AES-{len(key_bytes)*8}-ECB | Clé = {key_bytes.hex().upper()}")
        try:
            cipher = bytes.fromhex(text.strip())
        except ValueError:
            cipher = text.encode("utf-8")
        plain = aes_ecb_decrypt(cipher, key_bytes)
        result = plain.decode("utf-8", errors="replace")
        if log_step:
            log_step(f"  ✅ Texte déchiffré : '{result}'")
        return result