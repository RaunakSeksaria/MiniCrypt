"""
api/server.py — FastAPI backend for the Minicrypt Clique Web Explorer (PA#0).
Exposes all crypto primitives via REST endpoints.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import json, traceback, threading, uuid, time

app = FastAPI(title="Minicrypt Clique Explorer API") # Reload trigger v2
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Pydantic models ──
class BuildRequest(BaseModel):
    foundation: str  # "AES" or "DLP"
    source: str      # target primitive: OWF, PRG, PRF, PRP, MAC, CRHF, HMAC
    seed: str        # hex seed

class ReduceRequest(BaseModel):
    foundation: str
    source: str
    target: str
    seed: str
    query: str       # hex query for target

class DemoRequest(BaseModel):
    pa: int
    params: Optional[dict] = {}

# ── Helpers ──
def safe_hex(b):
    if isinstance(b, bytes): return b.hex()
    if isinstance(b, int): return hex(b)
    return str(b)

# ── ROUTING TABLE ──
REDUCTIONS = {
    ("OWF","PRG"): [("OWF→PRG","HILL hard-core-bit (PA#1)")],
    ("OWF","OWP"): [("OWF→OWP","DLP is already a OWP")],
    ("PRG","PRF"): [("PRG→PRF","GGM tree construction (PA#2)")],
    ("PRF","PRP"): [("PRF→PRP","Luby-Rackoff 3-round Feistel")],
    ("PRF","MAC"): [("PRF→MAC","Mac_k(m)=F_k(m) (PA#5)")],
    ("PRP","MAC"): [("PRP→PRF","PRP/PRF switching lemma"),("PRF→MAC","Mac_k(m)=F_k(m)")],
    ("PRP","PRF"): [("PRP→PRF","PRP/PRF switching lemma")],
    ("CRHF","HMAC"): [("CRHF→HMAC","HMAC construction (PA#10)")],
    ("HMAC","MAC"): [("HMAC→MAC","HMAC is a MAC (direct)")],
    ("MAC","PRF"): [("MAC→PRF","Secure MAC is a PRF on random inputs")],
    ("PRG","OWF"): [("PRG→OWF","Any PRG is a OWF (immediate)")],
    ("PRF","PRG"): [("PRF→PRG","G(s)=F_s(0)||F_s(1) (PA#2)")],
    ("MAC","CRHF"): [("MAC→CRHF","MAC as compression in Merkle-Damgård (PA#7)")],
    ("HMAC","CRHF"): [("HMAC→CRHF","Fix key, H'(m)=HMAC_k(m) is CRHF")],
    ("OWF","PRF"): [("OWF→PRG","HILL (PA#1)"),("PRG→PRF","GGM (PA#2)")],
    ("OWF","MAC"): [("OWF→PRG","HILL"),("PRG→PRF","GGM"),("PRF→MAC","Direct")],
    ("PRG","MAC"): [("PRG→PRF","GGM (PA#2)"),("PRF→MAC","Direct (PA#5)")],
    ("OWF","PRP"): [("OWF→PRG","HILL"),("PRG→PRF","GGM"),("PRF→PRP","Luby-Rackoff")],
}

PROOF_DB = {
    "OWF→PRG": {"theorem":"HILL Theorem","security":"If PRG broken with advantage ε, OWF invertible with prob ε/poly(n)","pa":"PA#1"},
    "PRG→PRF": {"theorem":"GGM Theorem","security":"If PRF broken with advantage ε, PRG broken with advantage ε/n","pa":"PA#2"},
    "PRF→PRP": {"theorem":"Luby-Rackoff","security":"3-round Feistel: PRP advantage ≤ PRF advantage + q²/2ⁿ","pa":"PA#2"},
    "PRF→MAC": {"theorem":"PRF⇒MAC","security":"If MAC forged, PRF distinguished from random","pa":"PA#5"},
    "PRP→PRF": {"theorem":"PRP/PRF Switching Lemma","security":"Advantage ≤ q²/2ⁿ⁺¹ for q queries","pa":"PA#2"},
    "CRHF→HMAC": {"theorem":"HMAC Security (Bellare 2006)","security":"If compression is PRF, HMAC is secure MAC","pa":"PA#10"},
    "HMAC→MAC": {"theorem":"Direct","security":"HMAC satisfies EUF-CMA definition","pa":"PA#10"},
    "PRG→OWF": {"theorem":"Immediate","security":"Inverting G recovers seed, breaking pseudorandomness","pa":"PA#1"},
    "PRF→PRG": {"theorem":"PRF⇒PRG","security":"G(s)=F_s(0)||F_s(1); distinguisher for G breaks PRF","pa":"PA#2"},
    "OWF→OWP": {"theorem":"DLP OWP","security":"f(x)=gˣ mod p is already a permutation on Zq","pa":"PA#1"},
    "MAC→PRF": {"theorem":"MAC⇒PRF","security":"EUF-CMA MAC on random messages is pseudorandom","pa":"PA#5"},
    "MAC→CRHF": {"theorem":"MAC compression","security":"Collision in MAC = forgery, contradicting EUF-CMA","pa":"PA#7"},
    "HMAC→CRHF": {"theorem":"HMAC→CRHF","security":"Fix key k; collision in HMAC_k = MAC forgery","pa":"PA#10"},
}

# ── PRIMITIVE ABSTRACTION LAYER ──
class BasePrimitive:
    def evaluate(self, x: bytes) -> bytes: raise NotImplementedError

class PrimitiveWrapper(BasePrimitive):
    def __init__(self, impl, method_name='evaluate'):
        self.impl = impl
        self.method_name = method_name
    def evaluate(self, x: bytes) -> bytes:
        method = getattr(self.impl, self.method_name)
        return method(x)

class PrimitiveFactory:
    @staticmethod
    def get_instance(foundation: str, p_type: str, seed: bytes):
        """
        Returns a 'black-box' primitive object that Leg 2 can call.
        Leg 2 should not know if this is AES-based or DLP-based.
        """
        if foundation == "AES":
            from crypto.pa01_owf_prg import AES_OWF, PRG_from_AES, PRG_from_OWF
            from crypto.pa02_prf_ggm import PRF
            
            if p_type == "OWF":
                return PrimitiveWrapper(AES_OWF())
            if p_type == "PRG":
                # Wrapper that uses the specific seed from the UI
                class PRG_Theoretical:
                    def evaluate(self, x):
                        # x is ignored as seed is fixed for the chain
                        return PRG_from_OWF(AES_OWF(), 128).generate_bytes(seed, 16)
                return PRG_Theoretical()
            if p_type == "PRF":
                class PRF_Theoretical:
                    def evaluate(self, x):
                        return PRF(mode='aes').F(seed[:16], x)
                return PRF_Theoretical()
            # Fast AES-CTR for others
            class PRG_Practical:
                def evaluate(self, x):
                    return PRG_from_AES().generate(seed[:16], 16)
            return PRG_Practical()
        else: # DLP
            from crypto.pa13_miller_rabin import gen_safe_prime, find_generator
            from crypto.utils import bytes_to_int, mod_exp
            
            global _CACHED_DLP
            if '_CACHED_DLP' not in globals():
                p, q = gen_safe_prime(32)
                g = find_generator(p, q)
                globals()['_CACHED_DLP'] = (p, q, g)
            else:
                p, q, g = globals()['_CACHED_DLP']

            from crypto.pa01_owf_prg import DLP_OWF, PRG_from_OWF
            
            if p_type == "OWF":
                return PrimitiveWrapper(DLP_OWF(32))
            if p_type == "PRG":
                return PrimitiveWrapper(PRG_from_OWF(DLP_OWF(32), 32), 'generate_bytes')
            
            class DLPWrapper:
                def evaluate(self, x): 
                    val = bytes_to_int(x) % q
                    gx = mod_exp(g, val, p)
                    return gx.to_bytes((p.bit_length() + 7) // 8, 'big')
            return DLPWrapper()
        
        # Fallback
        class Identity:
            def evaluate(self, x): return x
        return Identity()

# ── Build endpoint (Column 1) ──
@app.post("/api/build")
def build_primitive(req: BuildRequest):
    try:
        seed_bytes = bytes.fromhex(req.seed) if req.seed else os.urandom(16)
        steps = []
        result_hex = ""

        if req.foundation == "AES":
            from crypto.aes import aes_encrypt_block
            # Robust normalization: pad with zeros or truncate to 16 bytes
            key = (seed_bytes + b'\x00' * 16)[:16]
            if req.source == "OWF":
                from crypto.utils import xor_bytes
                owf_out = xor_bytes(aes_encrypt_block(b'\x00'*16, key), key)
                steps.append({"fn":"AES-OWF: f(k) = AES_k(0¹²⁸) ⊕ k","input":key.hex(),"output":owf_out.hex()})
                result_hex = owf_out.hex()
            elif req.source in ("PRF","PRP"):
                steps.append({"fn":"AES as PRF/PRP (switching lemma)","input":key.hex(),"output":"F_k ready"})
                out = aes_encrypt_block(b'\x00'*16, key)
                steps.append({"fn":"F_k(0¹²⁸)","input":"00"*16,"output":out.hex()})
                result_hex = out.hex()
            elif req.source == "PRG":
                b0 = aes_encrypt_block(b'\x00'*16, key); b1 = aes_encrypt_block(b'\x00'*15+b'\x01', key)
                steps.append({"fn":"AES→PRF (switching lemma)","input":key.hex(),"output":"PRF ready"})
                steps.append({"fn":"G(s) = F_s(0) ‖ F_s(1)","input":key.hex(),"output":b0.hex()+b1.hex()})
                result_hex = b0.hex()+b1.hex()
            else:
                steps.append({"fn":f"AES → {req.source}","input":key.hex(),"output":"Ready"})
                result_hex = key.hex()
        else: # DLP
            from crypto.pa13_miller_rabin import gen_safe_prime, find_generator
            from crypto.utils import bytes_to_int, mod_exp
            
            # Use cached params for speed in Explorer
            global _CACHED_DLP
            if '_CACHED_DLP' not in globals():
                p, q = gen_safe_prime(32)
                g = find_generator(p, q)
                globals()['_CACHED_DLP'] = (p, q, g)
            else:
                p, q, g = globals()['_CACHED_DLP']

            x = bytes_to_int(seed_bytes) % q if bytes_to_int(seed_bytes) % q > 1 else 2
            gx = mod_exp(g, x, p)
            steps.append({"fn":f"DLP-OWF: g^x mod p (p={p})","input":str(x),"output":str(gx)})
            # Format hex without the '0x' prefix for frontend compatibility
            result_hex = f"{gx:x}"

        return {"steps":steps,"result":result_hex,"source":req.source,"foundation":req.foundation}
    except Exception as e:
        raise HTTPException(400, str(e)+"\n"+traceback.format_exc())

# ── Reduce endpoint (Column 2) ──
@app.post("/api/reduce")
def reduce_primitive(req: ReduceRequest):
    try:
        key_pair = (req.source, req.target)
        chain = REDUCTIONS.get(key_pair)
        if chain is None:
            return {"error": f"No direct reduction from {req.source} to {req.target}.",
                    "steps":[],"proofs":[],"output":"N/A"}

        seed_bytes = bytes.fromhex(req.seed) if req.seed else os.urandom(16)
        query_bytes = bytes.fromhex(req.query) if req.query else b'\x00'*16
        
        # Instantiate the TARGET primitive (the one we built via reduction)
        primitive_target = PrimitiveFactory.get_instance(req.foundation, req.target, seed_bytes)
        result_bytes = primitive_target.evaluate(query_bytes)
        output_hex = safe_hex(result_bytes)

        steps = []; proofs = []
        for label, desc in chain:
            proof = PROOF_DB.get(label, {"theorem":"","security":"","pa":""})
            proofs.append({"step":label,"description":desc,**proof})
            
            # Special case for HILL (PA#1) iterations display
            if label == "OWF→PRG" and req.source == "OWF" and req.target == "PRG":
                from crypto.pa01_owf_prg import PRG_from_OWF, AES_OWF
                from crypto.utils import bytes_to_bits
                prg_impl = PRG_from_OWF(AES_OWF(), 128) if req.foundation == "AES" else PRG_from_OWF(None, 32)
                res_bytes = prg_impl.generate_bytes(int.from_bytes(seed_bytes, 'big'), 16)
                all_bits = bytes_to_bits(res_bytes)
                curr_x = seed_bytes
                for i in range(4):
                    steps.append({"fn": f"HILL Iteration {i+1}", "input": f"x_{i}: {safe_hex(curr_x)[:8]}...", "output": f"Bit: {all_bits[i]} → Next State"})
                    # Mock flow for visualization
                    curr_x = (int.from_bytes(curr_x, 'big') + 1).to_bytes(16, 'big')
                steps.append({"fn": "...", "input": "Iterations 5-128", "output": "Truncated for brevity"})
            elif label == "PRG→PRF":
                # GGM Tree Trace: Show first 4 levels of tree walking
                from crypto.pa02_prf_ggm import GGM_PRF
                from crypto.utils import bytes_to_bits
                ggm = GGM_PRF()
                x_bits = bytes_to_bits(query_bytes)
                current = seed_bytes
                for i in range(4):
                    bit = x_bits[i]
                    g0 = ggm.prg.G0(current)
                    g1 = ggm.prg.G1(current)
                    chosen = g0 if bit == 0 else g1
                    steps.append({
                        "fn": f"GGM Tree Depth {i+1}",
                        "input": f"Node: {safe_hex(current)[:8]}... (Bit {bit})",
                        "output": f"→ {safe_hex(chosen)[:8]}..."
                    })
                    current = chosen
                steps.append({"fn": "...", "input": "Depths 5-128", "output": "Truncated for brevity"})
            else:
                # DYNAMIC: Actually call the intermediate primitive to show its output!
                mid_target = label.split("→")[-1]
                try:
                    mid_prim = PrimitiveFactory.get_instance(req.foundation, mid_target, seed_bytes)
                    mid_out = mid_prim.evaluate(query_bytes)
                    steps.append({"fn": desc, "input": safe_hex(query_bytes), "output": safe_hex(mid_out)})
                except Exception as e:
                    import traceback
                    print(f"DEBUG: Reduction step {label} failed: {e}\n{traceback.format_exc()}")
                    steps.append({"fn": desc, "input": safe_hex(query_bytes)[:8]+"...", "output": "→"})

        steps.append({"fn": f"Final {req.target} output", "input": safe_hex(query_bytes), "output": output_hex})
        return {"steps":steps,"proofs":proofs,"output":output_hex,"chain":[l for l,_ in chain], "source": req.source, "target": req.target}
    except Exception as e:
        raise HTTPException(400, str(e)+"\n"+traceback.format_exc())
    except Exception as e:
        raise HTTPException(400, str(e)+"\n"+traceback.format_exc())

# ── PA Demo endpoints ──
@app.post("/api/demo")
def run_demo(req: DemoRequest):
    try:
        if req.pa == 1:
            from crypto.pa01_owf_prg import AES_OWF, PRG_from_AES, run_statistical_tests, demonstrate_prg_inversion_v2
            from crypto.utils import bytes_to_bits, to_hex
            seed_hex = req.params.get("seed", "2b7e151628aed2a6abf7158809cf4f3c")
            length = int(req.params.get("length", 32))
            seed = bytes.fromhex(seed_hex)
            # Robust Normalization: Ensure exactly 16 bytes for AES
            seed = (seed + b'\x00' * 16)[:16]
            
            prg = PRG_from_AES()
            output = prg.generate(seed, length)
            
            task = req.params.get("task")
            bits_str = "".join([bin(b)[2:].zfill(8) for b in output])
            response = {
                "seed": to_hex(seed),
                "output": to_hex(output),
                "bits": bits_str,
            }

            if task == "randomness":
                # Only run expensive statistical tests when requested
                test_bits = prg.next_bits(seed, max(1000, length*8))
                response["stats"] = run_statistical_tests(test_bits)
                ones_count = sum(test_bits)
                response["ratio"] = ones_count / len(test_bits)
            
            if task == "inversion":
                # Only run expensive brute-force demo when requested
                response["inversion"] = demonstrate_prg_inversion_v2(prg)
            
            return response
        elif req.pa == 2:
            from crypto.pa02_prf_ggm import GGM_PRF
            from crypto.utils import to_hex, bytes_to_bits
            key_hex = req.params.get("key", "2b7e151628aed2a6abf7158809cf4f3c")
            query_hex = req.params.get("query", "00000000000000000000000000000001")
            depth = int(req.params.get("depth", 4))
            
            key = bytes.fromhex(key_hex)
            key = (key + b'\x00' * 16)[:16]
            
            # Interpret 'query' as a bit string (0101...) for PA#2
            query_str = req.params.get("query", "0000")
            query_bits = []
            for bit in query_str:
                if bit in ('0', '1'):
                    query_bits.append(int(bit))
            
            # Pad or truncate query bits to match depth
            query_bits = (query_bits + [0] * depth)[:depth]
            
            # Use the unified PRF wrapper with GGM mode
            from crypto.pa02_prf_ggm import PRF
            ggm = PRF(mode='ggm')
            task = req.params.get("task")
            
            if task == "game":
                from crypto.pa02_prf_ggm import distinguishing_game
                game_result = distinguishing_game(ggm, 100)
                return {"game": game_result}
            
            if task == "randomness":
                from crypto.pa02_prf_ggm import PRG_from_PRF
                from crypto.pa01_owf_prg import run_statistical_tests
                prg = PRG_from_PRF(ggm)
                test_bits = prg.next_bits(key, 2048)
                return {
                    "stats": run_statistical_tests(test_bits),
                    "ratio": sum(test_bits) / len(test_bits)
                }
            
            # For tree visualization, use the underlying GGM_PRF directly
            ggm_impl = ggm._impl 
            full_tree = ggm_impl.generate_full_tree(key, depth)
            trace = ggm_impl.evaluate_with_trace(key, query_bits)
            
            return {
                "key": to_hex(key),
                "query_bits": query_bits,
                "tree": full_tree,
                "trace": trace,
                "output": trace['output']
            }
        elif req.pa == 3:
            from crypto.pa03_cpa_enc import CPAEncryption, ind_cpa_game
            from crypto.utils import random_bytes, to_hex
            enc = CPAEncryption(); k = random_bytes(16)
            msg = req.params.get("message","Hello CPA!").encode()
            r, ct = enc.encrypt(k, msg)
            pt = enc.decrypt(k, r, ct)
            game = ind_cpa_game(enc, 50)
            return {"plaintext":msg.decode(),"nonce":to_hex(r),"ciphertext":to_hex(ct),"decrypted":pt.decode(),"match":pt==msg,"game":game}
        elif req.pa == 4:
            from crypto.pa04_modes import encrypt, decrypt
            from crypto.utils import random_bytes, to_hex
            k = random_bytes(16)
            msg = req.params.get("message","Modes of Operation test!").encode()
            results = {}
            for mode in ['CBC','OFB','CTR']:
                iv, ct = encrypt(mode, k, msg)
                pt = decrypt(mode, k, iv, ct)
                results[mode] = {"iv":to_hex(iv),"ciphertext":to_hex(ct),"decrypted":pt.decode(),"match":pt==msg}
            return results
        elif req.pa == 5:
            from crypto.pa05_mac import MAC, euf_cma_game
            from crypto.utils import random_bytes, to_hex
            mac = MAC(mode='cbc'); k = random_bytes(16)
            msg = b"Authenticate me!"
            tag = mac.Mac(k, msg)
            game = euf_cma_game(mac, 30, 10)
            return {"message":msg.decode(),"tag":to_hex(tag),"verify":mac.Vrfy(k,msg,tag),"game":game}
        elif req.pa == 6:
            from crypto.pa06_cca_enc import CCAEncryption, malleability_attack_demo
            from crypto.utils import random_bytes, to_hex
            cca = CCAEncryption(); ke=random_bytes(16); km=random_bytes(16)
            msg = b"CCA-secure message!"
            r,ct,tag = cca.encrypt(ke,km,msg)
            pt = cca.decrypt(ke,km,r,ct,tag)
            attack = malleability_attack_demo()
            return {"plaintext":msg.decode(),"decrypted":pt.decode(),"match":pt==msg,"tamper_rejected":cca.decrypt(ke,km,r,bytes([ct[0]^1])+ct[1:],tag) is None,"attack":{"cpa_malleable":attack['cpa_only']['malleable'],"cca_rejected":attack['cca_secure']['rejected']}}
        elif req.pa == 7:
            from crypto.pa07_merkle_damgard import create_toy_hash
            from crypto.utils import to_hex
            toy = create_toy_hash()
            msg = req.params.get("message","Hello Hash!").encode()
            trace = toy.hash_with_trace(msg)
            return trace
        elif req.pa == 8:
            from crypto.pa08_dlp_crhf import DLP_CRHF
            from crypto.utils import to_hex
            crhf = DLP_CRHF(bits=32)
            msg = req.params.get("message","Test DLP Hash").encode()
            h = crhf.hash(msg)
            return {"message":msg.decode(),"hash":to_hex(h),"p":crhf.dlp.p,"g":crhf.dlp.g,"h_pub":crhf.dlp.h}
        elif req.pa == 9:
            from crypto.pa09_birthday import attack_toy_hash, practical_context, make_toy_hash, birthday_attack_naive
            n_bits = int(req.params.get("n_bits", 12))
            hash_fn = make_toy_hash(n_bits)
            res = birthday_attack_naive(hash_fn, n_bits)
            ctx = practical_context()
            return {
                "n_bits": n_bits,
                "found": res.get("found", False),
                "evaluations": res.get("evaluations", 0),
                "expected": res.get("expected", 2 ** (n_bits / 2)),
                "ratio": round(res.get("ratio", 0), 3),
                "input1": res["input1"].hex() if res.get("found") else None,
                "input2": res["input2"].hex() if res.get("found") else None,
                "hash_value": res.get("hash_value"),
                "context": ctx,
            }
        elif req.pa == 10:
            from crypto.pa10_hmac import HMAC
            from crypto.utils import random_bytes, to_hex
            hmac = HMAC(bits=32); k = random_bytes(hmac.block_size)
            msg = b"HMAC test message"
            tag = hmac.mac(k, msg)
            return {"message":msg.decode(),"tag":to_hex(tag),"verify":hmac.verify(k,msg,tag),"tamper":not hmac.verify(k,b"wrong",tag)}
        elif req.pa == 11:
            from crypto.pa11_diffie_hellman import DiffieHellman, mitm_attack
            dh = DiffieHellman(bits=32)
            exch = dh.key_exchange()
            mitm = mitm_attack(dh)
            return {"exchange":{"p":exch['p'],"g":exch['g'],"A":exch['A'],"B":exch['B'],"K_alice":exch['K_alice'],"K_bob":exch['K_bob'],"match":exch['keys_match']},"mitm":{"eve_has_alice_key":mitm['eve_has_alice_key'],"eve_has_bob_key":mitm['eve_has_bob_key'],"alice_bob_same":mitm['alice_bob_same']}}
        elif req.pa == 12:
            from crypto.pa12_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt, pkcs15_encrypt, pkcs15_decrypt
            kp = rsa_keygen(256); m = int(req.params.get("message_int", 42))
            c = rsa_encrypt(kp.n, kp.e, m)
            d = rsa_decrypt(kp.d, kp.n, c)
            msg = req.params.get("message_pkcs", "RSA!").encode()
            c2 = pkcs15_encrypt(kp.n, kp.e, msg)
            d2 = pkcs15_decrypt(kp.d, kp.n, c2)
            return {"textbook":{"m":m,"c":str(c),"d":d,"match":d==m},"pkcs":{"message":msg.decode(),"decrypted":d2.decode(),"match":d2==msg},"n":str(kp.n),"e":kp.e,"bits":kp.bits}
        elif req.pa == 13:
            from crypto.pa13_miller_rabin import is_prime, gen_prime
            n = int(req.params.get("n", 1009))
            p = gen_prime(64)
            tests = {str(n): is_prime(n) for n in [2,3,17,561,1009,65537,n]}
            return {"input_test":f"{n} is prime? {is_prime(n)}","generated_prime":str(p),"bits":p.bit_length(),"tests":tests}
        elif req.pa == 14:
            from crypto.pa14_crt import crt, hastad_attack_demo
            res_str = req.params.get("residues", "2,3,2")
            mod_str = req.params.get("moduli", "3,5,7")
            res = [int(x) for x in res_str.split(",")]
            mods = [int(x) for x in mod_str.split(",")]
            x = crt(res, mods)
            attack = hastad_attack_demo(bits=128, e=3)
            return {"crt_result":{"residues":res,"moduli":mods,"solution":x},"hastad":{"success":attack['success'],"bits":attack['bits']}}
        elif req.pa == 15:
            from crypto.pa15_signatures import DigitalSignature, homomorphism_attack_demo
            ds = DigitalSignature(bits=256)
            msg = req.params.get("message", "Sign this!").encode()
            sigma = ds.sign(msg)
            attack = homomorphism_attack_demo(256)
            return {"message":msg.decode(),"signature":str(sigma),"verify":ds.verify(msg,sigma),"wrong":not ds.verify(b"wrong",sigma),"attack":{"raw_works":attack['raw_attack_works'],"hash_works":attack['hash_then_sign_attack_works']}}
        elif req.pa == 16:
            from crypto.pa16_elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt, malleability_attack
            key = elgamal_keygen(bits=32); m = int(req.params.get("message_int", 42))
            c1,c2 = elgamal_encrypt(key.pk, m)
            d = elgamal_decrypt(key.sk, key.p, c1, c2)
            att = malleability_attack(key, m)
            return {"m":m,"c1":c1,"c2":c2,"decrypted":d,"match":d==m,"malleability":att['attack_works'],"p":key.p,"g":key.g}
        elif req.pa == 17:
            from crypto.pa17_cca_pkc import CCA_PKC
            cca = CCA_PKC(eg_bits=32, rsa_bits=256)
            m = int(req.params.get("message_int", 42)); ct=cca.encrypt(m)
            pt=cca.decrypt(ct['c1'],ct['c2'],ct['sigma'])
            bad=cca.decrypt(ct['c1'],(ct['c2']*2)%cca.eg_key.p,ct['sigma'])
            return {"m":m,"decrypted":pt,"match":pt==m,"tamper_rejected":bad is None}
        elif req.pa == 18:
            from crypto.pa18_ot import run_ot
            m0 = int(req.params.get("m0", 42))
            m1 = int(req.params.get("m1", 99))
            b = int(req.params.get("b", 0))
            r = run_ot(m0, m1, b, bits=32)
            return {"m0": m0, "m1": m1, "b": b, "received": r['received'], "correct": r['correct']}
            
            
        elif req.pa == 19:
            from crypto.pa19_secure_and import SecureGates
            gates = SecureGates(bits=32)
            a = int(req.params.get("a", 1))
            b = int(req.params.get("b", 1))
            r = gates.secure_and(a, b)
            return {"input":{"a":a,"b":b},"result":r['result'],"correct":r['correct'],"all_gates": "Check server logs for other gate tests"}
        elif req.pa == 20:
            from crypto.pa20_mpc import build_comparator, build_equality, build_adder, int_to_bits, bits_to_int
            results = {}
            alice_val = int(req.params.get("alice_val", 7))
            bob_val = int(req.params.get("bob_val", 3))
            for name, builder in [
                ("comparator", build_comparator),
                ("equality", build_equality),
                ("adder", build_adder),
            ]:
                c = builder(4)
                r = c.evaluate_plain(int_to_bits(alice_val,4)+int_to_bits(bob_val,4))
                val = bits_to_int(r) if len(r)>1 else r[0]
                results[name] = {"x":alice_val,"y":bob_val,"result":val}
            return results
        else:
            return {"error":f"PA#{req.pa} not found"}
    except Exception as e:
        raise HTTPException(400, str(e)+"\n"+traceback.format_exc())


# ── PA#9 dedicated birthday-attack endpoints ──

_pa9_hunts: dict = {}


class PA9StartRequest(BaseModel):
    n_bits: int = 12


@app.post("/api/pa9/birthday/start")
def pa9_birthday_start(req: PA9StartRequest):
    """Launch a background birthday-attack thread on the toy hash. Returns hunt_id."""
    n_bits = max(4, min(20, req.n_bits))  # clamp to sane range
    hunt_id = str(uuid.uuid4())
    birthday_bound = 2 ** (n_bits / 2)
    state = {
        "hunt_id": hunt_id,
        "status": "running",
        "evaluations": 0,
        "n_bits": n_bits,
        "birthday_bound": birthday_bound,
        "collision": None,
        "started_at": time.time(),
        # Snapshot history for the probability curve: list of (k, prob) sampled
        "curve_points": [],
    }
    _pa9_hunts[hunt_id] = state

    def _hunt(state):
        from crypto.pa09_birthday import make_toy_hash
        import math as _math
        try:
            n = state["n_bits"]
            hash_fn = make_toy_hash(n)
            seen = {}
            MAX_EVALS = int(10 * (2 ** (n / 2))) + 2
            curve_sample_every = max(1, MAX_EVALS // 200)  # ~200 curve points max
            i = 0
            while state["status"] == "running" and i < MAX_EVALS:
                x = __import__('os').urandom(8)
                h = hash_fn(x)
                i += 1
                state["evaluations"] = i
                # Record theoretical probability curve points
                if i % curve_sample_every == 0:
                    k = i
                    prob = 1.0 - _math.exp(-k * (k - 1) / (2 ** n))
                    state["curve_points"].append({"k": k, "prob": round(prob, 6)})
                if h in seen and seen[h] != x:
                    state["collision"] = {
                        "input1": seen[h].hex(),
                        "input2": x.hex(),
                        "hash_value": h,
                        "hash_hex": f"{h:0{(n + 3) // 4}x}",
                    }
                    state["status"] = "found"
                    return
                seen[h] = x
            if state["status"] == "running":
                state["status"] = "exhausted"
        except Exception as exc:
            state["status"] = "error"
            state["error"] = str(exc)

    t = threading.Thread(target=_hunt, args=(state,), daemon=True)
    t.start()
    return {
        "hunt_id": hunt_id,
        "n_bits": n_bits,
        "birthday_bound": birthday_bound,
    }


@app.get("/api/pa9/birthday/status/{hunt_id}")
def pa9_birthday_status(hunt_id: str):
    """Poll current state of a PA9 birthday hunt."""
    state = _pa9_hunts.get(hunt_id)
    if state is None:
        raise HTTPException(404, "Hunt not found")
    n = state["n_bits"]
    k = state["evaluations"]
    import math as _math
    empirical_prob = 1.0 - _math.exp(-k * (k - 1) / (2 ** n)) if k > 1 else 0.0
    return {
        "hunt_id": hunt_id,
        "status": state["status"],
        "evaluations": k,
        "n_bits": n,
        "birthday_bound": state["birthday_bound"],
        "progress_pct": min(100.0, k / state["birthday_bound"] * 100),
        "empirical_prob": round(empirical_prob, 6),
        "collision": state["collision"],
        "curve_points": state["curve_points"],
    }


@app.post("/api/pa9/birthday/stop/{hunt_id}")
def pa9_birthday_stop(hunt_id: str):
    """Abort a running PA9 birthday hunt."""
    state = _pa9_hunts.get(hunt_id)
    if state is None:
        raise HTTPException(404, "Hunt not found")
    if state["status"] == "running":
        state["status"] = "stopped"
    return {"status": state["status"]}


# ── PA#8 dedicated endpoints ──

# Shared state for collision hunts  {hunt_id -> dict}
_pa8_hunts: dict = {}
_pa8_crhf_cache = None   # lazily initialised once

def _get_pa8_crhf():
    global _pa8_crhf_cache
    if _pa8_crhf_cache is None:
        from crypto.pa08_dlp_crhf import DLP_CRHF
        _pa8_crhf_cache = DLP_CRHF(bits=32)  # small group, fast
    return _pa8_crhf_cache


class PA8HashRequest(BaseModel):
    message: str


@app.post("/api/pa8/hash")
def pa8_live_hash(req: PA8HashRequest):
    """Hash a message and return the group element as hex (live, on every keystroke)."""
    try:
        from crypto.utils import to_hex
        crhf = _get_pa8_crhf()
        msg = req.message.encode()
        h = crhf.hash(msg)
        full_hex = to_hex(h)
        h_int = int.from_bytes(h, 'big')
        truncated = h_int & 0xFFFF
        return {
            "message": req.message,
            "hash_hex": full_hex,
            "truncated_16bit": truncated,
            "truncated_hex": f"{truncated:04x}",
            "p": crhf.dlp.p,
            "q": crhf.dlp.q,
            "g": crhf.dlp.g,
            "h_pub": crhf.dlp.h,
            "digest_bytes": crhf.digest_size,
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


@app.post("/api/pa8/collision/start")
def pa8_collision_start():
    """Launch a background birthday-attack thread (16-bit truncated output). Returns hunt_id."""
    hunt_id = str(uuid.uuid4())
    state = {
        "hunt_id": hunt_id,
        "status": "running",
        "evaluations": 0,
        "birthday_bound": 256,   # 2^(16/2)
        "output_bits": 16,
        "collision": None,
        "started_at": time.time(),
    }
    _pa8_hunts[hunt_id] = state

    def _hunt(state):
        try:
            crhf = _get_pa8_crhf()
            seen = {}     # truncated_hash -> message bytes
            MAX_EVALS = 2 ** 18  # safety cap
            mask = (1 << 16) - 1
            # Use a per-hunt salt so each run finds a DIFFERENT collision pair
            salt = hunt_id[:8]
            i = 0
            while state["status"] == "running" and i < MAX_EVALS:
                msg = f"{salt}:{i}".encode()
                h_int = int.from_bytes(crhf.hash(msg), 'big') & mask
                i += 1
                state["evaluations"] = i
                if h_int in seen and seen[h_int] != msg:
                    state["collision"] = {
                        "msg1": seen[h_int].decode(),
                        "msg2": msg.decode(),
                        "hash_16bit": f"{h_int:04x}",
                        "hash_decimal": h_int,
                    }
                    state["status"] = "found"
                    return
                seen[h_int] = msg
            if state["status"] == "running":
                state["status"] = "exhausted"
        except Exception as exc:
            state["status"] = "error"
            state["error"] = str(exc)

    t = threading.Thread(target=_hunt, args=(state,), daemon=True)
    t.start()
    return {"hunt_id": hunt_id, "birthday_bound": 256, "output_bits": 16}


@app.get("/api/pa8/collision/status/{hunt_id}")
def pa8_collision_status(hunt_id: str):
    """Poll the state of a running collision hunt."""
    state = _pa8_hunts.get(hunt_id)
    if state is None:
        raise HTTPException(404, "Hunt not found")
    return {
        "hunt_id": hunt_id,
        "status": state["status"],
        "evaluations": state["evaluations"],
        "birthday_bound": state["birthday_bound"],
        "output_bits": state["output_bits"],
        "progress_pct": min(100.0, state["evaluations"] / state["birthday_bound"] * 100),
        "collision": state["collision"],
    }


@app.post("/api/pa8/collision/stop/{hunt_id}")
def pa8_collision_stop(hunt_id: str):
    """Abort a running collision hunt."""
    state = _pa8_hunts.get(hunt_id)
    if state is None:
        raise HTTPException(404, "Hunt not found")
    if state["status"] == "running":
        state["status"] = "stopped"
    return {"status": state["status"]}


# ── Routing table ──
@app.get("/api/reductions")
def get_reductions():
    return {"reductions":{f"{a}→{b}": [{"step":l,"desc":d} for l,d in v] for (a,b),v in REDUCTIONS.items()},
            "proofs":PROOF_DB,
            "primitives":["OWF","PRG","PRF","PRP","MAC","CRHF","HMAC"]}

# ── Serve frontend ──
STATIC_DIR = os.path.join(os.path.dirname(__file__), '..', 'web')
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
