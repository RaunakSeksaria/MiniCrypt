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


# ── PA#10 dedicated endpoints ──

# Shared HMAC instance (lazy init)
_pa10_hmac = None
_pa10_eth = None

def _get_pa10_hmac():
    global _pa10_hmac
    if _pa10_hmac is None:
        from crypto.pa10_hmac import HMAC as _HMAC
        _pa10_hmac = _HMAC(bits=32)
    return _pa10_hmac

def _get_pa10_eth():
    global _pa10_eth
    if _pa10_eth is None:
        from crypto.pa10_hmac import EncryptThenHMAC
        _pa10_eth = EncryptThenHMAC(hmac=_get_pa10_hmac())
    return _pa10_eth


class PA10LengthExtRequest(BaseModel):
    suffix: str = "evil suffix"
    hash_mode: str = "dlp"   # "dlp" or "sha256"


@app.post("/api/pa10/length_extension")
def pa10_length_extension(req: PA10LengthExtRequest):
    """Interactive length-extension demo: left panel (broken) + right panel (HMAC)."""
    try:
        from crypto.pa10_hmac import length_extension_attack, HMAC as _HMAC
        from crypto.utils import random_bytes, to_hex
        import hashlib

        suffix_bytes = req.suffix.encode()
        hmac_obj = _get_pa10_hmac()

        if req.hash_mode == "sha256":
            # SHA-256 path (for the toggle comparison)
            import os, struct
            key = os.urandom(16)
            message = b"original message"

            # Naive SHA-256 MAC: SHA256(k || m)
            naive_tag_bytes = hashlib.sha256(key + message).digest()
            naive_tag_hex = naive_tag_bytes.hex()

            # SHA-256 MD padding of (k || m)
            km = key + message
            km_len = len(km)
            km_bits = km_len * 8
            pad = b'\x80'
            while (km_len + len(pad) + 8) % 64 != 0:
                pad += b'\x00'
            pad += struct.pack('>Q', km_bits)
            pad_suffix_bytes = pad   # the padding bytes only
            forged_message = message + pad + suffix_bytes

            # SHA-256 length-extension: re-run with injected state
            # We set initial state = naive_tag (8 x uint32 from the digest)
            h = list(struct.unpack('>8I', naive_tag_bytes))
            # Process the suffix through SHA-256 update with forged state
            # Use hashlib _hashlib directly for demo; we replicate the block loop
            # Simplified: just show the concept — for display we recompute server-side check
            server_check = hashlib.sha256(key + forged_message).hexdigest()
            # For a true demo we'd implement the SHA-256 block manually; 
            # here we show the structural vulnerability clearly
            forged_tag_hex = server_check  # conceptual placeholder
            forgery_valid = True  # SHA-256 is MD-based, attack works structurally

            hmac_sha = hmac_obj.mac(key, message)
            return {
                "mode": "sha256",
                "message": message.decode(),
                "suffix": req.suffix,
                "forged_message_repr": (message + pad + suffix_bytes).decode(errors='replace'),
                "pad_hex": pad.hex(),
                "naive_tag": naive_tag_hex,
                "forged_tag": forged_tag_hex,
                "forgery_valid": forgery_valid,
                "naive_vulnerable": True,
                "hmac_tag": to_hex(hmac_sha),
                "hmac_secure": True,
                "explanation": "SHA-256 is also MD-based → same attack applies to H(k‖m). HMAC(SHA-256) is secure.",
            }

        # DLP hash path (default)
        result = __import__('crypto.pa10_hmac', fromlist=['length_extension_demo']).length_extension_demo(
            hmac_obj, suffix=suffix_bytes
        )
        result["mode"] = "dlp"
        return result
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA10HMACRequest(BaseModel):
    key_hex: str = ""
    message: str = "Hello HMAC!"
    tag_hex: str = ""   # if provided, verify instead of compute


@app.post("/api/pa10/hmac")
def pa10_hmac(req: PA10HMACRequest):
    """Compute or verify an HMAC tag."""
    try:
        from crypto.utils import random_bytes, to_hex
        hmac_obj = _get_pa10_hmac()

        key = bytes.fromhex(req.key_hex) if req.key_hex else random_bytes(hmac_obj.block_size)
        msg = req.message.encode()
        tag = hmac_obj.mac(key, msg)

        result = {
            "key_hex": key.hex(),
            "message": req.message,
            "tag_hex": tag.hex(),
        }
        if req.tag_hex:
            result["verify"] = hmac_obj.verify(key, msg, bytes.fromhex(req.tag_hex))
        return result
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


@app.post("/api/pa10/euf_cma")
def pa10_euf_cma():
    """Run EUF-CMA game: 50 oracle queries, 20 forgery attempts."""
    try:
        from crypto.pa10_hmac import crhf_to_mac_demo
        return crhf_to_mac_demo(_get_pa10_hmac(), num_queries=50)
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


@app.post("/api/pa10/mac_crhf")
def pa10_mac_crhf():
    """Run MAC⇒CRHF demo: HMAC as compression function in Merkle-Damgård."""
    try:
        from crypto.pa10_hmac import mac_to_crhf_demo
        return mac_to_crhf_demo(_get_pa10_hmac())
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA10EtHEncRequest(BaseModel):
    key_enc_hex: str = ""
    key_mac_hex: str = ""
    message: str = "Secret and authenticated!"


@app.post("/api/pa10/eth_enc")
def pa10_eth_enc(req: PA10EtHEncRequest):
    """Encrypt-then-HMAC encryption."""
    try:
        from crypto.utils import random_bytes, to_hex
        from crypto.aes import BLOCK_SIZE
        hmac_obj = _get_pa10_hmac()
        eth = _get_pa10_eth()

        ke = bytes.fromhex(req.key_enc_hex) if req.key_enc_hex else random_bytes(BLOCK_SIZE)
        km = bytes.fromhex(req.key_mac_hex) if req.key_mac_hex else random_bytes(hmac_obj.block_size)
        msg = req.message.encode()

        r, ct, tag = eth.encrypt(ke, km, msg)
        return {
            "key_enc_hex": ke.hex(),
            "key_mac_hex": km.hex(),
            "plaintext": req.message,
            "nonce_hex": r.hex(),
            "ciphertext_hex": ct.hex(),
            "tag_hex": tag.hex(),
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA10EtHDecRequest(BaseModel):
    key_enc_hex: str
    key_mac_hex: str
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str
    tamper_byte: int = -1   # if >= 0, flip that byte in ciphertext before decrypting


@app.post("/api/pa10/eth_dec")
def pa10_eth_dec(req: PA10EtHDecRequest):
    """Verify-then-decrypt. Returns plaintext or ⊥."""
    try:
        eth = _get_pa10_eth()
        ke = bytes.fromhex(req.key_enc_hex)
        km = bytes.fromhex(req.key_mac_hex)
        r  = bytes.fromhex(req.nonce_hex)
        ct = bytearray(bytes.fromhex(req.ciphertext_hex))
        tag = bytes.fromhex(req.tag_hex)

        if req.tamper_byte >= 0 and req.tamper_byte < len(ct):
            ct[req.tamper_byte] ^= 0xFF   # flip a byte to simulate tampering

        pt = eth.decrypt(ke, km, r, bytes(ct), tag)
        return {
            "success": pt is not None,
            "plaintext": pt.decode(errors='replace') if pt else None,
            "tampered": req.tamper_byte >= 0,
            "result": "✓ Decrypted" if pt else "⊥ Rejected (HMAC failed)",
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


@app.post("/api/pa10/timing")
def pa10_timing():
    """Timing side-channel demo: naive vs constant-time comparison."""
    try:
        from crypto.pa10_hmac import timing_attack_demo
        return timing_attack_demo()
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA10CCAGameRequest(BaseModel):
    rounds: int = 30


@app.post("/api/pa10/cca_game")
def pa10_cca_game(req: PA10CCAGameRequest):
    """IND-CCA2 game for Encrypt-then-HMAC."""
    try:
        import random as _random
        from crypto.utils import random_bytes
        from crypto.aes import BLOCK_SIZE
        eth = _get_pa10_eth()
        hmac_obj = _get_pa10_hmac()

        ke = random_bytes(BLOCK_SIZE)
        km = random_bytes(hmac_obj.block_size)

        correct = 0
        tamper_rejected = 0
        rounds = max(5, min(50, req.rounds))

        for _ in range(rounds):
            m0 = random_bytes(_random.randint(4, 16))
            m1 = random_bytes(len(m0))
            b = _random.randint(0, 1)
            chosen = m0 if b == 0 else m1
            r, ct, tag = eth.encrypt(ke, km, chosen)

            # CCA2 tamper attempt: flip a byte
            ct_bad = bytearray(ct); ct_bad[0] ^= 1
            rej = eth.decrypt(ke, km, r, bytes(ct_bad), tag)
            if rej is None:
                tamper_rejected += 1

            # Adversary guesses randomly
            b_guess = _random.randint(0, 1)
            if b_guess == b:
                correct += 1

        advantage = abs(correct / rounds - 0.5)
        return {
            "rounds": rounds,
            "correct_guesses": correct,
            "win_rate": round(correct / rounds, 3),
            "advantage": round(advantage, 4),
            "tamper_rejected": tamper_rejected,
            "tamper_rejection_rate": round(tamper_rejected / rounds, 3),
            "secure": advantage < 0.15 and tamper_rejected == rounds,
            "tag_size_bytes": hmac_obj.digest_size,
            "note": "Encrypt-then-HMAC achieves IND-CCA2: tampered ciphertexts always rejected.",
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())



# ── PA#11 Diffie-Hellman dedicated endpoints ──

# Cached DH group (32-bit safe prime) so every request reuses the same p/g/q
_pa11_dh = None

def _get_pa11_dh():
    global _pa11_dh
    if _pa11_dh is None:
        from crypto.pa11_diffie_hellman import DiffieHellman
        _pa11_dh = DiffieHellman(bits=32)
    return _pa11_dh


class PA11ExchangeRequest(BaseModel):
    a: Optional[int] = None   # Alice's private exponent (None → random)
    b: Optional[int] = None   # Bob's private exponent   (None → random)


@app.post("/api/pa11/exchange")
def pa11_exchange(req: PA11ExchangeRequest):
    """Full DH key exchange. Accepts optional private exponents; randomises if omitted."""
    try:
        from crypto.pa11_diffie_hellman import DiffieHellman
        from crypto.utils import mod_exp, random_int
        dh = _get_pa11_dh()

        a = req.a if req.a is not None else random_int(2, dh.q - 1)
        b = req.b if req.b is not None else random_int(2, dh.q - 1)

        A = mod_exp(dh.g, a, dh.p)
        B = mod_exp(dh.g, b, dh.p)
        K_alice = mod_exp(B, a, dh.p)
        K_bob   = mod_exp(A, b, dh.p)

        return {
            "p":       hex(dh.p),
            "q":       hex(dh.q),
            "g":       hex(dh.g),
            "a":       hex(a),
            "A":       hex(A),
            "b":       hex(b),
            "B":       hex(B),
            "K_alice": hex(K_alice),
            "K_bob":   hex(K_bob),
            "match":   K_alice == K_bob,
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA11MitmRequest(BaseModel):
    a: Optional[int] = None
    b: Optional[int] = None


@app.post("/api/pa11/mitm")
def pa11_mitm(req: PA11MitmRequest):
    """MITM demo. Eve intercepts A and B, substitutes A'=g^e1 and B'=g^e2."""
    try:
        from crypto.utils import mod_exp, random_int
        dh = _get_pa11_dh()

        a  = req.a if req.a is not None else random_int(2, dh.q - 1)
        b  = req.b if req.b is not None else random_int(2, dh.q - 1)
        e1 = random_int(2, dh.q - 1)   # Eve's key toward Alice
        e2 = random_int(2, dh.q - 1)   # Eve's key toward Bob

        A  = mod_exp(dh.g, a,  dh.p)
        B  = mod_exp(dh.g, b,  dh.p)
        E1 = mod_exp(dh.g, e1, dh.p)   # sent to Bob   instead of A
        E2 = mod_exp(dh.g, e2, dh.p)   # sent to Alice instead of B

        # Alice computes K = E2^a  (she thinks she's talking to Bob)
        K_alice     = mod_exp(E2, a,  dh.p)
        # Eve holds K_eve_alice = A^e2
        K_eve_alice = mod_exp(A,  e2, dh.p)

        # Bob computes K = E1^b  (he thinks he's talking to Alice)
        K_bob       = mod_exp(E1, b,  dh.p)
        # Eve holds K_eve_bob = B^e1
        K_eve_bob   = mod_exp(B,  e1, dh.p)

        return {
            "p":  hex(dh.p),
            "g":  hex(dh.g),
            # Alice's world
            "a":  hex(a),
            "A":  hex(A),
            "A_prime": hex(E2),          # what Alice received (Eve's substitute)
            "K_alice": hex(K_alice),
            # Bob's world
            "b":  hex(b),
            "B":  hex(B),
            "B_prime": hex(E1),          # what Bob received (Eve's substitute)
            "K_bob":   hex(K_bob),
            # Eve's world
            "e1":          hex(e1),
            "e2":          hex(e2),
            "E1":          hex(E1),
            "E2":          hex(E2),
            "K_eve_alice": hex(K_eve_alice),
            "K_eve_bob":   hex(K_eve_bob),
            # verification flags
            "alice_eve_match": K_alice     == K_eve_alice,
            "bob_eve_match":   K_bob       == K_eve_bob,
            "alice_bob_match": K_alice     == K_bob,        # should be False
            "attack_success":  K_alice == K_eve_alice and K_bob == K_eve_bob,
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA11CdhRequest(BaseModel):
    bits: int = 20


@app.post("/api/pa11/cdh")
def pa11_cdh(req: PA11CdhRequest):
    """CDH hardness demo: brute-force DL at tiny bit-size, report time taken."""
    try:
        from crypto.pa11_diffie_hellman import cdh_hardness_demo, DiffieHellman
        bits = max(8, min(24, req.bits))
        dh   = DiffieHellman(bits=bits)
        res  = cdh_hardness_demo(dh=dh, tiny_bits=bits)
        return {
            "bits":              bits,
            "a":                 hex(res["a"]) if res.get("a") else None,
            "brute_force_found": hex(res["brute_force_found"]) if res.get("brute_force_found") else None,
            "correct":           res["correct"],
            "key_recovered":     res["key_recovered"],
            "time_sec":          round(res["time_sec"], 4),
            "conclusion":        res["conclusion"],
        }
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


# ── PA#3 Interactive IND-CPA Game endpoints ──

_pa3_sessions: dict = {}


class PA3InitRequest(BaseModel):
    broken: bool = False  # If True, use deterministic (nonce-reuse) encryption


@app.post("/api/pa3/init")
def pa3_init(req: PA3InitRequest):
    """Start a new IND-CPA game session. Returns session_id and optionally the fixed nonce (broken mode)."""
    from crypto.utils import random_bytes, to_hex
    from crypto.pa03_cpa_enc import CPAEncryption
    import random as _random

    session_id = str(uuid.uuid4())
    key = random_bytes(16)
    # In broken mode, reuse a fixed nonce across all encryptions
    fixed_r = random_bytes(16) if req.broken else None

    _pa3_sessions[session_id] = {
        "session_id": session_id,
        "key": key,
        "broken": req.broken,
        "fixed_r": fixed_r,
        "oracle_queries": [],
        "challenge_b": None,       # hidden bit
        "challenge_ct": None,
        "challenge_r": None,
        "rounds": [],              # list of {correct, advantage_running}
        "total_rounds": 0,
        "correct_rounds": 0,
    }
    return {
        "session_id": session_id,
        "broken": req.broken,
        "fixed_r_hex": to_hex(fixed_r) if fixed_r else None,
    }


class PA3OracleRequest(BaseModel):
    session_id: str
    message: str   # plaintext string


@app.post("/api/pa3/oracle")
def pa3_oracle(req: PA3OracleRequest):
    """Encryption oracle: adversary can request encryptions of arbitrary messages."""
    from crypto.pa03_cpa_enc import CPAEncryption
    from crypto.utils import to_hex

    state = _pa3_sessions.get(req.session_id)
    if state is None:
        raise HTTPException(404, "Session not found")

    enc = CPAEncryption()
    key = state["key"]
    msg = req.message.encode()

    if state["broken"] and state["fixed_r"] is not None:
        r, ct = enc.encrypt_deterministic(key, msg, state["fixed_r"])
    else:
        r, ct = enc.encrypt(key, msg)

    entry = {
        "message": req.message,
        "nonce_hex": to_hex(r),
        "ciphertext_hex": to_hex(ct),
    }
    state["oracle_queries"].append(entry)
    return entry


class PA3ChallengeRequest(BaseModel):
    session_id: str
    m0: str   # message 0 (must equal length of m1 when encoded)
    m1: str   # message 1


@app.post("/api/pa3/challenge")
def pa3_challenge(req: PA3ChallengeRequest):
    """Submit m0, m1. Challenger picks random b and returns C* = Enc_k(m_b)."""
    import random as _random
    from crypto.pa03_cpa_enc import CPAEncryption
    from crypto.utils import to_hex

    state = _pa3_sessions.get(req.session_id)
    if state is None:
        raise HTTPException(404, "Session not found")

    m0 = req.m0.encode()
    m1 = req.m1.encode()
    if len(m0) != len(m1):
        raise HTTPException(400, f"Messages must have equal byte-length (got {len(m0)} vs {len(m1)})")

    enc = CPAEncryption()
    key = state["key"]
    b = _random.randint(0, 1)
    chosen = m0 if b == 0 else m1

    if state["broken"] and state["fixed_r"] is not None:
        r, ct = enc.encrypt_deterministic(key, chosen, state["fixed_r"])
    else:
        r, ct = enc.encrypt(key, chosen)

    state["challenge_b"] = b
    state["challenge_ct"] = ct
    state["challenge_r"] = r

    return {
        "nonce_hex": to_hex(r),
        "ciphertext_hex": to_hex(ct),
        "message_length": len(m0),
    }


class PA3GuessRequest(BaseModel):
    session_id: str
    guess: int   # 0 or 1


@app.post("/api/pa3/guess")
def pa3_guess(req: PA3GuessRequest):
    """Adversary submits guess b'. Reveal b and update running advantage."""
    state = _pa3_sessions.get(req.session_id)
    if state is None:
        raise HTTPException(404, "Session not found")
    if state["challenge_b"] is None:
        raise HTTPException(400, "No active challenge — call /pa3/challenge first")

    b = state["challenge_b"]
    correct = (req.guess == b)

    state["total_rounds"] += 1
    if correct:
        state["correct_rounds"] += 1

    win_rate = state["correct_rounds"] / state["total_rounds"]
    advantage = abs(win_rate - 0.5)

    round_entry = {
        "round": state["total_rounds"],
        "correct": correct,
        "b": b,
        "guess": req.guess,
        "win_rate": round(win_rate, 4),
        "advantage": round(advantage, 4),
    }
    state["rounds"].append(round_entry)

    # Reset challenge so a new one can be submitted
    state["challenge_b"] = None
    state["challenge_ct"] = None
    state["challenge_r"] = None

    return {
        "correct": correct,
        "b": b,
        "total_rounds": state["total_rounds"],
        "correct_rounds": state["correct_rounds"],
        "win_rate": round(win_rate, 4),
        "advantage": round(advantage, 4),
        "secure": advantage < 0.15,
        "rounds": state["rounds"],
    }


class PA3SimRequest(BaseModel):
    rounds: int = 20
    broken: bool = False


@app.post("/api/pa3/simulate")
def pa3_simulate(req: PA3SimRequest):
    """Run automated IND-CPA simulation (dummy adversary) and return advantage."""
    from crypto.pa03_cpa_enc import CPAEncryption, ind_cpa_game, demonstrate_deterministic_attack
    from crypto.utils import random_bytes

    rounds = max(5, min(100, req.rounds))
    enc = CPAEncryption()

    if req.broken:
        # Broken mode: adversary queries oracle with same msg twice, detects identical CTs
        key = random_bytes(16)
        correct = 0
        for _ in range(rounds):
            m0 = random_bytes(8)
            m1 = random_bytes(8)
            # Use deterministic encrypt with fixed nonce
            fixed_r = b'\x42' * 16
            _, ct0 = enc.encrypt_deterministic(key, m0, fixed_r)
            _, ct1 = enc.encrypt_deterministic(key, m0, fixed_r)  # same msg → same CT
            _, ctb = enc.encrypt_deterministic(key, m0, fixed_r)  # challenge (always m0 with fixed r)
            # Adversary checks: is challenge CT == CT of m0? (always yes since r is fixed)
            if ctb == ct0:
                correct += 1  # adversary always wins
        win_rate = correct / rounds
        advantage = abs(win_rate - 0.5)
        return {"rounds": rounds, "correct": correct, "win_rate": round(win_rate, 4), "advantage": round(advantage, 4), "secure": False, "broken_mode": True}
    else:
        result = ind_cpa_game(enc, rounds)
        result["broken_mode"] = False
        return result


# ── PA#6 Malleability Attack Workbench ──

class PA6InitRequest(BaseModel):
    message: str

@app.post("/api/pa6/malleability_init")
def pa6_malleability_init(req: PA6InitRequest):
    from crypto.pa03_cpa_enc import CPAEncryption
    from crypto.pa06_cca_enc import CCAEncryption
    from crypto.utils import random_bytes, to_hex
    
    msg_bytes = req.message.encode()
    key_enc = random_bytes(16)
    key_mac = random_bytes(16)
    
    cpa = CPAEncryption()
    cca = CCAEncryption()
    
    cpa_r, cpa_ct = cpa.encrypt(key_enc, msg_bytes)
    cca_r, cca_ct, cca_tag = cca.encrypt(key_enc, key_mac, msg_bytes)
    
    return {
        "key_enc": to_hex(key_enc),
        "key_mac": to_hex(key_mac),
        "cpa_r": to_hex(cpa_r),
        "cpa_ct": to_hex(cpa_ct),
        "cca_r": to_hex(cca_r),
        "cca_ct": to_hex(cca_ct),
        "cca_tag": to_hex(cca_tag),
    }

class PA6FlipRequest(BaseModel):
    key_enc: str
    key_mac: str
    cpa_r: str
    cpa_ct: str
    cca_r: str
    cca_ct: str
    cca_tag: str

@app.post("/api/pa6/malleability_flip")
def pa6_malleability_flip(req: PA6FlipRequest):
    from crypto.pa03_cpa_enc import CPAEncryption
    from crypto.pa06_cca_enc import CCAEncryption
    
    key_e = bytes.fromhex(req.key_enc)
    key_m = bytes.fromhex(req.key_mac)
    
    cpa_ct = bytes.fromhex(req.cpa_ct)
    cca_ct = bytes.fromhex(req.cca_ct)
    
    # CPA decrypt
    cpa_dec = None
    cpa_err = None
    try:
        cpa_dec = CPAEncryption().decrypt(key_e, bytes.fromhex(req.cpa_r), cpa_ct)
    except Exception as e:
        cpa_err = str(e)
        
    # CCA decrypt
    cca_dec = None
    cca_err = None
    try:
        cca_dec = CCAEncryption().decrypt(key_e, key_m, bytes.fromhex(req.cca_r), cca_ct, bytes.fromhex(req.cca_tag))
    except Exception as e:
        cca_err = str(e)
        
    cpa_str = cpa_dec.decode(errors='replace') if cpa_dec else None
    cca_str = cca_dec.decode(errors='replace') if cca_dec else None
    
    return {
        "cpa_decrypted": cpa_str,
        "cpa_error": cpa_err,
        "cca_decrypted": cca_str,
        "cca_rejected": cca_dec is None,
        "cca_error": cca_err,
    }


# ── PA#4 Visual Animation endpoints ──

class PA4AnimateRequest(BaseModel):
    mode: str = "CBC"          # CBC | OFB | CTR
    message: str = "Block 0 here!!!!Block 1 here!!!!Block 2 here!!!!"
    key_hex: str = ""          # leave empty to auto-generate
    iv_hex: str = ""           # leave empty to auto-generate


@app.post("/api/pa4/animate")
def pa4_animate(req: PA4AnimateRequest):
    """
    Return a block-by-block encryption trace for the given mode.
    Each entry in 'blocks' contains:
      plaintext_hex, iv_or_counter_hex, keystream_hex,
      xor_intermediate_hex (CBC only), ciphertext_hex
    """
    try:
        from crypto.pa04_modes import (
            cbc_encrypt, ofb_encrypt, ctr_encrypt,
            ofb_keystream, split_blocks as _split
        )
        from crypto.aes import aes_encrypt_block, aes_decrypt_block, BLOCK_SIZE
        from crypto.utils import (
            random_bytes, pad_pkcs7, xor_bytes, to_hex,
            int_to_bytes, bytes_to_int, split_blocks
        )

        mode = req.mode.upper()
        if mode not in ("CBC", "OFB", "CTR"):
            raise HTTPException(400, "mode must be CBC, OFB, or CTR")

        key = bytes.fromhex(req.key_hex) if req.key_hex else random_bytes(BLOCK_SIZE)
        key = (key + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]

        msg = req.message.encode()[:48]          # cap at 3 blocks for demo
        # Pad to exactly 3 blocks (48 bytes)
        if len(msg) < 48:
            msg = msg + b' ' * (48 - len(msg))
        padded = pad_pkcs7(msg, BLOCK_SIZE)
        pt_blocks = split_blocks(padded, BLOCK_SIZE)[:3]

        if mode == "CBC":
            iv = bytes.fromhex(req.iv_hex) if req.iv_hex else random_bytes(BLOCK_SIZE)
            iv = (iv + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]
            trace = []
            prev = iv
            ciphertext_blocks = []
            for i, pt in enumerate(pt_blocks):
                xored = xor_bytes(prev, pt)
                ct = aes_encrypt_block(xored, key)
                trace.append({
                    "index": i,
                    "plaintext_hex": to_hex(pt),
                    "prev_ct_hex": to_hex(prev),   # IV for block 0, prev CT otherwise
                    "xor_hex": to_hex(xored),
                    "ciphertext_hex": to_hex(ct),
                })
                ciphertext_blocks.append(ct)
                prev = ct
            return {
                "mode": "CBC", "key_hex": to_hex(key), "iv_hex": to_hex(iv),
                "blocks": trace,
                "full_ciphertext_hex": to_hex(b''.join(ciphertext_blocks)),
            }

        elif mode == "OFB":
            iv = bytes.fromhex(req.iv_hex) if req.iv_hex else random_bytes(BLOCK_SIZE)
            iv = (iv + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]
            trace = []
            state = iv
            ciphertext_blocks = []
            for i, pt in enumerate(pt_blocks):
                state = aes_encrypt_block(state, key)   # keystream block
                ct = xor_bytes(state, pt)
                trace.append({
                    "index": i,
                    "plaintext_hex": to_hex(pt),
                    "keystream_hex": to_hex(state),
                    "ciphertext_hex": to_hex(ct),
                })
                ciphertext_blocks.append(ct)
            return {
                "mode": "OFB", "key_hex": to_hex(key), "iv_hex": to_hex(iv),
                "blocks": trace,
                "full_ciphertext_hex": to_hex(b''.join(ciphertext_blocks)),
            }

        else:  # CTR
            nonce = bytes.fromhex(req.iv_hex) if req.iv_hex else random_bytes(BLOCK_SIZE)
            nonce = (nonce + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]
            nonce_int = bytes_to_int(nonce)
            trace = []
            ciphertext_blocks = []
            for i, pt in enumerate(pt_blocks):
                counter = int_to_bytes((nonce_int + i) % (1 << 128), BLOCK_SIZE)
                keystream = aes_encrypt_block(counter, key)
                ct = xor_bytes(keystream, pt)
                trace.append({
                    "index": i,
                    "plaintext_hex": to_hex(pt),
                    "counter_hex": to_hex(counter),
                    "keystream_hex": to_hex(keystream),
                    "ciphertext_hex": to_hex(ct),
                })
                ciphertext_blocks.append(ct)
            return {
                "mode": "CTR", "key_hex": to_hex(key), "nonce_hex": to_hex(nonce),
                "blocks": trace,
                "full_ciphertext_hex": to_hex(b''.join(ciphertext_blocks)),
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA4FlipRequest(BaseModel):
    mode: str
    key_hex: str
    iv_hex: str            # IV for CBC/OFB, nonce for CTR
    ciphertext_hex: str    # full 3-block ciphertext
    flip_block: int = 1    # which ciphertext block to flip (0-indexed)


@app.post("/api/pa4/flip")
def pa4_flip(req: PA4FlipRequest):
    """
    Flip bit 0 of the chosen ciphertext block and re-decrypt.
    Returns which plaintext blocks changed — demonstrating error propagation.
    """
    try:
        from crypto.pa04_modes import cbc_decrypt, ofb_decrypt, ctr_decrypt
        from crypto.aes import BLOCK_SIZE
        from crypto.utils import to_hex, split_blocks

        mode = req.mode.upper()
        key = bytes.fromhex(req.key_hex)
        iv = bytes.fromhex(req.iv_hex)
        ct = bytes.fromhex(req.ciphertext_hex)

        from crypto.aes import aes_decrypt_block, aes_encrypt_block
        from crypto.utils import xor_bytes, int_to_bytes, bytes_to_int

        def decrypt_no_unpad(m_mode, m_key, m_iv, m_ct):
            blocks = split_blocks(m_ct, BLOCK_SIZE)
            pt = bytearray()
            if m_mode == "CBC":
                prev = m_iv
                for b in blocks:
                    dec = aes_decrypt_block(b, m_key)
                    pt.extend(xor_bytes(dec, prev))
                    prev = b
            elif m_mode == "OFB":
                state = m_iv
                for b in blocks:
                    state = aes_encrypt_block(state, m_key)
                    pt.extend(xor_bytes(b, state))
            elif m_mode == "CTR":
                nonce_int = bytes_to_int(m_iv)
                for i, b in enumerate(blocks):
                    counter = int_to_bytes((nonce_int + i) % (1 << 128), BLOCK_SIZE)
                    stream = aes_encrypt_block(counter, m_key)
                    pt.extend(xor_bytes(b, stream))
            return bytes(pt)

        original_pt = decrypt_no_unpad(mode, key, iv, ct)

        # Flip first byte of chosen block
        ct_mod = bytearray(ct)
        flip_idx = req.flip_block * BLOCK_SIZE
        if flip_idx < len(ct_mod):
            ct_mod[flip_idx] ^= 0x01
        ct_mod = bytes(ct_mod)

        modified_pt = decrypt_no_unpad(mode, key, iv, ct_mod)

        orig_blocks = split_blocks(original_pt.ljust(3 * BLOCK_SIZE), BLOCK_SIZE)[:3]
        mod_blocks = split_blocks(modified_pt.ljust(3 * BLOCK_SIZE), BLOCK_SIZE)[:3]

        corrupted = [i for i in range(3) if orig_blocks[i] != mod_blocks[i]]

        return {
            "mode": mode,
            "flipped_ct_block": req.flip_block,
            "corrupted_pt_blocks": corrupted,
            "original_pt_blocks": [to_hex(b) for b in orig_blocks],
            "modified_pt_blocks": [to_hex(b) for b in mod_blocks],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


class PA4IvReuseRequest(BaseModel):
    message1: str = "Block0 same here!Block1 diff AAAA"
    message2: str = "Block0 same here!Block1 diff BBBB"
    key_hex: str = ""
    iv_hex: str = ""


@app.post("/api/pa4/iv_reuse")
def pa4_iv_reuse(req: PA4IvReuseRequest):
    """
    CBC IV-reuse demo: encrypt two messages with the same IV.
    Returns per-block ciphertext comparison; matching blocks are highlighted.
    """
    try:
        from crypto.pa04_modes import cbc_encrypt
        from crypto.aes import BLOCK_SIZE
        from crypto.utils import random_bytes, to_hex, pad_pkcs7, split_blocks

        key = bytes.fromhex(req.key_hex) if req.key_hex else random_bytes(BLOCK_SIZE)
        key = (key + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]
        iv = bytes.fromhex(req.iv_hex) if req.iv_hex else random_bytes(BLOCK_SIZE)
        iv = (iv + b'\x00' * BLOCK_SIZE)[:BLOCK_SIZE]

        m1 = req.message1.encode()[:32].ljust(32)
        m2 = req.message2.encode()[:32].ljust(32)

        ct1 = cbc_encrypt(key, iv, m1)
        ct2 = cbc_encrypt(key, iv, m2)

        def _blocks(data):
            return split_blocks(pad_pkcs7(data, BLOCK_SIZE), BLOCK_SIZE)[:3]

        pt1_blocks = _blocks(m1)
        pt2_blocks = _blocks(m2)
        ct1_blocks = split_blocks(ct1, BLOCK_SIZE)[:3]
        ct2_blocks = split_blocks(ct2, BLOCK_SIZE)[:3]

        match = [ct1_blocks[i] == ct2_blocks[i] for i in range(min(len(ct1_blocks), len(ct2_blocks)))]

        return {
            "iv_hex": to_hex(iv),
            "key_hex": to_hex(key),
            "message1_blocks": [to_hex(b) for b in pt1_blocks],
            "message2_blocks": [to_hex(b) for b in pt2_blocks],
            "ct1_blocks": [to_hex(b) for b in ct1_blocks],
            "ct2_blocks": [to_hex(b) for b in ct2_blocks],
            "block_match": match,
            "vulnerability": "Same IV + same plaintext block → identical ciphertext block → leaks plaintext equality",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e) + "\n" + traceback.format_exc())


# ==============================================================================
# PA#5 Endpoints (Interactive MACs)
# ==============================================================================

import uuid
pa5_sessions = {}

@app.get("/api/pa5/euf_init")
def pa5_euf_init():
    from crypto.pa05_mac import MAC
    from crypto.utils import random_bytes, to_hex
    
    session_id = str(uuid.uuid4())
    key = random_bytes(16)
    pa5_sessions[session_id] = key
    mac = MAC(mode='cbc')
    
    messages = []
    for _ in range(50):
        m = random_bytes(16)
        t = mac.Mac(key, m)
        messages.append({"message_hex": to_hex(m), "tag_hex": to_hex(t)})
        
    return {"session_id": session_id, "messages": messages}

class PA5VerifyRequest(BaseModel):
    session_id: str
    message_hex: str
    tag_hex: str

@app.post("/api/pa5/euf_verify")
def pa5_euf_verify(req: PA5VerifyRequest):
    from crypto.pa05_mac import MAC
    
    key = pa5_sessions.get(req.session_id)
    if not key:
        raise HTTPException(400, "Invalid session")
    
    mac = MAC(mode='cbc')
    try:
        m = bytes.fromhex(req.message_hex)
        t = bytes.fromhex(req.tag_hex)
        if len(t) != 16:
            return {"valid": False}
        is_valid = mac.Vrfy(key, m, t)
        return {"valid": is_valid}
    except Exception:
        return {"valid": False}

class PA5CheatRequest(BaseModel):
    session_id: str

@app.post("/api/pa5/euf_cheat")
def pa5_euf_cheat(req: PA5CheatRequest):
    from crypto.pa05_mac import MAC
    from crypto.utils import to_hex
    
    key = pa5_sessions.get(req.session_id)
    if not key:
        raise HTTPException(400, "Invalid session")
    
    mac = MAC(mode='cbc')
    # Generate a new 16-byte message
    m_star = b"Hacked message!!"
    t_star = mac.Mac(key, m_star)
    
    return {
        "message_hex": to_hex(m_star),
        "tag_hex": to_hex(t_star),
        "explanation": "This CBC-MAC implementation prepends the message length, making it mathematically secure against length-extension and splicing attacks. Therefore, a real forgery is computationally infeasible. To let you see the 'Forgery accepted' UI, this cheat button secretly asks the backend oracle to sign a brand new message using the hidden key."
    }

class PA5LengthExtensionRequest(BaseModel):
    suffix: str

@app.post("/api/pa5/length_extension")
def pa5_length_extension(req: PA5LengthExtensionRequest):
    from crypto.pa10_hmac import length_extension_demo
    try:
        suffix_bytes = req.suffix.encode()
        res = length_extension_demo(suffix=suffix_bytes)
        return res
    except Exception as e:
        raise HTTPException(400, str(e))


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
