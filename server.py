import socket
import pickle
import random
import time
import threading
import functools
from hashlib import sha256
from sympy import primitive_root
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Global structures for active and blocked IDs.
active_ids = set()            # IDs of currently connected patients.
blocked_ids = {}              # {patient_id: block_timestamp}

# -------------------- Performance Measurement --------------------
perf_metrics = {
    "KeyPair": {"total_time": 0, "count": 0},
    "SignGen": {"total_time": 0, "count": 0},
    "SignVer": {"total_time": 0, "count": 0},
    "Hash": {"total_time": 0, "count": 0}
}

def measure_time(metric_name):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            perf_metrics[metric_name]["total_time"] += elapsed
            perf_metrics[metric_name]["count"] += 1
            return result
        return wrapper
    return decorator

def print_performance_table():
    print("\nPerformance Analysis (Average execution time in milliseconds):")
    print("-" * 60)
    print(f"{'Primitive':<30}{'Avg Time (ms)':>15}{'Calls':>10}")
    print("-" * 60)
    for key, data in perf_metrics.items():
        avg = (data["total_time"] / data["count"] * 1000) if data["count"] > 0 else 0
        print(f"{key:<30}{avg:>15.4f}{data['count']:>10}")
    print("-" * 60)

def generate_large_prime():
    while True:
        prime = random.randint(2**10, 2**12)
        if all(prime % i != 0 for i in range(2, int(prime**0.5) + 1)):
            return prime

@measure_time("KeyPair")
def generate_key_pair(prime, g):
    private_key = random.randint(1, prime - 1)
    public_key = pow(g, private_key, prime)
    return private_key, public_key

@measure_time("Hash")
def compute_hash(message):
    return sha256(message.encode('utf-8')).hexdigest()

@measure_time("SignGen")
def elgamal_sign(message, private_key, prime, generator):
    while True:
        k = random.randint(1, prime - 2)
        if gcd(k, prime - 1) == 1:
            break
    r = pow(generator, k, prime)
    hash_hex = compute_hash(message)
    hash_val = int(hash_hex, 16)
    s = (hash_val - private_key * r) * pow(k, -1, prime - 1) % (prime - 1)
    return (r, s)

@measure_time("SignVer")
def elgamal_verify(message, signature, public_key, prime, generator):
    r, s = signature
    if not (1 <= r < prime and 1 <= s < prime - 1):
        return False
    hash_hex = compute_hash(message)
    hash_val = int(hash_hex, 16)
    left = (pow(public_key, r, prime) * pow(r, s, prime)) % prime
    right = pow(generator, hash_val, prime)
    return left == right

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

class DoctorServer:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)  # Up to 5 simultaneous connections

        # Per-client information stored as a dictionary:
        # { patient_id: {"conn": connection, "prime": p, "g": g,
        #                "doctor_private": d, "doctor_public": D, "session_key": s} }
        self.client_info = {}
        self.id_gwn = "GWN_Doctor_1"
        self.rn_doctor = random.randint(1000, 9999)
        self.delta_ts = 5  # seconds
        self.long_term_key = random.randint(100000, 999999)

    def block_patient(self, patient_id):
        blocked_ids[patient_id] = time.time()
        if patient_id in active_ids:
            active_ids.remove(patient_id)
        print(f"[INFO] Patient {patient_id} is now blocked.")

    def compute_group_key(self):
        keys = []
        for pid in sorted(self.client_info.keys()):
            sk = self.client_info[pid].get("session_key")
            if sk is not None:
                keys.append(str(sk))
        concatenated = "".join(keys) + str(self.docPrivateKey)
        GK = compute_hash(concatenated)
        return GK

    def send_group_key(self):
        GK = self.compute_group_key()
        for patient_id, info in self.client_info.items():
            if patient_id in blocked_ids:
                continue
            try:
                conn = info["conn"]
                p_conn = info["prime"]
                session_key = info.get("session_key")
                if session_key is None:
                    continue
                sk_effective = session_key
                #sk_effective = session_key
                #key_bytes = sk_effective.to_bytes(16, byteorder='big', signed=False)
                key_bytes = bytes.fromhex(sk_effective)
                iv = get_random_bytes(AES.block_size)
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                encrypted_GK = iv + cipher.encrypt(pad(GK.encode('utf-8'), AES.block_size))
                msg = {"opcode": 30, "encrypted_group_key": encrypted_GK}
                conn.send(pickle.dumps(msg))
                print(f"[Opcode 30] Sent encrypted group key to patient {patient_id}.")
            except Exception as e:
                print(f"[Opcode 30] Failed to send group key to patient {patient_id}: {e}")
        return GK

    def broadcast_message(self, message):
        if not self.client_info:
            print("No authenticated patients to broadcast to.")
            return

        # Step 1: Send new group key
        GK = self.compute_group_key()
        for patient_id, info in self.client_info.items():
            if patient_id in blocked_ids:
                continue
            try:
                conn = info["conn"]
                p_conn = info["prime"]
                session_key = info.get("session_key")
                if session_key is None:
                    continue
                sk_effective = session_key
                print(sk_effective)
                #key_bytes = sk_effective.to_bytes(16, byteorder='big', signed=False)
                key_bytes = bytes.fromhex(sk_effective)

                iv_gk = get_random_bytes(AES.block_size)
                cipher_gk = AES.new(key_bytes, AES.MODE_CBC, iv_gk)
                encrypted_GK = iv_gk + cipher_gk.encrypt(pad(GK.encode('utf-8'), AES.block_size))
                msg_group = {"opcode": 30, "encrypted_group_key": encrypted_GK}
                conn.send(pickle.dumps(msg_group))
                print(f"[Opcode 30] Sent encrypted group key to patient {patient_id}.")
            except Exception as e:
                print(f"[Opcode 30] Failed to send group key to patient {patient_id}: {e}")

        # Step 2: Broadcast the actual message using GK in AES-CBC
        key_for_group = GK[:32]  # first 32 hex characters = 16 bytes
        group_key_bytes = bytes.fromhex(key_for_group)
        iv_msg = get_random_bytes(AES.block_size)
        cipher_group = AES.new(group_key_bytes, AES.MODE_CBC, iv_msg)
        encrypted_message = iv_msg + cipher_group.encrypt(pad(message.encode('utf-8'), AES.block_size))
        for patient_id, info in self.client_info.items():
            if patient_id in blocked_ids:
                continue
            try:
                conn = info["conn"]
                msg_broadcast = {"opcode": 40, "encrypted_message": encrypted_message}
                conn.send(pickle.dumps(msg_broadcast))
                print(f"[Opcode 40] Broadcast message sent to patient {patient_id}.")
            except Exception as e:
                print(f"[Opcode 40] Failed to send broadcast to patient {patient_id}: {e}")

    def shutdown(self):
        print("[Opcode 60] Shutting down server and disconnecting all clients.")
        for info in self.client_info.values():
            try:
                info["conn"].close()
            except Exception:
                pass
        self.server.close()

    def doctor_input_thread(self):
        while True:
            try:
                message = input("\nEnter message to broadcast (or 'Block Patient_ID' to block, 'exit' to stop): ")
                if message.lower() == "exit":
                    print("Exiting broadcast input thread.")
                    break

                if message.startswith("Block"):
                    _, patient_id = message.split(maxsplit=1)
                    self.block_patient(patient_id)
                    if patient_id in self.client_info:
                        try:
                            conn = self.client_info[patient_id]["conn"]
                            conn.send(pickle.dumps({"opcode": 80, "message": "You are blocked by the server."}))
                            conn.close()
                            del self.client_info[patient_id]
                            print(f"Patient {patient_id} has been disconnected.")
                        except:
                            pass
                else:
                    self.broadcast_message(message)
                    print_performance_table()

            except KeyboardInterrupt:
                print("\n[Opcode 60] Ctrl+C pressed. Server disconnecting.")
                self.shutdown()
                break

    def start(self):
        print("Doctor (Server) is listening for patient requests...")
        threading.Thread(target=self.doctor_input_thread, daemon=True).start()
        try:
            while True:
                conn, addr = self.server.accept()
                print(f"Connected by {addr}")
                threading.Thread(target=self.handle_client, args=(conn,)).start()
        except KeyboardInterrupt:
            print("\n[Opcode 60] Ctrl+C pressed. Server disconnecting.")
            self.shutdown()

    def handle_client(self, conn):
        patient_id = None
        authenticated = False
        try:
            # Step 1: Public Key Exchange (Opcode 5)
            data = conn.recv(4096)
            if not data:
                conn.close()
                return
            initial_msg = pickle.loads(data)
            if "opcode" in initial_msg and initial_msg["opcode"] == 5:
                patient_id = initial_msg["id_patient"]
                current_time = time.time()

                if patient_id in active_ids:
                    msg = {"opcode": 70, "message": "Already Active Connection Exists."}
                    conn.send(pickle.dumps(msg))
                    print(f"[Opcode 70] Patient {patient_id} already active. Disconnecting connection.")
                    conn.close()
                    return

                if patient_id in blocked_ids:
                    block_time = blocked_ids[patient_id]
                    if current_time - block_time < 120:
                        msg = {"opcode": 80, "message": "Authentication failed earlier. You are blocked. Please try after 2 minutes."}
                        conn.send(pickle.dumps(msg))
                        print(f"[Opcode 80] Patient {patient_id} is blocked. Disconnecting connection.")
                        conn.close()
                        return
                    else:
                        del blocked_ids[patient_id]
                        print(f"[INFO] Block expired for patient {patient_id}. Allowing new connection.")

                active_ids.add(patient_id)
                public_key_patient = initial_msg["public_key_patient"]  # (p, g, y)
                p_client, g_client, _ = public_key_patient

                d, D = generate_key_pair(p_client, g_client)
                self.docPrivateKey=d
                self.client_info[patient_id] = {
                    "conn": conn,
                    "prime": p_client,
                    "g": g_client,
                    "doctor_private": d,
                    "doctor_public": D
                }

                response_pk = {"opcode": 5, "public_key_doctor": (p_client, g_client, D)}
                conn.send(pickle.dumps(response_pk))
                print(f"[INFO] Domain parameters accepted and doctor's key pair generated for patient {patient_id}")
            else:
                print("[ERROR] Expected public key request (opcode 5) but did not receive it. Disconnecting.")
                conn.close()
                return

            # Step 2: Receive Authentication Request (Opcode 10)
            data = conn.recv(4096)
            if not data:
                conn.close()
                return
            auth_request = pickle.loads(data)
            ts_patient = auth_request['ts_patient']
            rn_patient = auth_request['rn_patient']
            c1 = auth_request['c1']
            c2 = auth_request['c2']
            patient_id = auth_request['id_patient']
            sign_data1 = auth_request['sign_data1']
            _, _, y_client = auth_request['public_key_patient']

            info = self.client_info.get(patient_id)
            if info is None:
                print(f"[ERROR] No stored info for patient {patient_id}. Disconnecting.")
                conn.close()
                return
            p_conn = info["prime"]
            g_conn = info["g"]
            d = info["doctor_private"]

            if abs(time.time() - ts_patient) > self.delta_ts:
                print(f"[ERROR] Timestamp validation failed for patient {patient_id}. Disconnecting.")
                self.block_patient(patient_id)
                conn.send(pickle.dumps({"opcode": 80, "message": "Timestamp validation failed. Authentication blocked."}))
                conn.close()
                return

            msg_to_verify = f"{ts_patient}{rn_patient}{self.id_gwn}{c1}{c2}"
            if not elgamal_verify(msg_to_verify, sign_data1, y_client, p_conn, g_conn):
                print(f"[ERROR] Signature validation failed for patient {patient_id}. Disconnecting.")
                self.block_patient(patient_id)
                conn.send(pickle.dumps({"opcode": 80, "message": "Authentication failed (signature mismatch). You are blocked."}))
                conn.close()
                return

            print(f"[Opcode 10: KEY VERIFICATION] Signature validation successful for patient {patient_id}.")
            s = pow(c1, d, p_conn)
            s_inv = pow(s, -1, p_conn)
            session_key = (c2 * s_inv) % p_conn
            print(f"[Opcode 20: SESSION TOKEN] Decrypted session key for patient {patient_id}: {session_key}")
            info["session_key"] = session_key

            # Step 3: Respond with Re-encrypted Session Key
            r_val = random.randint(1, p_conn - 1)
            c1_reencrypted = pow(g_conn, r_val, p_conn)
            c2_reencrypted = (session_key * pow(y_client, r_val, p_conn)) % p_conn
            ts_doctor = int(time.time())
            response_msg = f"{ts_doctor}{self.rn_doctor}{patient_id}{c1_reencrypted}{c2_reencrypted}"
            sign_data2 = elgamal_sign(response_msg, d, p_conn, g_conn)
            response = {
                "ts_doctor": ts_doctor,
                "rn_doctor": self.rn_doctor,
                "c1_reencrypted": c1_reencrypted,
                "c2_reencrypted": c2_reencrypted,
                "sign_data2": sign_data2,
                "public_key_doctor": (p_conn, g_conn, info["doctor_public"]),
                "opcode": 20
            }
            conn.send(pickle.dumps(response))

            # Step 4: Receive Final Session Key Verifier
            data = conn.recv(4096)
            if not data:
                conn.close()
                return
            final_validation = pickle.loads(data)
            skv_patient = final_validation['skv_patient']
            ts_patient_final = final_validation['ts_patient_final']

            if abs(time.time() - ts_patient_final) > self.delta_ts:
                print(f"[ERROR] Final timestamp validation failed for patient {patient_id}. Disconnecting.")
                self.block_patient(patient_id)
                conn.send(pickle.dumps({"opcode": 80, "message": "Final timestamp validation failed. Authentication blocked."}))
                conn.close()
                return

            computed_sk_input = f"{session_key}{ts_patient}{ts_doctor}{rn_patient}{self.rn_doctor}{patient_id}{self.id_gwn}"
            computed_sk = compute_hash(computed_sk_input)
            print(f"Server SKV for patient {patient_id}: {computed_sk}")

            computed_skv_input = f"{computed_sk}{ts_patient_final}"
            computed_skv = compute_hash(computed_skv_input)

            if computed_skv == skv_patient:
                print(f"[Opcode 20: SESSION TOKEN] Session key validation successful for patient {patient_id}. Secure communication established.")
                authenticated = True
                info["session_key"] = computed_sk
                #self.client_info["session_key"]=computed_sk
                print_performance_table()
            else:
                print(f"[ERROR] Session key validation failed for patient {patient_id}. Disconnecting.")
                self.block_patient(patient_id)
                conn.send(pickle.dumps({"opcode": 80, "message": "Session key validation failed. Authentication blocked."}))
        except Exception as e:
            print(f"[ERROR] An exception occurred with patient {patient_id}: {e}")
            if patient_id:
                self.block_patient(patient_id)
        finally:
            if not authenticated:
                if patient_id in active_ids:
                    active_ids.remove(patient_id)
                if patient_id in self.client_info:
                    del self.client_info[patient_id]
                conn.close()
                return

        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                msg = pickle.loads(data)
                if "opcode" in msg and msg["opcode"] == 90:
                    print(f"[Opcode 90] Received exit message from patient {patient_id}. Removing connection.")
                    break
        except Exception as e:
            print(f"[ERROR] Exception while listening for messages from patient {patient_id}: {e}")
        finally:
            if patient_id in active_ids:
                active_ids.remove(patient_id)
            if patient_id in self.client_info:
                del self.client_info[patient_id]
            conn.close()
            print(f"Connection with patient {patient_id} closed.")

if __name__ == "__main__":
    server = DoctorServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[Opcode 60] Ctrl+C pressed. Server disconnecting.")
        server.shutdown()
