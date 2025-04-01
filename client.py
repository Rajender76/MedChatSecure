import socket
import pickle
import random
import time
import functools
from hashlib import sha256
from math import gcd
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from sympy import primitive_root

def generate_large_prime():
    while True:
        prime = random.randint(2**10, 2**12)
        if all(prime % i != 0 for i in range(2, int(prime**0.5) + 1)):
            return prime

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
        avg = (data["total_time"]/data["count"] * 1000) if data["count"] > 0 else 0
        print(f"{key:<30}{avg:>15.4f}{data['count']:>10}")
    print("-" * 60)

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

class PatientClient:
    def __init__(self, host='127.0.0.1', port=5000, patient_id="Patient_1"):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.prime = None
        self.g = None
        self.private_key_patient = None
        self.public_key_patient = None
        self.id_patient = patient_id
        self.delta_ts = 5  # seconds
        self.session_key = None  # ephemeral session key
        self.public_key_doctor = None  # to be received from server
        self.group_key = None  # will be received via opcode 30

    def connect(self):
        try:
            self.client.connect((self.host, self.port))
            self.exchange_public_key()
            self.authenticate()
            self.listen_for_broadcasts()
        except Exception as e:
            print(f"Connection error: {e}")
            self.client.close()

    def exchange_public_key(self):
        self.prime = generate_large_prime()
        self.g = primitive_root(self.prime)
        self.private_key_patient, self.public_key_patient = generate_key_pair(self.prime, self.g)
        public_key_tuple = (self.prime, self.g, self.public_key_patient)
        pk_request = {
            "opcode": 5,
            "public_key_patient": public_key_tuple,
            "id_patient": self.id_patient
        }
        self.client.send(pickle.dumps(pk_request))
        data = self.client.recv(4096)
        if not data:
            print("[Opcode 60] No response from server.")
            self.client.close()
            return
        response = pickle.loads(data)
        if "opcode" in response:
            if response["opcode"] == 70:
                print("[Opcode 70] Already Active Connection Exists.")
                self.client.close()
                return
            elif response["opcode"] == 80:
                print("[Opcode 80] " + response["message"])
                self.client.close()
                return
            elif response["opcode"] == 5:
                doctor_pk_tuple = response["public_key_doctor"]
                p_doc, g_doc, y_doc = doctor_pk_tuple
                if p_doc != self.prime or g_doc != self.g:
                    print("[Opcode 60] Domain parameter mismatch.")
                    self.client.close()
                    return
                self.public_key_doctor = y_doc
                print("Received doctor's public key.")
            else:
                print("Invalid response from server.")
                self.client.close()
        else:
            print("Invalid response from server.")
            self.client.close()

    def authenticate(self):
        try:
            ts_patient = int(time.time())
            rn_patient = random.randint(1000, 9999)
            self.session_key = random.randint(10000, 99999)
            r_val = random.randint(1, self.prime - 1)
            c1 = pow(self.g, r_val, self.prime)
            c2 = (self.session_key * pow(self.public_key_doctor, r_val, self.prime)) % self.prime
            msg_to_sign = f"{ts_patient}{rn_patient}{'GWN_Doctor_1'}{c1}{c2}"
            sign_data1 = elgamal_sign(msg_to_sign, self.private_key_patient, self.prime, self.g)
            auth_request = {
                "opcode": 10,
                "ts_patient": ts_patient,
                "rn_patient": rn_patient,
                "id_patient": self.id_patient,
                "c1": c1,
                "c2": c2,
                "public_key_patient": (self.prime, self.g, self.public_key_patient),
                "sign_data1": sign_data1
            }
            self.client.send(pickle.dumps(auth_request))
            data = self.client.recv(4096)
            if not data:
                print("[Opcode 60] No response during authentication.")
                self.client.close()
                return
            response = pickle.loads(data)
            if "opcode" in response and response["opcode"] == 80:
                print("[Opcode 80] " + response["message"])
                self.client.close()
                return
            ts_doctor = response['ts_doctor']
            rn_doctor_response = response['rn_doctor']
            c1_reencrypted = response['c1_reencrypted']
            c2_reencrypted = response['c2_reencrypted']
            sign_data2 = response['sign_data2']
            doctor_pk_tuple = response.get("public_key_doctor")
            if doctor_pk_tuple:
                p_doc, g_doc, y_doc = doctor_pk_tuple
                if p_doc != self.prime or g_doc != self.g:
                    print("[Opcode 60] Domain parameter mismatch with doctor's key.")
                    self.client.close()
                    return
                self.public_key_doctor = y_doc
            if abs(time.time() - ts_doctor) > self.delta_ts:
                print("[Opcode 60] Timestamp validation failed (doctor's response).")
                self.client.close()
                return
            msg_to_verify = f"{ts_doctor}{rn_doctor_response}{self.id_patient}{c1_reencrypted}{c2_reencrypted}"
            if not elgamal_verify(msg_to_verify, sign_data2, self.public_key_doctor, self.prime, self.g):
                print("[Opcode 60] Signature verification failed.")
                self.client.close()
                return
            print("[Opcode 10: KEY VERIFICATION] Signature validation successful.")
            s = pow(c1_reencrypted, self.private_key_patient, self.prime)
            s_inv = pow(s, -1, self.prime)
            decrypted_session_key = (c2_reencrypted * s_inv) % self.prime
            print(f"[Opcode 20: SESSION TOKEN] Decrypted session key: {decrypted_session_key}")
            if decrypted_session_key != (self.session_key % self.prime):
                print("[Opcode 60] Session key mismatch. Terminating connection.")
                self.client.close()
                return
            print("[Opcode 10: KEY VERIFICATION] Session key matches. Secure communication established.")
            computed_sk_input = f"{decrypted_session_key}{ts_patient}{ts_doctor}{rn_patient}{rn_doctor_response}{self.id_patient}{'GWN_Doctor_1'}"
            computed_sk = compute_hash(computed_sk_input)
            ts_patient_final = int(time.time())
            computed_skv_input = f"{computed_sk}{ts_patient_final}"
            skv_patient = compute_hash(computed_skv_input)
            self.session_key=computed_sk
            final_validation = {
                "skv_patient": skv_patient,
                "ts_patient_final": ts_patient_final
            }
            self.client.send(pickle.dumps(final_validation))
            print("Session key verification sent. Secure communication established.")
            print_performance_table()
        except Exception as e:
            print(f"An error occurred during authentication: {e}")
            self.client.close()

    def decrypt_with_aes(self, encrypted_message, key):
        try:
            iv = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Error during decryption: {e}")
            return None

    def listen_for_broadcasts(self):
        try:
            while True:
                data = self.client.recv(4096)
                if not data:
                    print("[Opcode 60] Server disconnected.")
                    break
                msg = pickle.loads(data)
                if "opcode" in msg:
                    if msg["opcode"] == 30:
                        encrypted_GK = msg["encrypted_group_key"]
                        sk_effective = self.session_key
                        print(sk_effective)
                        #sk_effective = self.session_key % self.prime
                        #sk_effective = self.session_key
                        #key_bytes = sk_effective.to_bytes(16, byteorder='big', signed=False)
                        key_bytes = bytes.fromhex(sk_effective)
                        try:
                            self.group_key = self.decrypt_with_aes(encrypted_GK, key_bytes)
                            if self.group_key:
                                print(f"[Opcode 30] Received group key: {self.group_key}")
                            else:
                                print("[Opcode 30] Failed to decrypt group key.")
                        except Exception as e:
                            print(f"Error decrypting group key: {e}")
                    elif msg["opcode"] == 40:
                        encrypted_message = msg["encrypted_message"]
                        if not self.group_key:
                            print("[INFO] No group key available yet.")
                            continue
                        key_for_group = self.group_key[:32]  # first 32 hex chars = 16 bytes
                        key_bytes = bytes.fromhex(key_for_group)
                        broadcast_text = self.decrypt_with_aes(encrypted_message, key_bytes)
                        if broadcast_text is None:
                            print("[Opcode 40] Failed to decrypt broadcast message.")
                        else:
                            print(f"[Opcode 50: DEC MSG] Broadcast Message Received: {broadcast_text}")
                    elif msg["opcode"] == 80:
                        print("[BLOCKED] " + msg.get("message", "You have been blocked by the server."))
                        self.client.close()
                        break
                    elif msg["opcode"] == 60:
                        print("[Opcode 60] " + msg.get("message", "Server disconnected."))
                        self.client.close()
                        break
        except KeyboardInterrupt:
            # On Ctrl+C, send opcode 90 to notify the server
            exit_msg = {"opcode": 90, "id_patient": self.id_patient}
            try:
                self.client.send(pickle.dumps(exit_msg))
                print("[Opcode 90] Sent exit message to server.")
            except Exception as e:
                print(f"Error sending exit message: {e}")
        except Exception as e:
            print(f"Error receiving broadcast: {e}")
        finally:
            self.client.close()
            print("Client connection closed.")

if __name__ == "__main__":
    patient_id = input("Enter patient ID (e.g., Patient_1): ")
    client = PatientClient(patient_id=patient_id)
    client.connect()
