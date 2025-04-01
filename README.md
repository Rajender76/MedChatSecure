# MedChatSecure
Implementation of Secure Telemedical Conference using Digital Signature.


# Secure Telemedical Conference (Lab Assignment 2)


## Code Flow

1) Run server.py
  ```python server.py```
2) Start client.py

  ```python client.py```

### Code Flow Explaination and Functionality

1) Client generates the public parameters (p,g,y) and send to doctor

2) Doctor computes his public key and shares to client(patient).

3) Choose the Random Integer(SK), With Doctor's public key, generate elgamal encryption of it and sign using patient's private key. The detailed steps are placed below.

4) After verifying timestamp, verify the signature and decrypt the Random Integer(SK).

5) Now again With Patient's public key, generate elgamal encryption of it and sign using doctor's private key. The detailed steps are placed below.

6) Now patient will verify timestamp,verigy and the signature and decrypt it which will be equal to generated Random Integer(SK).

7) Now, patient will generate the Shared Session Key by hashing and genrate the verifier and sends to doctor.

8) Doctor will compute the shared session key and verify. Now authentication is successful.

9) At the server side, we enabled the user to enter the broadcasst message and privilege to block the patient. Now the Message Broadcast will be done.

10) When a new Patient comes, then we will compute the Group Key and share to all existing authenticated patients.

11) We used AES with 256 bit key and in CBC Mode.

### Functionalities

1) When a new broadcast message is to be delivered, then we computed Group key and sent to all patients.

2) Doctor can block any patient at any time and Patient can voluntarilty exit.

3) If the two patients enter with same ID, then blocking both.


## Communication Protocol Opcodes


### Opcode 5: PUBLIC PARAMETERS EXCHANGE
**Syntax:**
```
{
  "opcode": 5,
  "public_key_patient": (p, g, public_key),
  "id_patient": "Patient_ID"
}
```
**Description:** Exchange public keys between patient and doctor.

---

### Opcode 10: KEY VERIFICATION

**Syntax:**  
Client → Server:
```
<ts_patient, rn_patient, id_patient, c1, c2, sign_data1>
sign_data1=elgamal_sign({ts_patient, rn_patient, id_patient, c1, c2})
```
Server → Client:
```
<ts_doctor, rn_doctor, id_patient, c1_reencrypted, c2_reencrypted, sign_data2>
```

**Description:** Authenticate and establish a session key between doctor and patient using ElGamal signatures.

---

### Opcode 20: SESSION TOKEN

**Syntax:**
```
<ts_doctor, rn_doctor, id_patient, c1_reencrypted, c2_reencrypted, sign_data2>
```
**Purpose:** Exchange encrypted session key to establish secure communication.

---

### Opcode 30: GROUP KEY

**Syntax:**
```
<encrypted_group_key>
```
**Purpose:** Securely distribute a group key encrypted with session keys to each patient.

---

### Opcode 40: ENC MSG

**Syntax:**
```
<encrypted_group_key, encrypted_message>
```
**Purpose:** Broadcast encrypted emergency messages from doctor to all patients.

---

### Opcode 50: DEC MSG

**Syntax:**
```
<decrypted_message>
```
**Purpose:** Patients decrypt received messages using the group key.

---

### Opcode 60: DISCONNECT

**Syntax:**
```
<message>
```
**Purpose:** End session for participants due to validation failure or errors.

---

### Opcode 80: BLOCKED

**Syntax:**
```
<message>
```
**Purpose:** Notify client about blocking due to security violations (e.g., invalid timestamps, signature mismatch).

---

### Opcode 90: EXIT

**Syntax:**
```
<id_patient>
```
**Purpose:** Client notifies server upon intentional disconnection.

---

## Performance Metrics

### We are computing performance metrics both at client and server. At Server, Cumulative performances will be displayed

Eg ..

| Primitive            | Avg Time (ms) | Calls |
|----------------------|---------------|-------|
| KeyPair Generation   | 0.0217        | 5     |
| Signature Generation | 0.0538        | 5     |
| Signature Verification | 0.1079      | 5     |
| Hash Computation     | 0.0219        | 28    |

---

### Assumptions 
- Maximum allowable transmission delay (`∆TS`) is set to 5 seconds.
- We are using 2 min block time when we block.
- We are enabling another thing like if client presses Ctrl+C, that means it is voluntarily exited from the group. We enabled it using Signal Handling.
- AES encryption is utilized for message confidentiality.
- ElGamal cryptosystem is used for signatures and key exchange.

---

**Run Instructions:**
```
Server:
python server.py

Client:
python client.py
```

Ensure dependencies (`pickle`, `Crypto`, `sympy`, etc.) are installed.

---

To activate Environmental variables in UBuntu source /home/saicharanthammi/Downloads/POIS/22_lab1\ \(2\)/venv/bin/activate
