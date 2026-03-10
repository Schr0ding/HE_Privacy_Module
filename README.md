# HE Privacy Module

A **Homomorphic Encryption (HE) Privacy Module** composed of a C++ REST microservice and a set of demo videos illustrating a full privacy-preserving data-sharing workflow.

## Repository Structure

```
HE_Privacy_Module/
├── homomorphic_enc_microservice/   # C++ HE REST API
│   ├── src/main.cpp
│   ├── CMakeLists.txt
│   └── Dockerfile
└── demo/                           # Workflow demo videos
```

---

## Homomorphic Encryption Microservice

A RESTful microservice built in **C++17** that exposes cryptographic operations using **Microsoft SEAL**. It supports the **BFV** and **CKKS** homomorphic encryption schemes, enabling computation on encrypted data without ever decrypting it.

### Tech Stack

| Component | Library / Version |
|---|---|
| Homomorphic Encryption | [Microsoft SEAL](https://github.com/microsoft/SEAL) v4.1.1 |
| HTTP Framework | [Pistache](https://github.com/pistacheio/pistache) |
| JSON Parsing | [nlohmann/json](https://github.com/nlohmann/json) v3.11.2 |
| Base64 / Crypto | OpenSSL |
| Build System | CMake ≥ 3.22.1 |

### API Endpoints

All endpoints are `POST` and listen on **port `8889`**. Payloads and responses are JSON. Keys and ciphertexts are serialized as **Base64** strings.

#### `POST /homomorphic/generate-keys`

Generates a public/secret key pair for a given SEAL context.

**Request body:**
```json
{
  "sealContext": {
    "schemeType": "BFV",
    "polyModulusDegree": 4096
  }
}
```

**Response:**
```json
{
  "publicKey": "<base64>",
  "secretKey": "<base64>"
}
```

---

#### `POST /homomorphic/encrypt`

Encrypts a plaintext value using a public key.

**Request body (BFV):**
```json
{
  "sealContext": {
    "schemeType": "BFV",
    "polyModulusDegree": 4096
  },
  "publicKey": "<base64>",
  "plainTextValue": 42
}
```

**Request body (CKKS):**
```json
{
  "sealContext": {
    "schemeType": "CKKS",
    "polyModulusDegree": 8192,
    "coeffModulus": [60, 40, 40, 60]
  },
  "publicKey": "<base64>",
  "plainTextValue": 3.14
}
```

**Response:**
```json
{
  "encryptedValue": "<base64>"
}
```

---

#### `POST /homomorphic/decrypt`

Decrypts a ciphertext using a secret key.

**Request body:**
```json
{
  "sealContext": { ... },
  "secretKey": "<base64>",
  "encryptedValue": "<base64>"
}
```

**Response:**
```json
{
  "plainTextValue": 42
}
```

---

#### `POST /homomorphic/add`

Performs **homomorphic addition** of two ciphertexts. The result remains encrypted and can only be decrypted by the holder of the secret key.

**Request body:**
```json
{
  "sealContext": { ... },
  "encryptedValue1": "<base64>",
  "encryptedValue2": "<base64>"
}
```

**Response:**
```json
{
  "encryptedResult": "<base64>"
}
```

---

### Running with Docker

**Build the image:**
```bash
cd homomorphic_enc_microservice
docker build -t he-microservice .
```

**Run the container:**
```bash
docker run -p 8889:8889 he-microservice
```

The server will be available at `http://localhost:8889`.

> The Dockerfile installs all dependencies from source (Pistache, nlohmann/json, Microsoft SEAL) on top of Ubuntu 22.04, so the build may take several minutes on the first run.

### Building Locally (without Docker)

Prerequisites: `cmake`, `libssl-dev`, `meson`, `ninja-build`, Microsoft SEAL v4.1.1 and Pistache installed system-wide.

```bash
cd homomorphic_enc_microservice
mkdir build && cd build
cmake ..
make -j$(nproc)
./MicroServC
```

---

## Demo

The `demo/` directory contains **8 video files** illustrating a complete privacy-preserving data-sharing workflow:

| # | Video | Description |
|---|---|---|
| 1 | `1_policy_creation.mp4` | Create a data-sharing policy |
| 2 | `2_asset_creation.mp4` | Register a data asset |
| 3 | `3_Contract_creation.mp4` | Establish a contract between parties |
| 4 | `4_Consumer_keygen.mp4` | Consumer generates a HE key pair |
| 5 | `5_Aggregator_Key_Assignation.mp4` | Aggregator is assigned the public key |
| 6 | `6_Provider_encryption.mp4` | Provider encrypts data with the public key |
| 7 | `7_Aggregator_computation.mp4` | Aggregator performs computation on encrypted data |
| 8 | `8_Decryption.mp4` | Consumer decrypts the final result |

This workflow demonstrates how a **consumer**, a **data provider**, and an **aggregator** can collaborate on sensitive data without the aggregator ever seeing the plaintext values.

---

## Supported HE Schemes

| Scheme | Use Case | Value Type |
|---|---|---|
| **BFV** | Exact integer arithmetic | `uint64` |
| **CKKS** | Approximate floating-point arithmetic | `double` |

## License

See [LICENSE](LICENSE) for details.
