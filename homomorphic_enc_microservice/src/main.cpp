#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>
#include <pistache/http_defs.h>
#include <seal/seal.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>

using json = nlohmann::json;
using namespace Pistache;
using namespace seal;
using namespace Rest::Routes;

// 1) Declaración/definición de la función para agregar cabeceras CORS
void addCorsHeaders(Http::ResponseWriter &response) {
    // Permitir solicitudes desde el origen del frontend
    response.headers().add<Http::Header::AccessControlAllowOrigin>("*");
    // Permitir métodos
    response.headers().add<Http::Header::AccessControlAllowMethods>("GET, POST, PUT, DELETE, OPTIONS");
    // Incluir "x-api-key" (o cualquier otro header) en la lista
    response.headers().add<Http::Header::AccessControlAllowHeaders>("Content-Type, Accept, Origin, x-api-key");
}


// Funciones de codificación y decodificación Base64
class Base64 {
public:
    static std::string encode(const std::string &input) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, input.data(), input.size());
        BIO_flush(bio);

        char *encoded;
        size_t length = BIO_get_mem_data(bio, &encoded);
        std::string result(encoded, length);

        BIO_free_all(bio);
        return result;
    }

    static std::string decode(const std::string &input) {
        BIO *bio = BIO_new_mem_buf(input.data(), input.size());
        BIO *b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        std::vector<char> buffer(input.size());
        int decodedLength = BIO_read(bio, buffer.data(), buffer.size());

        BIO_free_all(bio);
        return std::string(buffer.data(), decodedLength);
    }
};

// Clase auxiliar para la configuración de SEAL
class SealUtils {
public:
    static SEALContext createSealContext(const json &sealContextJson) {
        // Determinar el esquema (BFV o CKKS)
        scheme_type scheme;
        std::string schemeType = sealContextJson["schemeType"];
        if (schemeType == "BFV") {
            scheme = scheme_type::bfv;  // 1
        } else if (schemeType == "CKKS") {
            scheme = scheme_type::ckks; // 1
        } else {
            throw std::invalid_argument("Esquema no soportado: " + schemeType);
        }

        size_t polyModulusDegree = sealContextJson["polyModulusDegree"];

        // Configuración de parámetros
        EncryptionParameters parms(scheme);
        parms.set_poly_modulus_degree(polyModulusDegree);

        if (scheme == scheme_type::bfv) {
            std::cout << "Configurando BFV..." << std::endl;
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(polyModulusDegree));
            parms.set_plain_modulus(PlainModulus::Batching(polyModulusDegree, 60));
        } else if (scheme == scheme_type::ckks) {
            std::cout << "Configurando CKKS..." << std::endl;
            std::vector<int> coeffModulusBits = sealContextJson["coeffModulus"];
            parms.set_coeff_modulus(CoeffModulus::Create(polyModulusDegree, coeffModulusBits));
        }

        SEALContext context(parms);
        if (!context.parameters_set()) {
            throw std::invalid_argument("Parámetros inválidos para el esquema especificado");
        }
        return context;
    }
};

// Clase principal que maneja los endpoints
class HomomorphicHandler {
public:

    // Endpoint OPTIONS para manejar preflight
    void handleOptions(const Rest::Request &request, Http::ResponseWriter response) {
        addCorsHeaders(response);
        response.send(Http::Code::Ok);
    }

    // generate-keys
    void generateKeys(const Rest::Request &request, Http::ResponseWriter response) {
        try {
            addCorsHeaders(response); // Agrega cabeceras CORS
            auto jsonBody = json::parse(request.body());
            SEALContext context = SealUtils::createSealContext(jsonBody["sealContext"]);

            KeyGenerator keygen(context);
            PublicKey publicKey;
            keygen.create_public_key(publicKey);
            SecretKey secretKey = keygen.secret_key();

            std::ostringstream publicKeyStream, secretKeyStream;
            publicKey.save(publicKeyStream);
            secretKey.save(secretKeyStream);

            json result;
            result["publicKey"] = Base64::encode(publicKeyStream.str());
            result["secretKey"] = Base64::encode(secretKeyStream.str());
            response.send(Http::Code::Ok, result.dump());
        } catch (const std::exception &e) {
            response.send(Http::Code::Internal_Server_Error, e.what());
        }
    }

    // encrypt
    void encrypt(const Rest::Request &request, Http::ResponseWriter response) {
        try {
            addCorsHeaders(response);
            auto jsonBody = json::parse(request.body());

            // Verificar campos requeridos
            if (!jsonBody.contains("sealContext") || jsonBody["sealContext"].is_null()) {
                throw std::invalid_argument("El campo 'sealContext' es requerido.");
            }
            if (!jsonBody["sealContext"].contains("schemeType") || jsonBody["sealContext"]["schemeType"].is_null()) {
                throw std::invalid_argument("El campo 'schemeType' dentro de 'sealContext' es requerido.");
            }
            if (!jsonBody.contains("publicKey") || jsonBody["publicKey"].empty()) {
                throw std::invalid_argument("El campo 'publicKey' es requerido y no puede estar vacío.");
            }
            if (!jsonBody.contains("plainTextValue") || jsonBody["plainTextValue"].is_null()) {
                throw std::invalid_argument("El campo 'plainTextValue' es requerido.");
            }

            // Crear contexto SEAL
            SEALContext context = SealUtils::createSealContext(jsonBody["sealContext"]);
            if (jsonBody["sealContext"]["schemeType"] == "CKKS") {
                std::cout << "Configurando CKKS..." << std::endl;
            }

            // Cargar la clave pública
            PublicKey publicKey;
            std::istringstream publicKeyStream(Base64::decode(jsonBody["publicKey"]));
            publicKey.load(context, publicKeyStream);

            Encryptor encryptor(context, publicKey);
            Plaintext plaintext;

            // Leer el esquema
            std::string schemeType = jsonBody["sealContext"]["schemeType"];
            if (schemeType == "BFV") {
                uint64_t decimalValue = jsonBody["plainTextValue"].get<uint64_t>();
                plaintext = Plaintext(std::to_string(decimalValue));
            } else if (schemeType == "CKKS") {
                double value = jsonBody["plainTextValue"].get<double>();
                CKKSEncoder encoder(context);
                double scale = pow(2.0, 40);
                encoder.encode(value, scale, plaintext);
            } else {
                throw std::invalid_argument("Esquema no reconocido: " + schemeType);
            }

            // Encriptar
            Ciphertext ciphertext;
            encryptor.encrypt(plaintext, ciphertext);

            // Serializar ciphertext
            std::ostringstream cipherStream;
            ciphertext.save(cipherStream);

            json result;
            result["encryptedValue"] = Base64::encode(cipherStream.str());
            response.send(Http::Code::Ok, result.dump());
        } catch (const std::exception &e) {
            response.send(Http::Code::Internal_Server_Error, e.what());
        }
    }

    // decrypt
    void decrypt(const Rest::Request &request, Http::ResponseWriter response) {
        try {
            addCorsHeaders(response);
            auto jsonBody = json::parse(request.body());

            // Verificar campos requeridos
            if (!jsonBody.contains("sealContext") || jsonBody["sealContext"].is_null()) {
                throw std::invalid_argument("El campo 'sealContext' es requerido.");
            }
            if (!jsonBody["sealContext"].contains("schemeType") || jsonBody["sealContext"]["schemeType"].is_null()) {
                throw std::invalid_argument("El campo 'schemeType' dentro de 'sealContext' es requerido.");
            }
            if (!jsonBody.contains("secretKey") || jsonBody["secretKey"].empty()) {
                throw std::invalid_argument("El campo 'secretKey' es requerido y no puede estar vacío.");
            }
            if (!jsonBody.contains("encryptedValue") || jsonBody["encryptedValue"].empty()) {
                throw std::invalid_argument("El campo 'encryptedValue' es requerido y no puede estar vacío.");
            }

            // Crear contexto SEAL
            SEALContext context = SealUtils::createSealContext(jsonBody["sealContext"]);
            if (jsonBody["sealContext"]["schemeType"] == "CKKS") {
                std::cout << "Configurando CKKS..." << std::endl;
            }

            // Cargar la clave secreta
            SecretKey secretKey;
            std::istringstream secretKeyStream(Base64::decode(jsonBody["secretKey"]));
            secretKey.load(context, secretKeyStream);

            // Cargar ciphertext
            Ciphertext ciphertext;
            std::istringstream cipherStream(Base64::decode(jsonBody["encryptedValue"]));
            ciphertext.load(context, cipherStream);

            // Desencriptar
            Decryptor decryptor(context, secretKey);
            Plaintext plaintext;
            decryptor.decrypt(ciphertext, plaintext);

            json result;

            // Leer schemeType
            std::string schemeType = jsonBody["sealContext"]["schemeType"];
            if (schemeType == "BFV") {
                std::string plainValue = plaintext.to_string();
                uint64_t decodedValueBFV = std::stoull(plainValue);
                result["plainTextValue"] = decodedValueBFV;
            } else if (schemeType == "CKKS") {
                CKKSEncoder encoder(context);
                std::vector<double> value;
                encoder.decode(plaintext, value);

                if (!value.empty()) {
                    double decodedValueCKKS = value[0];
                    result["plainTextValue"] = decodedValueCKKS;
                } else {
                    throw std::runtime_error("El vector decodificado está vacío.");
                }
            } else {
                throw std::invalid_argument("Esquema no reconocido: " + schemeType);
            }

            response.send(Http::Code::Ok, result.dump());
        } catch (const std::exception &e) {
            response.send(Http::Code::Internal_Server_Error, e.what());
        }
    }

    // add (suma)
    void add(const Rest::Request &request, Http::ResponseWriter response) {
        try {
            addCorsHeaders(response);
            auto jsonBody = json::parse(request.body());
            SEALContext context = SealUtils::createSealContext(jsonBody["sealContext"]);

            Ciphertext cipher1, cipher2;
            std::istringstream cipher1Stream(Base64::decode(jsonBody["encryptedValue1"]));
            std::istringstream cipher2Stream(Base64::decode(jsonBody["encryptedValue2"]));
            cipher1.load(context, cipher1Stream);
            cipher2.load(context, cipher2Stream);

            Evaluator evaluator(context);
            Ciphertext resultCipher;
            evaluator.add(cipher1, cipher2, resultCipher);

            std::ostringstream resultStream;
            resultCipher.save(resultStream);

            json result;
            result["encryptedResult"] = Base64::encode(resultStream.str());
            response.send(Http::Code::Ok, result.dump());
        } catch (const std::exception &e) {
            response.send(Http::Code::Internal_Server_Error, e.what());
        }
    }
};

int main() {
    Address addr(Ipv4::any(), Port(8889));
    Http::Endpoint server(addr);

    auto opts = Http::Endpoint::options()
        .threads(1)
        .maxRequestSize(10 * 1024 * 1024);
    server.init(opts);

    Rest::Router router;
    HomomorphicHandler handler;

    Post(router, "/homomorphic/generate-keys", bind(&HomomorphicHandler::generateKeys, &handler));
    Post(router, "/homomorphic/encrypt",      bind(&HomomorphicHandler::encrypt,       &handler));
    Post(router, "/homomorphic/decrypt",      bind(&HomomorphicHandler::decrypt,       &handler));
    Post(router, "/homomorphic/add",          bind(&HomomorphicHandler::add,           &handler));
    Options(router, "/homomorphic/*",         bind(&HomomorphicHandler::handleOptions, &handler));

    server.setHandler(router.handler());
    std::cout << "Servidor en ejecución en http://localhost:8889" << std::endl;

    server.serve();
    return 0;
}
