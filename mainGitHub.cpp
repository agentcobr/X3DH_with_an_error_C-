#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/kdf.h>

#include <QByteArray>
#include <QFile>
#include <QDebug>
#include <stdexcept>
#include <QTextStream>
#include <QString>

struct KeyPair {
    QByteArray privateKey;
    QByteArray publicKey;
};

struct KeyStorage {
    KeyPair IK;
    KeyPair EK;
    KeyPair SPK;
    KeyPair OPK;
};

class FullFunction {
public:
    KeyPair generateIK();
    KeyPair generateIKSign();
    KeyPair generateEK();
    KeyPair generateSPK(const QByteArray& IK_privateKey);
    KeyPair generateOPK();

    KeyPair generateKeyPair();                                                      //ED25519
    KeyPair generateKeyPairSign();                                                  //X25519

    QByteArray signData(const QByteArray& data, const QByteArray& privateKey);

    void saveKeys(const QByteArray &keyData, const QString &fileName);
    QByteArray loadKey(const QString& filename);
    EVP_PKEY* loadPrivateKey(const QByteArray& keyData);
    EVP_PKEY* loadPublicKey(const QByteArray& keyData);
    QByteArray convertPKeyToByteArray(EVP_PKEY* pkey);

    QByteArray computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey);

    QByteArray generateSharedSecret(const QByteArray& IK_A,
                                    const QByteArray& EK_A,
                                    const QByteArray& IK_B,
                                    const QByteArray& SPK_B,
                                    const QByteArray& OPK_B);
private:
    QByteArray IK_private;
    QByteArray IK_public;
    KeyPair signedPreKey;
    std::vector<KeyPair> OTPs;

    QByteArray extractPrivateKey(EVP_PKEY* pkey);
    QByteArray extractPublicKey(EVP_PKEY* pkey);
};

KeyPair FullFunction::generateKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Key generation failed.");
    }

    BIO* bioPrivate = BIO_new(BIO_s_mem());
    if (!bioPrivate) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for private key");
    }

    if (!PEM_write_bio_PrivateKey(bioPrivate, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bioPrivate);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* bufferPrivate;
    BIO_get_mem_ptr(bioPrivate, &bufferPrivate);
    QByteArray privateKey(bufferPrivate->data, bufferPrivate->length);
    BIO_free(bioPrivate);

    BIO* bioPublic = BIO_new(BIO_s_mem());
    if (!bioPublic) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    if (!PEM_write_bio_PUBKEY(bioPublic, pkey)) {
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write public key to BIO");
    }

    BUF_MEM* bufferPublic;
    BIO_get_mem_ptr(bioPublic, &bufferPublic);
    QByteArray publicKey(bufferPublic->data, bufferPublic->length);
    BIO_free(bioPublic);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return KeyPair{privateKey, publicKey};
}

KeyPair FullFunction::generateKeyPairSign() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Key generation failed.");
    }

    BIO* bioPrivate = BIO_new(BIO_s_mem());
    if (!bioPrivate) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for private key");
    }

    if (!PEM_write_bio_PrivateKey(bioPrivate, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bioPrivate);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* bufferPrivate;
    BIO_get_mem_ptr(bioPrivate, &bufferPrivate);
    QByteArray privateKey(bufferPrivate->data, bufferPrivate->length);
    BIO_free(bioPrivate);

    BIO* bioPublic = BIO_new(BIO_s_mem());
    if (!bioPublic) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIO for public key");
    }

    if (!PEM_write_bio_PUBKEY(bioPublic, pkey)) {
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to write public key to BIO");
    }

    BUF_MEM* bufferPublic;
    BIO_get_mem_ptr(bioPublic, &bufferPublic);
    QByteArray publicKey(bufferPublic->data, bufferPublic->length);
    BIO_free(bioPublic);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return KeyPair{privateKey, publicKey};
}

KeyPair FullFunction::generateIK() {
    return generateKeyPair();
}

KeyPair FullFunction::generateEK() {
    return generateKeyPairSign();
}

KeyPair FullFunction::generateSPK(const QByteArray& IK_privateKey) {
    KeyPair spk = generateKeyPairSign();

    QByteArray signature = signData(spk.publicKey, IK_privateKey);

    qDebug() << "SPK public key signed successfully.";

    return KeyPair{spk.privateKey, spk.publicKey + signature};
}

KeyPair FullFunction::generateOPK() {
    return generateKeyPairSign();
}

void FullFunction::saveKeys(const QByteArray &keyData, const QString &fileName) {
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        throw std::runtime_error("Failed to open file for writing: " + fileName.toStdString());
    }

    if (file.write(keyData) == -1) {
        file.close();
        throw std::runtime_error("Failed to write data to file: " + fileName.toStdString());
    }
    file.close();
    qDebug() << "Saved a key to" << fileName;
}

QByteArray FullFunction::loadKey(const QString& filename) {
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Unable to open file for reading: " + filename.toStdString());
    }
    QByteArray key = file.readAll();

    if (!key.startsWith("-----BEGIN")) {
        throw std::runtime_error("Key is not in PEM format.");
    }

    file.close();
    return key;
}

EVP_PKEY* FullFunction::loadPrivateKey(const QByteArray& keyData) {
    if (keyData.isEmpty()) {
        throw std::runtime_error("Key data is empty.");
    }

    if (!keyData.contains("-----BEGIN PRIVATE KEY-----")) {
        throw std::runtime_error("Invalid PEM format for private key.");
    }

    BIO* bio = BIO_new_mem_buf(keyData.constData(), keyData.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key.");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        unsigned long errCode = ERR_get_error();
        char errMsg[256];
        ERR_error_string_n(errCode, errMsg, sizeof(errMsg));
        throw std::runtime_error("Failed to read private key (loadPrivateKey): " + std::string(errMsg));
    }

    return pkey;
}


EVP_PKEY* FullFunction::loadPublicKey(const QByteArray& keyData) {
    BIO* bio = BIO_new_mem_buf(keyData.constData(), keyData.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key.");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw std::runtime_error("Failed to read public key: " + QString(ERR_error_string(ERR_get_error(), nullptr)).toStdString());
    }

    return pkey;
}

QByteArray FullFunction::convertPKeyToByteArray(EVP_PKEY* pkey) {
    if (!pkey) {
        throw std::runtime_error("Null EVP_PKEY provided.");
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO.");
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write public key to BIO.");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    QByteArray byteArray(mem->data, static_cast<int>(mem->length));

    BIO_free(bio);
    return byteArray;
}

QByteArray FullFunction::signData(const QByteArray& data, const QByteArray& privateKey) {
    BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw std::runtime_error("Failed to load private key: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Private key is not Ed25519");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX for signing");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize DigestSign: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    size_t sigLen = 0;
    if (EVP_DigestSign(ctx, nullptr, &sigLen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to determine signature length: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    QByteArray signature(sigLen, 0);
    if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(signature.data()), &sigLen,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to compute signature: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

QByteArray FullFunction::computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey) {
    std::unique_ptr<BIO, decltype(&BIO_free)> privBio(
        BIO_new_mem_buf(localKey.privateKey.data(), localKey.privateKey.size()), BIO_free);
    if (!privBio) {
        throw std::runtime_error("Failed to create BIO for private key.");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> privKey(
        d2i_PrivateKey_bio(privBio.get(), nullptr), EVP_PKEY_free);
    if (!privKey) {
        unsigned long err = ERR_get_error();
        char errBuff[120];
        ERR_error_string_n(err, errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to read private key: ") + errBuff);
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> pubBio(
        BIO_new_mem_buf(remotePublicKey.data(), remotePublicKey.size()), BIO_free);
    if (!pubBio) {
        throw std::runtime_error("Failed to create BIO for public key.");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pubKey(
        d2i_PUBKEY_bio(pubBio.get(), nullptr), EVP_PKEY_free);
    if (!pubKey) {
        throw std::runtime_error("Failed to read public key.");
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(privKey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), pubKey.get()) <= 0) {
        unsigned long err = ERR_get_error();
        char errBuff[120];
        ERR_error_string_n(err, errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to initialize or set peer for shared secret computation: ") + errBuff);
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) <= 0) {
        throw std::runtime_error("Failed to determine shared secret length.");
    }

    QByteArray sharedSecret(secretLen, 0);
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(sharedSecret.data()), &secretLen) <= 0) {
        throw std::runtime_error("Failed to derive shared secret.");
    }

    return sharedSecret;
}

QByteArray FullFunction::generateSharedSecret(const QByteArray& IK_A, const QByteArray& EK_A,
                                              const QByteArray& IK_B, const QByteArray& SPK_B,
                                              const QByteArray& OPK_B) {
    if (IK_A.isEmpty() || EK_A.isEmpty() || IK_B.isEmpty() || SPK_B.isEmpty() || OPK_B.isEmpty()) {
        throw std::invalid_argument("One or more input keys are empty.");
    }

    QByteArray DH1 = computeSharedSecret({IK_A, {}}, SPK_B);
    QByteArray DH2 = computeSharedSecret({EK_A, {}}, IK_B);
    QByteArray DH3 = computeSharedSecret({EK_A, {}}, SPK_B);
    QByteArray DH4 = computeSharedSecret({EK_A, {}}, OPK_B);

    qDebug() << "DH1:" << DH1.toHex();
    qDebug() << "DH2:" << DH2.toHex();
    qDebug() << "DH3:" << DH3.toHex();
    qDebug() << "DH4:" << DH4.toHex();

    QByteArray concatenatedSecret = DH1 + DH2 + DH3 + DH4;

    if (concatenatedSecret.isEmpty()) {
        throw std::runtime_error("Concatenated secret is empty. Check shared secret computation.");
    }

    unsigned char outKey[32];
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        throw std::runtime_error("Failed to fetch HKDF.");
    }

    EVP_KDF_CTX* kdfCtx = EVP_KDF_CTX_new(kdf);
    if (!kdfCtx) {
        EVP_KDF_free(kdf);
        throw std::runtime_error("Failed to initialize HKDF context.");
    }

    QByteArray salt;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string("salt", salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string("key", concatenatedSecret.data(), concatenatedSecret.size()),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_CTX_set_params(kdfCtx, params) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_KDF_CTX_free(kdfCtx);
        EVP_KDF_free(kdf);
        throw std::runtime_error("HKDF parameter setup failed.");
    }

    size_t outKeyLen = sizeof(outKey);
    if (EVP_KDF_derive(kdfCtx, outKey, outKeyLen, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_KDF_CTX_free(kdfCtx);
        EVP_KDF_free(kdf);
        throw std::runtime_error("HKDF derivation failed.");
    }

    EVP_KDF_CTX_free(kdfCtx);
    EVP_KDF_free(kdf);

    return QByteArray(reinterpret_cast<const char*>(outKey), static_cast<int>(outKeyLen));
}

int main() {
    try {
        FullFunction keyManager;

        KeyPair ik_A = keyManager.generateIK();
        KeyPair ek_A = keyManager.generateEK();
        KeyPair spk_A = keyManager.generateSPK(ik_A.privateKey);

        std::vector<KeyPair> opks_A;
        for (int i = 0; i < 5; ++i) {
            opks_A.push_back(keyManager.generateOPK());
        }

        keyManager.saveKeys(ik_A.privateKey, "ikA_private.pem");
        keyManager.saveKeys(ik_A.publicKey, "ikA_public.pem");
        keyManager.saveKeys(spk_A.privateKey, "spkA_private.pem");
        keyManager.saveKeys(spk_A.publicKey, "spkA_public.pem");
        keyManager.saveKeys(ek_A.privateKey, "ekA_private.pem");
        keyManager.saveKeys(ek_A.publicKey, "ekA_public.pem");

        for (size_t i = 0; i < opks_A.size(); ++i) {
            keyManager.saveKeys(opks_A[i].privateKey, QString("opkA_private_%1.pem").arg(i));
            keyManager.saveKeys(opks_A[i].publicKey, QString("opkA_public_%1.pem").arg(i));
        }

        KeyPair ik_B = keyManager.generateIK();
        KeyPair ek_B = keyManager.generateEK();
        KeyPair spk_B = keyManager.generateSPK(ik_B.privateKey);

        std::vector<KeyPair> opks_B;
        for (int i = 0; i < 5; ++i) {
            opks_B.push_back(keyManager.generateOPK());
        }

        keyManager.saveKeys(ik_B.privateKey, "ikB_private.pem");
        keyManager.saveKeys(ik_B.publicKey, "ikB_public.pem");
        keyManager.saveKeys(spk_B.privateKey, "spkB_private.pem");
        keyManager.saveKeys(spk_B.publicKey, "spkB_public.pem");
        keyManager.saveKeys(ek_B.privateKey, "ekB_private.pem");
        keyManager.saveKeys(ek_B.publicKey, "ekB_public.pem");

        for (size_t i = 0; i < opks_B.size(); ++i) {
            keyManager.saveKeys(opks_B[i].privateKey, QString("opkB_private_%1.pem").arg(i));
            keyManager.saveKeys(opks_B[i].publicKey, QString("opkB_public_%1.pem").arg(i));
        }

        qDebug() << "All keys generated and saved successfully.";

        EVP_PKEY* loadedIKPublic_A = keyManager.loadPublicKey(keyManager.loadKey("ikA_public.pem"));
        EVP_PKEY* loadedEKPublic_A = keyManager.loadPublicKey(keyManager.loadKey("ekA_public.pem"));
        EVP_PKEY* loadedSPKPublic_B = keyManager.loadPublicKey(keyManager.loadKey("spkB_public.pem"));
        EVP_PKEY* loadedIKPublic_B = keyManager.loadPublicKey(keyManager.loadKey("ikB_public.pem"));
        EVP_PKEY* loadedOPKPublic_B = keyManager.loadPublicKey(keyManager.loadKey("opkB_public_0.pem"));

        //Проверка
        EVP_PKEY* loadedIKPrivate_A = keyManager.loadPrivateKey(keyManager.loadKey("ikA_private.pem"));
        EVP_PKEY* loadedEKPrivate_A = keyManager.loadPrivateKey(keyManager.loadKey("ekA_public.pem"));
        QByteArray byteIKPrivate_A = keyManager.convertPKeyToByteArray(loadedIKPrivate_A);
        QByteArray byteEKPrivate_A = keyManager.convertPKeyToByteArray(loadedEKPrivate_A);

        QByteArray byteIKPublic_A = keyManager.convertPKeyToByteArray(loadedIKPublic_A);
        QByteArray byteEKPublic_A = keyManager.convertPKeyToByteArray(loadedEKPublic_A);
        QByteArray byteSPKPublic_B = keyManager.convertPKeyToByteArray(loadedSPKPublic_B);
        QByteArray byteIKPublic_B = keyManager.convertPKeyToByteArray(loadedIKPublic_B);
        QByteArray byteOPKPublic_B = keyManager.convertPKeyToByteArray(loadedOPKPublic_B);

        qDebug() << "Public Key Content IK_A:" << byteIKPublic_A;

        QByteArray sharedSecret = keyManager.generateSharedSecret(
            byteIKPublic_A,   // IK_A_Private
            byteEKPublic_A,   // EK_A_Private
            byteIKPublic_B,   // IK_B_Public
            byteSPKPublic_B,  // SPK_B_Public
            byteOPKPublic_B   // OPK_B_Public
            );

        qDebug() << "Shared secret generated successfully.";

        EVP_PKEY_free(loadedIKPublic_A);
        EVP_PKEY_free(loadedEKPublic_A);
        EVP_PKEY_free(loadedSPKPublic_B);
        EVP_PKEY_free(loadedIKPublic_B);
        EVP_PKEY_free(loadedOPKPublic_B);


    } catch (const std::exception &e) {
        qCritical() << "Error:" << e.what();
        return 1;
    }

    return 0;
}

