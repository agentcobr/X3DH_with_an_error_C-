#include <main.cpp>

int func() {
    try {

        /*
        KeyPair testKey = keyManager.generateIK();
        keyManager.saveKeys(testKey.privateKey, "test_private.pem");
        QByteArray loadedKey = keyManager.loadKey("test_private.pem");
        EVP_PKEY* privateKey = keyManager.loadPrivateKey(loadedKey);
        if (privateKey) {
            qDebug() << "Private key loaded successfully.";
            EVP_PKEY_free(privateKey);
        }
        */

        /*
        QByteArray savedPrivateKey = keyManager.loadKey("ikA_private.pem");
        EVP_PKEY* testKey = keyManager.loadPrivateKey(savedPrivateKey);
        if (!testKey) {
            qCritical() << "Failed to load saved private key!";
            ERR_print_errors_fp(stderr); // Вывод ошибок OpenSSL
        } else {
            qDebug() << "Successfully loaded saved private key.";
            EVP_PKEY_free(testKey);
        }
        */

        /*
        QByteArray privateKey = generateECKeyPair();
        qDebug() << "Generated EC Private Key:";
        qDebug() << privateKey;
        qDebug() << "Successfully generated EC key pair!";
        */

        /*
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
        keyManager.saveKeys(ek_A.privateKey, "ekA_private.pem");
        keyManager.saveKeys(ek_A.publicKey, "ekA_public.pem");
        keyManager.saveKeys(spk_A.privateKey, "spkA_private.pem");
        keyManager.saveKeys(spk_A.publicKey, "spkA_public.pem");

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
        keyManager.saveKeys(ek_B.privateKey, "ekB_private.pem");
        keyManager.saveKeys(ek_B.publicKey, "ekB_public.pem");
        keyManager.saveKeys(spk_B.privateKey, "spkB_private.pem");
        keyManager.saveKeys(spk_B.publicKey, "spkB_public.pem");

        for (size_t i = 0; i < opks_B.size(); ++i) {
            keyManager.saveKeys(opks_B[i].privateKey, QString("opkB_private_%1.pem").arg(i));
            keyManager.saveKeys(opks_B[i].publicKey, QString("opkB_public_%1.pem").arg(i));
        }

        qDebug() << "All keys generated and saved successfully.";

        EVP_PKEY* loadedIKPrivate_A = keyManager.loadPrivateKey("ikA_private.pem");
        EVP_PKEY* loadedEKPrivate_A = keyManager.loadPrivateKey("ekA_private.pem");

        QByteArray byteIKPrivate_A = keyManager.convertPKeyToByteArray(loadedIKPrivate_A);
        QByteArray byteEKPrivate_A = keyManager.convertPKeyToByteArray(loadedEKPrivate_A);

        EVP_PKEY* loadedSPKPublic_B = keyManager.loadPublicKey("spkB_public.pem");
        EVP_PKEY* loadedIKPublic_B = keyManager.loadPublicKey("ikB_public.pem");
        EVP_PKEY* loadedOPKPublic_B = keyManager.loadPublicKey("opkB_public_0.pem");

        QByteArray byteSPKPublic_B = keyManager.convertPKeyToByteArray(loadedSPKPublic_B);
        QByteArray byteIKPublic_B = keyManager.convertPKeyToByteArray(loadedIKPublic_B);
        QByteArray byteOPKPublic_B = keyManager.convertPKeyToByteArray(loadedOPKPublic_B);

        qDebug() << "Public Key Content IK_A:" << byteIKPrivate_A.toHex();

        QByteArray sharedSecret = keyManager.generateSharedSecret(
            byteIKPrivate_A,   // IK_A_Private
            byteEKPrivate_A,   // EK_A_Private
            byteIKPublic_B,    // IK_B_Public
            byteSPKPublic_B,   // SPK_B_Public
            byteOPKPublic_B    // OPK_B_Public
            );

        qDebug() << "Shared secret generated successfully.";
        */

        FullFunction keyManager;

        KeyPair ik = keyManager.generateKeyPair(); // Ed25519
        keyManager.saveKeys(ik.privateKey, "ik_private.pem");
        keyManager.saveKeys(ik.publicKey, "ik_public.pem");
        qDebug() << "IK generated and saved successfully.";

        KeyPair ek = keyManager.generateKeyPair(); // Ed25519
        keyManager.saveKeys(ek.privateKey, "ek_private.pem");
        keyManager.saveKeys(ek.publicKey, "ek_public.pem");
        qDebug() << "EK generated and saved successfully.";

        KeyPair spk = keyManager.generateSPK(ik.privateKey);
        keyManager.saveKeys(spk.privateKey, "spk_private.pem");
        keyManager.saveKeys(spk.publicKey, "spk_public_signed.pem");
        qDebug() << "SPK generated, signed, and saved successfully.";

        const int opkCount = 5;
        std::vector<KeyPair> opks;
        for (int i = 0; i < opkCount; ++i) {
            KeyPair opk = keyManager.generateKeyPair(); // Ed25519
            keyManager.saveKeys(opk.privateKey, QString("opk_private_%1.pem").arg(i));
            keyManager.saveKeys(opk.publicKey, QString("opk_public_%1.pem").arg(i));
            opks.push_back(opk);
        }
        qDebug() << "OPKs generated and saved successfully.";

        QByteArray loadedSPK = keyManager.loadKey("spk_public_signed.pem");
        QByteArray spkPublicKey = loadedSPK.left(loadedSPK.size() - 64);
        QByteArray spkSignature = loadedSPK.right(64);

        QByteArray loadedIKPublicKey = keyManager.loadKey("ik_public.pem");
        qDebug() << "Loaded IK public successfully.";

    } catch (const std::exception &e) {
        qCritical() << "Error:" << e.what();
        return 1;
    }
    return 0;
}
