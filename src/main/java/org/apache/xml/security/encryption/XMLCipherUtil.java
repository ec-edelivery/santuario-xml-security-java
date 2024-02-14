/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.encryption;

import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.keys.content.derivedKey.ConcatKDFParamsImpl;
import org.apache.xml.security.encryption.keys.content.derivedKey.HKDFParamsImpl;
import org.apache.xml.security.encryption.keys.content.derivedKey.KDFParams;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

public final class XMLCipherUtil {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(XMLCipherUtil.class);

    private static final boolean gcmUseIvParameterSpec =
        AccessController.doPrivileged((PrivilegedAction<Boolean>)
            () -> Boolean.getBoolean("org.apache.xml.security.cipher.gcm.useIvParameterSpec"));

    /**
     * Build an <code>AlgorithmParameterSpec</code> instance used to initialize a <code>Cipher</code> instance
     * for block cipher encryption and decryption.
     *
     * @param algorithm the XML encryption algorithm URI
     * @param iv        the initialization vector
     * @return the newly constructed AlgorithmParameterSpec instance, appropriate for the
     * specified algorithm
     */
    public static AlgorithmParameterSpec constructBlockCipherParameters(String algorithm, byte[] iv) {
        if (EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM.equals(algorithm)
                || EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM.equals(algorithm)
                || EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM.equals(algorithm)) {
            return constructBlockCipherParametersForGCMAlgorithm(algorithm, iv);
        } else {
            LOG.debug("Saw non-AES-GCM mode block cipher, returning IvParameterSpec: {}", algorithm);
            return new IvParameterSpec(iv);
        }
    }

    public static AlgorithmParameterSpec constructBlockCipherParameters(boolean gcmAlgorithm, byte[] iv) {
        if (gcmAlgorithm) {
            return constructBlockCipherParametersForGCMAlgorithm("AES/GCM/NoPadding", iv);
        } else {
            LOG.debug("Saw non-AES-GCM mode block cipher, returning IvParameterSpec");
            return new IvParameterSpec(iv);
        }
    }

    private static AlgorithmParameterSpec constructBlockCipherParametersForGCMAlgorithm(String algorithm, byte[] iv) {
        if (gcmUseIvParameterSpec) {
            // This override allows to support Java 1.7+ with (usually older versions of) third-party security
            // providers which support or even require GCM via IvParameterSpec rather than GCMParameterSpec,
            // e.g. BouncyCastle <= 1.49 (really <= 1.50 due to a semi-related bug).
            LOG.debug("Saw AES-GCM block cipher, using IvParameterSpec due to system property override: {}", algorithm);
            return new IvParameterSpec(iv);
        }

        LOG.debug("Saw AES-GCM block cipher, attempting to create GCMParameterSpec: {}", algorithm);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        LOG.debug("Successfully created GCMParameterSpec");
        return gcmSpec;
    }

    /**
     * Method buildOAEPParameters from given parameters and returns OAEPParameterSpec. If encryptionAlgorithmURI is
     * not RSA_OAEP or RSA_OAEP_11, null is returned.
     *
     * @param encryptionAlgorithmURI the encryption algorithm URI (RSA_OAEP or RSA_OAEP_11)
     * @param digestAlgorithmURI     the digest algorithm URI
     * @param mgfAlgorithmURI        the MGF algorithm URI if encryptionAlgorithmURI is RSA_OAEP_11, otherwise parameter is ignored
     * @param oaepParams             the OAEP parameters bytes
     * @return OAEPParameterSpec or null if encryptionAlgorithmURI is not RSA_OAEP or RSA_OAEP_11
     */
    public static OAEPParameterSpec constructOAEPParameters(
            String encryptionAlgorithmURI,
            String digestAlgorithmURI,
            String mgfAlgorithmURI,
            byte[] oaepParams
    ) {
        if (XMLCipher.RSA_OAEP.equals(encryptionAlgorithmURI)
                || XMLCipher.RSA_OAEP_11.equals(encryptionAlgorithmURI)) {

            String jceDigestAlgorithm = "SHA-1";
            if (digestAlgorithmURI != null) {
                jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithmURI);
            }

            PSource.PSpecified pSource = oaepParams == null ?
                    PSource.PSpecified.DEFAULT : new PSource.PSpecified(oaepParams);

            MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
            if (XMLCipher.RSA_OAEP_11.equals(encryptionAlgorithmURI)) {
                mgfParameterSpec = constructMGF1Parameter(mgfAlgorithmURI);
            }
            return new OAEPParameterSpec(jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource);
        }
        return null;
    }

    /**
     * Create MGF1ParameterSpec for the given algorithm URI
     *
     * @param mgh1AlgorithmURI the algorithm URI. If null or empty, SHA-1 is used as default MGF1 digest algorithm.
     * @return the MGF1ParameterSpec for the given algorithm URI
     */
    public static MGF1ParameterSpec constructMGF1Parameter(String mgh1AlgorithmURI) {
        LOG.debug("Creating MGF1ParameterSpec for [{0}]", mgh1AlgorithmURI);
        if (mgh1AlgorithmURI == null || mgh1AlgorithmURI.isEmpty()) {
            LOG.warn("MGF1 algorithm URI is null or empty. Using SHA-1 as default.");
            return new MGF1ParameterSpec("SHA-1");
        }

        switch (mgh1AlgorithmURI) {
            case EncryptionConstants.MGF1_SHA1:
                return new MGF1ParameterSpec("SHA-1");
            case EncryptionConstants.MGF1_SHA224:
                return new MGF1ParameterSpec("SHA-224");
            case EncryptionConstants.MGF1_SHA256:
                return new MGF1ParameterSpec("SHA-256");
            case EncryptionConstants.MGF1_SHA384:
                return new MGF1ParameterSpec("SHA-384");
            case EncryptionConstants.MGF1_SHA512:
                return new MGF1ParameterSpec("SHA-512");
            default:
                LOG.warn("Unsupported MGF algorithm: [{0}] Using SHA-1 as default.", mgh1AlgorithmURI);
                return new MGF1ParameterSpec("SHA-1");
        }
    }

    /**
     * Get the MGF1 algorithm URI for the given MGF1ParameterSpec
     *
     * @param parameterSpec the MGF1ParameterSpec
     * @return the MGF1 algorithm URI for the given MGF1ParameterSpec
     */
    public static String getMgf1URIForParameter(MGF1ParameterSpec parameterSpec) {
        String digestAlgorithm = parameterSpec.getDigestAlgorithm();
        LOG.debug("Get MGF1 URI for digest algorithm [{0}]", digestAlgorithm);
        switch (digestAlgorithm) {
            case "SHA-1":
                return EncryptionConstants.MGF1_SHA1;
            case "SHA-224":
                return EncryptionConstants.MGF1_SHA224;
            case "SHA-256":
                return EncryptionConstants.MGF1_SHA256;
            case "SHA-384":
                return EncryptionConstants.MGF1_SHA384;
            case "SHA-512":
                return EncryptionConstants.MGF1_SHA512;
            default:
                LOG.warn("Unknown hash algorithm: [{0}]  for MGF1", digestAlgorithm);
                return EncryptionConstants.MGF1_SHA1;
        }
    }

    /**
     * Get the JCE hmac algorithm name for the given digest uri
     *
     * @param hmacAlgorithmURI the digest algorithm
     * @return the JCE hmac name algorithm
     * @throws IllegalArgumentException if the digest algorithm is not supported/unknown
     */
    public static String getJCEMacHashForUri(String hmacAlgorithmURI) throws NoSuchAlgorithmException {

        switch (hmacAlgorithmURI) {
            case XMLSignature.ALGO_ID_MAC_HMAC_SHA1:
                return "HmacSHA1";
            case XMLSignature.ALGO_ID_MAC_HMAC_SHA224:
                return "HmacSHA224";
            case XMLSignature.ALGO_ID_MAC_HMAC_SHA256:
                return "HmacSHA256";
            case XMLSignature.ALGO_ID_MAC_HMAC_SHA384:
                return "HmacSHA384";
            case XMLSignature.ALGO_ID_MAC_HMAC_SHA512:
                return "HmacSHA512";
            case XMLSignature.ALGO_ID_MAC_HMAC_RIPEMD160:
                return "HMACRIPEMD160";
            default:
                throw new NoSuchAlgorithmException("Unknown/not supported hash algorithm: [" + hmacAlgorithmURI + "]  for MacHash algorithm");
        }
    }

    /**
     * Construct an KeyAgreementParameterSpec object from the given parameters
     *
     * @param keyWrapAlgoURI         key wrap algorithm
     * @param agreementMethod        agreement method
     * @param keyAgreementPrivateKey private key to derive the shared secret in case of Diffie-Hellman key agreements
     */
    public static KeyAgreementParameters constructRecipientKeyAgreementParameters(String keyWrapAlgoURI,
                                                                                  AgreementMethod agreementMethod,
                                                                                  PrivateKey keyAgreementPrivateKey
    ) throws XMLSecurityException {
        String agreementAlgorithmURI = agreementMethod.getAlgorithm();
        int keyLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgoURI);

        KeyDerivationMethod keyDerivationMethod = agreementMethod.getKeyDerivationMethod();
        if (keyDerivationMethod == null) {
            throw new XMLEncryptionException("Key Derivation Algorithm is not specified");
        }
        KeyDerivationParameters kdp = constructKeyDerivationParameter(keyDerivationMethod, keyLength);

        return constructAgreementParameters(
                agreementAlgorithmURI, KeyAgreementParameters.ActorType.RECIPIENT, kdp,
                keyAgreementPrivateKey, agreementMethod.getOriginatorKeyInfo().getPublicKey());
    }

    /**
     * Construct an KeyAgreementParameterSpec object from the given parameters
     *
     * @param agreementAlgorithmURI  agreement algorithm
     * @param keyDerivationParameter key derivation parameters (e.g. ConcatKDFParams for ConcatKDF key derivation)
     * @param keyAgreementPrivateKey private key to derive the shared secret in case of Diffie-Hellman key agreements
     * @param keyAgreementPublicKey  public key to derive the shared secret in case of Diffie-Hellman key agreements
     */
    public static KeyAgreementParameters constructAgreementParameters(String agreementAlgorithmURI,
                                                                      KeyAgreementParameters.ActorType actorType,
                                                                      KeyDerivationParameters keyDerivationParameter,
                                                                      PrivateKey keyAgreementPrivateKey,
                                                                      PublicKey keyAgreementPublicKey) {
        KeyAgreementParameters ecdhKeyAgreementParameters = new KeyAgreementParameters(
                actorType,
                agreementAlgorithmURI, keyDerivationParameter);
        if (actorType == KeyAgreementParameters.ActorType.RECIPIENT) {
            ecdhKeyAgreementParameters.setRecipientPrivateKey(keyAgreementPrivateKey);
            ecdhKeyAgreementParameters.setOriginatorPublicKey(keyAgreementPublicKey);
        } else {
            ecdhKeyAgreementParameters.setOriginatorPrivateKey(keyAgreementPrivateKey);
            ecdhKeyAgreementParameters.setRecipientPublicKey(keyAgreementPublicKey);
        }

        return ecdhKeyAgreementParameters;
    }

    /**
     * Construct a KeyDerivationParameter object from the given keyDerivationMethod and keyBitLength
     *
     * @param keyDerivationMethod element with the key derivation method data
     * @param keyBitLength  expected derived key length
     * @return KeyDerivationParameters data
     * @throws XMLSecurityException if the keyDerivationMethod is not supported or invalid parameters are provided
     */
    public static KeyDerivationParameters constructKeyDerivationParameter(KeyDerivationMethod keyDerivationMethod, int keyBitLength) throws XMLSecurityException {
        String keyDerivationAlgorithm = keyDerivationMethod.getAlgorithm();
        KDFParams kdfParams = keyDerivationMethod.getKDFParams();
        if (EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF.equals(keyDerivationAlgorithm)) {
            if (! (kdfParams instanceof ConcatKDFParamsImpl)) {
                throw new XMLEncryptionException("KeyDerivation.InvalidParametersType", keyDerivationAlgorithm, ConcatKDFParamsImpl.class.getName());
            }

            ConcatKDFParamsImpl concatKDFParams = (ConcatKDFParamsImpl) kdfParams;

            return constructConcatKeyDerivationParameter(keyBitLength, concatKDFParams.getDigestMethod(), concatKDFParams.getAlgorithmId(),
                    concatKDFParams.getPartyUInfo(), concatKDFParams.getPartyVInfo(),
                    concatKDFParams.getSuppPubInfo(), concatKDFParams.getSuppPrivInfo());

        } else if (EncryptionConstants.ALGO_ID_KEYDERIVATION_HKDF.equals(keyDerivationAlgorithm)) {
            if (! (kdfParams instanceof HKDFParamsImpl)) {

                throw new XMLEncryptionException("KeyDerivation.InvalidParametersType", keyDerivationAlgorithm, HKDFParamsImpl.class.getName());
            }
            HKDFParamsImpl hKDFParams = (HKDFParamsImpl) kdfParams;
            return constructHKDFKeyDerivationParameter(keyBitLength,
                    hKDFParams.getPRFAlgorithm(),
                    hKDFParams.getSalt() != null ? Base64.getDecoder().decode(hKDFParams.getSalt()) : null,
                    hKDFParams.getInfo() != null ? Base64.getDecoder().decode(hKDFParams.getInfo()) : null);
        }
        throw new XMLEncryptionException("unknownAlgorithm", keyDerivationAlgorithm);
    }

    /**
     * Construct a ConcatKeyDerivationParameter object from the given parameters as specified in the XML Encryption 1.1
     * and NIST SP 800-56Ar2 specifications. (In a key establishment transaction, the participants,
     * parties U and V, are considered to be the first and second parties)
     *
     * @param keyBitLength expected derived key length
     * @param digestMethod digest method element identifies the digest algorithm used by the KDF
     * @param algorithmId  algorithm id indicates how the derived keying material will be parsed and for which
     *                     algorithm(s) the derived secret keying material will be used.
     * @param partyUInfo   partyUInfo containing public information about party
     * @param partyVInfo   partyVInfo containing public information about party
     * @param suppPubInfo  suppPubInfo An optional subfield, which could be null that contains additional, mutually
     *                     known public information
     * @param suppPrivInfo suppPrivInfo An optional subfield, which could be null, that contains additional, mutually
     * known private information
     * @return ConcatKeyDerivationParameter parameters used as input to the Concatenation Key Derivation Function
     */
    public static ConcatKDFParams constructConcatKeyDerivationParameter(int keyBitLength,
                                                                        String digestMethod,
                                                                        String algorithmId,
                                                                        String partyUInfo,
                                                                        String partyVInfo,
                                                                        String suppPubInfo,
                                                                        String suppPrivInfo) {

        ConcatKDFParams kdp = new ConcatKDFParams(keyBitLength, digestMethod);
        kdp.setAlgorithmID(algorithmId);
        kdp.setPartyUInfo(partyUInfo);
        kdp.setPartyVInfo(partyVInfo);
        kdp.setSuppPubInfo(suppPubInfo);
        kdp.setSuppPrivInfo(suppPrivInfo);
        return kdp;
    }

    /**
     * Construct a HKDFParams object from the given parameters as specified in the rfc5869 specification.
     *
     * @param keyBitLength The length of the derived key in bits (for example, 128 or 256)
     * @param hmacHashAlgorithm The HMAC hash algorithm to use for the key derivation. If null, the default algorithm
     *                          hmac-sha256 is used.
     * @param salt The salt value (a non-secret random value) used in the key derivation. If parameter is null,
     *             the string of hmac-length zeros is used when deriving the key.
     * @param info The context and application specific information (can be null)
     * @return HKDFParams parameters used as input to the HMAC-based Extract-and-Expand Key Derivation Function.
     */
    public static HKDFParams constructHKDFKeyDerivationParameter(int keyBitLength,
                                                                 String hmacHashAlgorithm,
                                                                 byte[] salt,
                                                                 byte[] info) {
        HKDFParams kdp = new HKDFParams(keyBitLength, hmacHashAlgorithm);
        kdp.setSalt(salt);
        kdp.setInfo(info);
        return kdp;
    }

    /**
     * Method hexStringToByteArray converts hex string to byte array.
     *
     * @param hexString the hex string to convert
     * @return the byte array of the input param, empty array if the hex string is empty, or null if input param is null
     */
    public static byte[] hexStringToByteArray(String hexString) {
        if (hexString == null){
            return null;
        }
        if (hexString.isEmpty()) {
            return new byte[0];
        }
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }
}
