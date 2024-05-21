package org.apache.xml.security.algorithms.assertions;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.assertions.impl.AssertSecureHKDF;
import org.apache.xml.security.algorithms.assertions.impl.AssertSecureKeyAgreementParameters;
import org.apache.xml.security.configuration.DeprecatedAlgorithmURIsType;
import org.apache.xml.security.configuration.SecurityAssertionType;
import org.apache.xml.security.configuration.WeakAlgorithmURIsType;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.exceptions.XMLSecurityValidationException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.I18n;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code SecurityAssertions} is a collection of utility methods that support
 * assertions on algorithms and its properties. These methods are used
 * to validate used signature and encryption algorithms and parameters.
 */
public class SecurityAssertions {
    private static final System.Logger LOG = System.getLogger(SecurityAssertions.class.getName());
    private static List<String> deprecatedAlgorithmURIs = new ArrayList<>();
    private static List<String> weakAlgorithmURIs = new ArrayList<>();
    private static Map<String, List<AssertSecureParametersType>> registeredAssertSecureParameters = new HashMap<>();
    private static int maxReferenceCount = 30;
    private static int maxTransformationCount = 5;

    // default security validation mode is permissive for backward compatibility with previous versions
    private static SecurityValidationLevelType securityValidationMode = SecurityValidationLevelType.INTERMEDIATE;

    /**
     * Initializes the security assertions from the XML configuration.
     *
     * @param securityAssertionConf the security assertion configuration
     */
    public static synchronized void init(SecurityAssertionType securityAssertionConf) {

        DeprecatedAlgorithmURIsType deprecatedAlgorithmURIsType = securityAssertionConf.getDeprecatedAlgorithmURIs();
        if (deprecatedAlgorithmURIsType != null) {
            deprecatedAlgorithmURIsType.getAlgorithmURI().forEach(SecurityAssertions::registerDeprecatedAlgorithm);
        } else {
            LOG.log(System.Logger.Level.WARNING, "No DeprecatedAlgorithmURIsType configured use default deprecated algorithms");
            registerDefaultDeprecatedAlgorithmURIs();
        }

        WeakAlgorithmURIsType weakAlgorithmURIsType = securityAssertionConf.getWeakAlgorithmURIs();
        if (weakAlgorithmURIsType != null) {
            weakAlgorithmURIsType.getAlgorithmURI().forEach(SecurityAssertions::registerWeakAlgorithm);
        } else {
            LOG.log(System.Logger.Level.WARNING, "No WeakAlgorithmURIsType configured use default deprecated algorithms");
            registerDefaultWeakAlgorithmURIs();
        }
    }

    /**
     * Initializes the default security validation configuration.
     */
    public static void initDefaultSecurityValidation() {
        initSecurityValidation(SecurityValidationLevelType.INTERMEDIATE, 30, 5);
        registerDefaultDeprecatedAlgorithmURIs();
        registerDefaultWeakAlgorithmURIs();
        registerDefaultAssertSecureParameters();
    }

    public static void initSecurityValidation(SecurityValidationLevelType securityValidationLevel, int maxReferenceCount, int maxTransformationCount) {
        securityValidationMode = securityValidationLevel;
        SecurityAssertions.maxReferenceCount = maxReferenceCount;
        SecurityAssertions.maxTransformationCount = maxTransformationCount;
    }

    /**
     * Registers the algorithm URI to list of broken algorithms.
     *
     * @param algorithmURI the URI of the broken algorithm
     */
    public static void registerDeprecatedAlgorithm(String algorithmURI) {
        LOG.log(System.Logger.Level.DEBUG, "Try to register deprecated algorithm [{0}]", algorithmURI);
        if (deprecatedAlgorithmURIs.contains(algorithmURI)) {
            return;
        }
        deprecatedAlgorithmURIs.add(algorithmURI);
    }

    /**
     * Registers the algorithm URI to list of weak algorithms.
     *
     * @param algorithmURI the URI of the weak algorithm
     */
    public static void registerWeakAlgorithm(String algorithmURI) {
        LOG.log(System.Logger.Level.DEBUG, "Try to register weak algorithm [{0}]", algorithmURI);
        if (weakAlgorithmURIs.contains(algorithmURI)) {
            return;
        }
        weakAlgorithmURIs.add(algorithmURI);
    }

    /**
     * Registers the default broken algorithm URIs. The broken algorithms are deprecated,
     * must not be used and must be avoided in favor of stronger algorithms.
     */
    public static void registerDefaultDeprecatedAlgorithmURIs() {
        // broken digest algorithms
        deprecatedAlgorithmURIs.clear();
        registerDeprecatedAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        // broken signature algorithms
        registerDeprecatedAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5);
        registerDeprecatedAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5);
        // broken diffie-hellman key agreement
        registerDeprecatedAlgorithm(EncryptionConstants.ALGO_ID_KEYAGREEMENT_DH);
    }

    /**
     * Registers the default weak algorithm URIs. The weak algorithms should be avoided
     * in favor of stronger algorithms. They can be deprecated in future versions of the library.
     * The weak algorithms are logged as warnings in the permissive and intermediate security to
     * inform the user about the potential security risks and sunsetting of the algorithm.
     */
    public static void registerDefaultWeakAlgorithmURIs() {
        weakAlgorithmURIs.clear();
        // weak digest algorithms
        registerWeakAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
        // weak signature algorithms
        registerWeakAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_DSA);
        registerWeakAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_DSA_SHA256);
        registerWeakAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        registerWeakAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        registerWeakAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA224);
        // weak encryption
        // broken encryption algorithms
        registerWeakAlgorithm(XMLCipher.TRIPLEDES);
        registerWeakAlgorithm(XMLCipher.TRIPLEDES_KeyWrap);
        registerWeakAlgorithm(XMLCipher.AES_128);
        registerWeakAlgorithm(XMLCipher.AES_192);
        registerWeakAlgorithm(XMLCipher.AES_256);
        registerWeakAlgorithm(EncryptionConstants.MGF1_SHA1);
        registerWeakAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
    }

    /**
     * Registers the default secure parameters validators for the algorithms.
     */
    public static void registerDefaultAssertSecureParameters() {
        registeredAssertSecureParameters.clear();
        registerAssertSecureParameters(EncryptionConstants.ALGO_ID_KEYDERIVATION_HKDF,
                AssertSecureHKDF.class.getName());
        registerAssertSecureParameters(EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                AssertSecureKeyAgreementParameters.class.getName());
        registerAssertSecureParameters(EncryptionConstants.ALGO_ID_KEYAGREEMENT_X25519,
                AssertSecureKeyAgreementParameters.class.getName());
        registerAssertSecureParameters(EncryptionConstants.ALGO_ID_KEYAGREEMENT_X448,
                AssertSecureKeyAgreementParameters.class.getName());
    }

    /**
     * Registers the AssertSecureParametersType class for the algorithm URI.
     *
     * @param algorithmURI                the URI of the algorithm
     * @param assertSecureParametersClass the class of the AssertSecureParametersType
     */
    public static void registerAssertSecureParameters(String algorithmURI, String assertSecureParametersClass) {
        try {
            AssertSecureParametersType assertSecureParameters = (AssertSecureParametersType)
                    Class.forName(assertSecureParametersClass).getDeclaredConstructor().newInstance();
            registerAssertSecureParameters(algorithmURI, assertSecureParameters);
        } catch (Exception e) {
            LOG.log(System.Logger.Level.ERROR, "Error registering AssertSecureParametersType", e);
        }
    }

    /**
     * Registers the AssertSecureParametersType for the algorithm URI.
     * @param algorithmURI the URI of the algorithm which is using the parameters
     * @param assertSecureParameters the AssertSecureParametersType instance to validate the parameters
     */
    public static void registerAssertSecureParameters(String algorithmURI, AssertSecureParametersType assertSecureParameters) {
        if (!registeredAssertSecureParameters.containsKey(algorithmURI)) {
            registeredAssertSecureParameters.put(algorithmURI, new ArrayList<>());
        }
        registeredAssertSecureParameters.get(algorithmURI).add(assertSecureParameters);
    }

    /**
     * Asserts that the algorithm URI is secure. If the algorithm is not secure, the behavior
     *
     * @param algorithmURI the URI of the algorithm to be validated
     * @throws XMLSecurityException if the algorithm is not secure
     */
    public static void assertSecureAlgorithmURI(String algorithmURI) throws XMLSecurityValidationException {
        assertSecureAlgorithmURI(securityValidationMode, algorithmURI);
    }

    /**
     * Asserts that the JCE name algorithm is secure. If the algorithm is not secure, the behavior
     *
     * @param securityValidationLevel security validation level to be used for the assertion
     * @param algorithmURI            the URI of the algorithm to be validated
     * @throws XMLSecurityException if the algorithm is not secure
     */
    public static void assertSecureAlgorithmURI(SecurityValidationLevelType securityValidationLevel, String algorithmURI) throws XMLSecurityValidationException {

        if (algorithmURI == null) {
            LOG.log(System.Logger.Level.WARNING, I18n.translate("secureValidation.NullAlgorithm"));
            return;
        }
        if (deprecatedAlgorithmURIs.contains(algorithmURI)) {
            handleBrokenAlgorithmURI(securityValidationLevel, algorithmURI);
        }
        if (weakAlgorithmURIs.contains(algorithmURI)) {
            handleWeakAlgorithmURI(securityValidationLevel, algorithmURI);
        }
    }

    /**
     * Handles the broken algorithm. The behavior depends on the security validation
     * securityValidationMode {@link org.apache.xml.security.algorithms.assertions.SecurityValidationLevelType}. In the permissive mode,
     * the broken algorithm is logged as a warning. In the intermediate and strict mode,
     * an XMLSecurityException is thrown.
     *
     * @param securityValidationLevel security validation level
     * @param algorithmURI            the URI of the broken algorithm
     * @throws XMLSecurityException if the security validation mode is intermediate or strict
     */
    private static void handleBrokenAlgorithmURI(SecurityValidationLevelType securityValidationLevel, String algorithmURI) throws XMLSecurityValidationException {
        String message = I18n.translate("secureValidation.BrokenAlgorithm", new Object[]{algorithmURI});
        switch (securityValidationLevel) {
            case PERMISSIVE:
                // log warning
                LOG.log(System.Logger.Level.WARNING, message);
                break;
            case INTERMEDIATE:
            case STRICT:
                throw new XMLSecurityValidationException(message);
        }
    }

    /**
     * Handles the weak algorithm. The behavior depends on the security validation mode.
     * In the permissive and intermediate mode {@link org.apache.xml.security.algorithms.assertions.SecurityValidationLevelType} the
     * weak algorithm is logged as a warning. In the strict mode, an XMLSecurityException is thrown.
     *
     * @param securityValidationLevel security validation level
     * @param algorithmURI            the URI of the weak algorithm
     * @throws XMLSecurityException if the security validation mode is strict
     */
    private static void handleWeakAlgorithmURI(SecurityValidationLevelType securityValidationLevel, String algorithmURI) throws XMLSecurityValidationException {
        String message = I18n.translate("secureValidation.WeakAlgorithm", new Object[]{algorithmURI});
        switch (securityValidationLevel) {
            case PERMISSIVE:
            case INTERMEDIATE:
                // log warning
                LOG.log(System.Logger.Level.WARNING, message);
                break;
            case STRICT:
                throw new XMLSecurityValidationException("secureValidation.WeakAlgorithm", algorithmURI);
        }
    }


    /**
     * Asserts that the reference count is within the allowed range, using the
     * default security validation level.
     *
     * @param iCount
     */
    public static void assertReferenceCount(int iCount) throws XMLSecurityValidationException {
        assertReferenceCount(securityValidationMode, iCount);
    }

    /**
     * Asserts that the reference count is within the allowed range.
     *
     * @param securityValidationLevel security validation level to be used for the assertion
     * @param iCount                  the number of references
     */
    public static void assertReferenceCount(SecurityValidationLevelType securityValidationLevel, int iCount) throws XMLSecurityValidationException {
        if (maxReferenceCount < iCount) {
            return;
        }
        switch (securityValidationLevel) {
            case PERMISSIVE:
                // log warning
                LOG.log(System.Logger.Level.WARNING, I18n.translate("secureValidation.InvalidReferenceCount", new Object[]{iCount, maxReferenceCount}));
                break;
            case INTERMEDIATE:
            case STRICT:
                throw new XMLSecurityValidationException("secureValidation.InvalidReferenceCount", iCount, maxReferenceCount);
        }
    }

    /**
     * Asserts that the transformations count in a reference is within the allowed range, using the
     * default security validation level.
     *
     * @param iCount the number of transformations
     */
    public static void assertTransformationCount(int iCount) throws XMLSecurityValidationException {
        assertTransformationCount(securityValidationMode, iCount);
    }

    /**
     * Asserts that the transformations count in a reference is within the allowed range.
     *
     * @param securityValidationLevel security validation level to be used for the assertion
     * @param iCount                  the number of transformations
     */
    public static void assertTransformationCount(SecurityValidationLevelType securityValidationLevel, int iCount) throws XMLSecurityValidationException {
        if (maxTransformationCount < iCount) {
            return;
        }
        switch (securityValidationMode) {
            case PERMISSIVE:
                // log warning
                LOG.log(System.Logger.Level.WARNING, I18n.translate("secureValidation.InvalidTransformationCount", new Object[]{iCount, maxTransformationCount}));
                break;
            case INTERMEDIATE:
            case STRICT:
                throw new XMLSecurityValidationException("secureValidation.InvalidTransformationCount", iCount, maxTransformationCount);
        }
    }

    /**
     * Returns if DTD processing is allowed due to default security validation level.
     */
    public static boolean allowDTDProcessing() {
        // default security validation mode is permissive for backward compatibility with previous versions
        return securityValidationMode == SecurityValidationLevelType.PERMISSIVE;
    }

    public static SecurityValidationLevelType getSecurityValidationLevel() {
        return securityValidationMode;
    }

    /**
     * Method  validates if any of registered parameter type security assertion classes
     * can validate the given parameters of the algorithm URI and parameter class. If it
     * exists it will call the assertSecureParameters method of the registered class.
     *
     * @param algorithmURI the URI of the algorithm
     * @param parameters   the parameters to be validated
     * @throws XMLSecurityValidationException if the parameter configuration  is not secure
     */
    public static void assertSecureAlgorithmParameters(String algorithmURI, Object parameters) throws XMLSecurityValidationException {
        List<AssertSecureParametersType> assertSecureParameters = registeredAssertSecureParameters.get(algorithmURI);
        if (assertSecureParameters == null || assertSecureParameters.isEmpty()) {
            LOG.log(System.Logger.Level.DEBUG, "No AssertSecureParametersType registered for algorithm [{0}]", algorithmURI);
            return;
        }
        for (AssertSecureParametersType assertSecureParameter : assertSecureParameters) {
            if (assertSecureParameter.canValidate(parameters.getClass())) {
                assertSecureParameter.assertSecureParameters(parameters);
            }
        }
    }
}
