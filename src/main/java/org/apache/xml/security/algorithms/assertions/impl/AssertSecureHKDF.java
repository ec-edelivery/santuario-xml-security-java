package org.apache.xml.security.algorithms.assertions.impl;

import org.apache.xml.security.algorithms.assertions.AssertSecureParametersType;
import org.apache.xml.security.algorithms.assertions.SecurityAssertions;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.exceptions.XMLSecurityValidationException;

/**
 * Class implements default validation of the HKDF parameters are secure. It
 * checks that the algorithm URI  the HMAC hash algorithm is secure. Optionally
 * it checks that the salt is not null/empty and logs warning in case of
 * INTERMEDIATE security level and throws and error if case of strict validation.
 * .
 */
public class AssertSecureHKDF implements AssertSecureParametersType<HKDFParams> {
    private static final System.Logger LOG = System.getLogger(AssertSecureHKDF.class.getName());

    /**
     * Asserts that the parameters are secure. It checks that the algorithm URI
     * and the HMAC hash algorithm is secure. Optionally it checks that the salt
     * is not null/empty and logs warning in case of INTERMEDIATE security level
     * and throws and error if case of strict validation.
     * @param params The HKDF parameters to be validated
     * @throws XMLSecurityValidationException if the parameters are not secure
     */
    @Override
    public void assertSecureParameters(HKDFParams params) throws XMLSecurityValidationException {
        SecurityAssertions.assertSecureAlgorithmURI(params.getAlgorithm());
        SecurityAssertions.assertSecureAlgorithmURI(params.getHmacHashAlgorithm());
        if (params.getSalt() == null){
            switch (SecurityAssertions.getSecurityValidationLevel()){
                case PERMISSIVE:
                case INTERMEDIATE:
                    LOG.log(System.Logger.Level.WARNING, "Salt is not set for HKDF key derivation");
                    break;
                case STRICT:
                    throw new XMLSecurityValidationException("secureValidation.WeakAlgorithmParameters", params.getAlgorithm(), "Salt");
            }
        }
    }

    /**
     * Checks if the class can validate the parameters.
     * @param paramClass The class type of the object to be validated
     * @return true if the class can be validated, false otherwise
     */
    @Override
    public boolean canValidate(Class paramClass) {
        return HKDFParams.class.isAssignableFrom(paramClass);
    }
}
