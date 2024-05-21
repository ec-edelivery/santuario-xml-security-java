package org.apache.xml.security.algorithms.assertions.impl;

import org.apache.xml.security.algorithms.assertions.AssertSecureParametersType;
import org.apache.xml.security.algorithms.assertions.SecurityAssertions;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.exceptions.XMLSecurityValidationException;

/**
 * Class implements default validation of the HKDF parameters are secure. It
 * checks that the algorithm URI  the HMAC hash algorithm is secure. Optionally
 * it checks that the salt is not null/empty and logs warning in case of
 * INTERMEDIATE security level and throws and error if case of strictk validation.
 * .
 */
public class AssertSecureKeyAgreementParameters implements AssertSecureParametersType<KeyAgreementParameters> {
    private static final System.Logger LOG = System.getLogger(AssertSecureKeyAgreementParameters.class.getName());

    @Override
    public void assertSecureParameters(KeyAgreementParameters params) throws XMLSecurityValidationException {
        SecurityAssertions.assertSecureAlgorithmURI(params.getKeyAgreementAlgorithm());
        KeyDerivationParameters kdp = params.getKeyDerivationParameter();
        if (kdp!=null) {
            LOG.log(System.Logger.Level.DEBUG, "Assert security for the KeyDerivationParameters");
            SecurityAssertions.assertSecureAlgorithmURI(kdp.getAlgorithm());
        }
    }

    @Override
    public boolean canValidate(Class paramClass) {
        return KeyAgreementParameters.class.isAssignableFrom(paramClass);
    }
}
