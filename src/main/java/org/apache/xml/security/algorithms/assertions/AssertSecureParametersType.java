package org.apache.xml.security.algorithms.assertions;

import org.apache.xml.security.exceptions.XMLSecurityValidationException;

/**
 * This interface is used to implement asserter that can verify the parameters
 * of a cryptographic algorithm are secure.
 *
 * @param <T> The type of the parameters to be validated
 */
public interface AssertSecureParametersType<T> {
    void assertSecureParameters(T params) throws XMLSecurityValidationException;
    boolean canValidate(Class<?> paramClass);
}
