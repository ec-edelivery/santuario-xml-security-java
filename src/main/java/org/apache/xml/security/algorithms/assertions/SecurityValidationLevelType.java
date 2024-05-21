package org.apache.xml.security.algorithms.assertions;


/**
 *  {@code SecurityValidationLevelType} is an enumeration of the different security
 *  validation modes/levels. The security validation level can be set to one of the
 *  following:
 *  <ul>
 *      <li><b>PERMISSIVE</b> Permission Mode (Allow all algorithms)
 *      <ul>
 *          <li>In this mode all algorithms can be used, but usage broken/weak
 *          algorithms is logged as error/warning.</li>
 *          <li>This mode is useful for monitoring and understanding which algorithms
 *          are being employed and they should be used only for development purposes!</li>
 *          <li>Mode is used for backward compatibility when Legacy StrictValidation
 *           is not set or is set to false.</li>
 *       </ul></li>
 *     <li><b>INTERMEDIATE</b> Intermediate Mode (Prevent usage of Forbidden Algorithms,
 *     <ul>
 *         <li>In the intermediate stage, you explicitly forbid certain algorithms
 *         but allows potentially weak algorithms</li>
 *         <li>If any forbidden algorithm is used, an error is thrown, and in case
 *         of weak algorithm the the usage is logged with warning.</li>
 *         <li>This helps prevent the use of known insecure or deprecated algorithms but still allows weak algorithms.</li>
 *         <li>Mode is used for backward compatibility when Legacy StrictValidation
 *         is set to true.</li>
 *         </ul></li>
 *     <li><b>STRICT</b> Strict Mode (Prevent usage of Forbidden and potentially weak Algorithms)
 *     <ul>
 *         <li>In the strict mode, you forbid the usage of unsafe and potentially weak algorithms.</li>
 *         <li>It not only forbids unsafe algorithms but also raises an error for potentially unsafe ones.</li>
 *         <li>Algorithms that are considered unsafe due to vulnerabilities or weaknesses fall into this category.</li>
 *     </ul></li>
 * </ul>
 */
public enum SecurityValidationLevelType {
    /*
     * Permission Mode (Allow all algorithms), should be used only for development purposes!
     */
    PERMISSIVE,
    /*
     * Intermediate Mode (Prevent usage of Forbidden Algorithms, but allow potentially weak Algorithms)
     */
    INTERMEDIATE,
    /*
     * Strict Mode (Prevent usage of Forbidden and potentially weak Algorithms)
     */
    STRICT
}
