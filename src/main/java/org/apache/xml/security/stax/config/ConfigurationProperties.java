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
package org.apache.xml.security.stax.config;

import java.util.List;
import java.util.Properties;

import org.apache.xml.security.configuration.PropertiesType;
import org.apache.xml.security.configuration.PropertyType;

/**
 * Configuration Properties
 *
 */
public final class ConfigurationProperties {
    /**
     * Enumeration of Property names supported by the library with their default values
     */
    public enum PropertyNameType {
        MAXIMUM_ALLOWED_TRANSFORMS_PER_REFERENCE("MaximumAllowedTransformsPerReference", "5"),
        MAXIMUM_ALLOWED_REFERENCES_PER_MANIFEST("MaximumAllowedReferencesPerManifest" ,"30"),
        DO_NOT_THROW_EXCEPTION_FOR_MANIFESTS("DoNotThrowExceptionForManifests" ,"false"),
        ALLOW_MD5_ALGORITHM("AllowMD5Algorithm" ,"false"),
        ALLOW_NOT_SAME_DOCUMENT_REFERENCES("AllowNotSameDocumentReferences" ,"false"),
        MAXIMUM_ALLOWED_XML_STRUCTURE_DEPTH("MaximumAllowedXMLStructureDepth" ,"100"),
        MAXIMUM_ALLOWED_ENCRYPTED_DATA_EVENTS("MaximumAllowedEncryptedDataEvents" ,"200"),
        DEFAULT_LANGUAGE_CODE("DefaultLanguageCode" ,"en"),
        DEFAULT_COUNTRY_CODE("DefaultCountryCode" ,"US"),
        SECURITY_VALIDATION_LEVEL("SecurityValidationLevel", "INTERMEDIATE");

        private String name;
        private String defaultValue;

        PropertyNameType(String name, String defaultValue) {
            this.name = name;
            this.defaultValue = defaultValue;
        }

        public String getName() {
            return name;
        }

        public String getDefaultValue() {
            return defaultValue;
        }
    }

    private static Properties properties;
    private static Class<?> callingClass;

    private ConfigurationProperties() {
        super();
    }

    protected static synchronized void init(PropertiesType propertiesType,
            Class<?> callingClass){
        properties = new Properties();
        List<PropertyType> handlerList = propertiesType.getProperty();
        for (PropertyType propertyType : handlerList) {
            properties.setProperty(propertyType.getNAME(), propertyType.getVAL());
        }
        ConfigurationProperties.callingClass = callingClass;
    }

    /**
     * Get the property value for the given key. If the key is not found, the
     * default value is returned.
     * @param key PropertyNameType enum
     * @return property value if defined in configuration else it returns default value for the key
     */
    public static String getProperty(PropertyNameType key) {
        return properties.getProperty(key.getName(), key.getDefaultValue());
    }

    public static String getProperty(String key) {
        return properties.getProperty(key);
    }

    public static Class<?> getCallingClass() {
        return callingClass;
    }
}
