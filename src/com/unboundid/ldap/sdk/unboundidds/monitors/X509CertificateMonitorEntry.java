/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2022 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about X.509
 * certificates that are in use by the Directory Server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The set of certificate monitor entries published by the directory server can
 * be obtained using the {@link MonitorManager#getX509CertificateMonitorEntries}
 * method.  Specific methods are available for accessing the associated monitor
 * data (e.g., {@link #getSubjectDN} to retrieve the certificate's subject DN),
 * and there are also methods for accessing this information in a generic manner
 * (e.g., {@link #getMonitorAttributes} to retrieve all of the monitor
 * attributes).  See the {@link MonitorManager} class documentation for an
 * example that demonstrates the use of the generic API for accessing monitor
 * data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class X509CertificateMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in X.509 certificate monitor entries.
   */
  @NotNull static final String X509_CERTIFICATE_MONITOR_OC =
       "ds-x509-certificate-monitor-entry";



  /**
   * The name of the attribute that holds the alias used to identify the
   * certificate in the key store.
   */
  @NotNull private static final String ATTR_ALIAS = "alias";



  /**
   * The name of the attribute that holds the name of the component with which
   * the certificate is associated.
   */
  @NotNull private static final String ATTR_COMPONENT_NAME = "component-name";



  /**
   * The name of the attribute that holds the type of component with which the
   * certificate is associated.
   */
  @NotNull private static final String ATTR_COMPONENT_TYPE = "component-type";



  /**
   * The name of the attribute that holds the context type for the certificate.
   */
  @NotNull private static final String ATTR_CONTEXT_TYPE = "context-type";



  /**
   * The name of the attribute that indicates whether the certificate is
   * currently within its validity time window.
   */
  @NotNull private static final String ATTR_CURRENTLY_VALID = "currently-valid";



  /**
   * The name of the attribute that holds the names of any components that
   * depend on the certificate.
   */
  @NotNull private static final String ATTR_DEPENDENT_COMPONENT =
       "dependent-component";



  /**
   * The name of the attribute that holds a human-readable length of time until
   * the certificate expires.
   */
  @NotNull private static final String
       ATTR_HUMAN_READABLE_TIME_UNTIL_EXPIRATION = "expires";



  /**
   * The name of the attribute that holds the reason that the certificate is
   * considered invalid.
   */
  @NotNull private static final String ATTR_INVALID_REASON = "invalid-reason";



  /**
   * The name of the attribute that holds the issuer certificate's subject DN.
   */
  @NotNull private static final String ATTR_ISSUER_SUBJECT_DN = "issuer";



  /**
   * The name of the attribute that holds the path to the key store file in
   * which the certificate is held.
   */
  @NotNull private static final String ATTR_KEY_STORE_FILE = "keystore-file";



  /**
   * The name of the attribute that holds the type of key store in which the
   * certificate is held.
   */
  @NotNull private static final String ATTR_KEY_STORE_TYPE = "keystore-type";



  /**
   * The name of the attribute that holds the certificate's notAfter timestamp.
   */
  @NotNull private static final String ATTR_NOT_VALID_AFTER = "not-valid-after";



  /**
   * The name of the attribute that holds the certificate's notBefore timestamp.
   */
  @NotNull private static final String ATTR_NOT_VALID_BEFORE =
       "not-valid-before";



  /**
   * The name of the attribute that holds generic property values for the
   * certificate.
   */
  @NotNull private static final String ATTR_PROPERTY = "property";



  /**
   * The name of the attribute that holds type of provider in which the
   * certificate is held.
   */
  @NotNull private static final String ATTR_PROVIDER_TYPE = "provider-type";



  /**
   * The name of the attribute that holds the number of seconds until
   * the certificate expires.
   */
  @NotNull private static final String ATTR_SECONDS_UNTIL_EXPIRATION =
       "expires-seconds";



  /**
   * The name of the attribute that holds the certificate's serial number.
   */
  @NotNull private static final String ATTR_SERIAL_NUMBER = "serial-number";



  /**
   * The name of the attribute that holds the certificate's subject DN.
   */
  @NotNull private static final String ATTR_SUBJECT_DN = "subject";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -750858825553972559L;



  // Indicates whether the certificate is currently within its validity window.
  @Nullable private final Boolean currentlyValid;

  // The notAfter timestamp for the certificate.
  @Nullable private final Date notValidAfter;

  // The notBefore timestamp for the certificate.
  @Nullable private final Date notValidBefore;

  // A list of components that depend on the certificate.
  @NotNull private final List<String> dependentComponents;

  // A list of context-specific properties for the certificate.
  @NotNull private final List<String> properties;

  // The number of seconds until the certificate expires.
  @Nullable private final Long secondsUntilExpiration;

  // The alias used to identify the certificate in the associated key store.
  @Nullable private final String alias;

  // The name of the component with which the certificate is associated.
  @Nullable private final String componentName;

  // The type of the component with which the certificate is associated.
  @Nullable private final String componentType;

  // The type of the context type for the certificate.
  @Nullable private final String contextType;

  // A human-readable length of time until the certificate expires.
  @Nullable private final String humanReadableTimeUntilExpiration;

  // A reason that the certificate is not considered valid.
  @Nullable private final String invalidReason;

  // The subject DN for the certificate's issuer.
  @Nullable private final String issuerSubjectDN;

  // The path to the key store file in which the certificate is held.
  @Nullable private final String keyStoreFile;

  // The type of key store in which the certificate is held.
  @Nullable private final String keyStoreType;

  // The type of provider in which the certificate is held.
  @Nullable private final String providerType;

  // A string representation of the certificate's serial number.
  @Nullable private final String serialNumber;

  // The certificate's subject DN.
  @Nullable private final String subjectDN;



  /**
   * Creates a new X.509 certificate monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as an X.509 certificate monitor
   *                entry.  It must not be {@code null}.
   */
  public X509CertificateMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    subjectDN = getString(ATTR_SUBJECT_DN);
    issuerSubjectDN = getString(ATTR_ISSUER_SUBJECT_DN);
    notValidBefore = getDate(ATTR_NOT_VALID_BEFORE);
    notValidAfter = getDate(ATTR_NOT_VALID_AFTER);
    secondsUntilExpiration = getLong(ATTR_SECONDS_UNTIL_EXPIRATION);
    humanReadableTimeUntilExpiration =
         getString(ATTR_HUMAN_READABLE_TIME_UNTIL_EXPIRATION);
    currentlyValid = getBoolean(ATTR_CURRENTLY_VALID);
    invalidReason = getString(ATTR_INVALID_REASON);
    serialNumber = getString(ATTR_SERIAL_NUMBER);
    contextType = getString(ATTR_CONTEXT_TYPE);
    componentType = getString(ATTR_COMPONENT_TYPE);
    componentName = getString(ATTR_COMPONENT_NAME);
    keyStoreType = getString(ATTR_KEY_STORE_TYPE);
    keyStoreFile = getString(ATTR_KEY_STORE_FILE);
    alias = getString(ATTR_ALIAS);
    providerType = getString(ATTR_PROVIDER_TYPE);
    dependentComponents = getStrings(ATTR_DEPENDENT_COMPONENT);
    properties = getStrings(ATTR_PROPERTY);
  }



  /**
   * Retrieves the subject DN for the certificate.
   *
   * @return  The subject DN for the certificate, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getSubjectDN()
  {
    return subjectDN;
  }



  /**
   * Retrieves the subject DN for the certificate's issuer.
   *
   * @return  The subject DN for the certificate's issuer, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getIssuerSubjectDN()
  {
    return issuerSubjectDN;
  }



  /**
   * Retrieves the earliest time that the certificate should be considered
   * valid.
   *
   * @return  The earliest time that the certificate should be considered valid,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Date getNotValidBefore()
  {
    return notValidBefore;
  }



  /**
   * Retrieves the latest time that the certificate should be considered
   * valid.
   *
   * @return  The latest time that the certificate should be considered valid,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Date getNotValidAfter()
  {
    return notValidAfter;
  }



  /**
   * Retrieves the length of time in seconds until the certificate expires.
   *
   * @return  The length of time in seconds until the certificate expires, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getSecondsUntilExpiration()
  {
    return secondsUntilExpiration;
  }



  /**
   * Retrieves a human-readable representation of the length of time until the
   * certificate expires.
   *
   * @return  A human-readable representation of the length of time until the
   *          certificate expires, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public String getHumanReadableTimeUntilExpiration()
  {
    return humanReadableTimeUntilExpiration;
  }



  /**
   * Indicates whether the certificate is currently within its validity window.
   *
   * @return  {@code Boolean.TRUE} if the certificate is within its validity
   *          window, {@code Boolean.FALSE} if it is outside its validity
   *          window, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Boolean getCurrentlyValid()
  {
    return currentlyValid;
  }



  /**
   * Retrieves the reason that the certificate is considered invalid.
   *
   * @return  The reason that the certificate is considered invalid, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getInvalidReason()
  {
    return invalidReason;
  }



  /**
   * Retrieves a string representation of the certificate's serial number.
   *
   * @return  A string representation of the certificate's serial number, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getSerialNumber()
  {
    return serialNumber;
  }



  /**
   * Retrieves the context in which the certificate is being used.
   *
   * @return  The context in which the certificate is being used, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getContextType()
  {
    return contextType;
  }



  /**
   * Retrieves the type of component with which the certificate is associated.
   *
   * @return  The type of component with which the certificate is associated, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getComponentType()
  {
    return componentType;
  }



  /**
   * Retrieves the name of the component with which the certificate is
   * associated.
   *
   * @return  The name of the component with which the certificate is
   *          associated, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getComponentName()
  {
    return componentName;
  }



  /**
   * Retrieves the type of key store in which the certificate is held.
   *
   * @return  The type of key store in which the certificate is held, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getKeyStoreType()
  {
    return keyStoreType;
  }



  /**
   * Retrieves the path to the key store file in which the certificate is held.
   *
   * @return  The path to the key store file in which the certificate is held,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getKeyStoreFile()
  {
    return keyStoreFile;
  }



  /**
   * Retrieves the alias used to identify the certificate in the key store.
   *
   * @return  The alias used to identify the certificate in the key store, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getAlias()
  {
    return alias;
  }



  /**
   * Retrieves the type of provider in which the certificate is held.
   *
   * @return  The type of provider in which the certificate is held, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getProviderType()
  {
    return providerType;
  }



  /**
   * Retrieves the names of any components that depend on the certificate.
   *
   * @return  The names of any components that depend on the certificate, or an
   *          empty list if it was not included in the monitor entry.
   */
  @NotNull()
  public List<String> getDependentComponents()
  {
    return dependentComponents;
  }



  /**
   * Retrieves a list of context-specific properties for the certificate.
   *
   * @return  A list of context-specific properties for the certificate, or an
   *          empty list if it was not included in the monitor entry.
   */
  @NotNull()
  public List<String> getProperties()
  {
    return properties;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_X509_CERTIFICATE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_X509_CERTIFICATE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs = new LinkedHashMap<>();

    if (subjectDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SUBJECT_DN,
           INFO_X509_CERTIFICATE_DISPNAME_SUBJECT_DN.get(),
           INFO_X509_CERTIFICATE_DESC_SUBJECT_DN.get(),
           subjectDN);
    }

    if (issuerSubjectDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ISSUER_SUBJECT_DN,
           INFO_X509_CERTIFICATE_DISPNAME_ISSUER_DN.get(),
           INFO_X509_CERTIFICATE_DESC_ISSUER_DN.get(),
           issuerSubjectDN);
    }

    if (notValidBefore != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NOT_VALID_BEFORE,
           INFO_X509_CERTIFICATE_DISPNAME_NOT_BEFORE.get(),
           INFO_X509_CERTIFICATE_DESC_NOT_BEFORE.get(),
           notValidBefore);
    }

    if (notValidAfter != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NOT_VALID_AFTER,
           INFO_X509_CERTIFICATE_DISPNAME_NOT_AFTER.get(),
           INFO_X509_CERTIFICATE_DESC_NOT_AFTER.get(),
           notValidAfter);
    }

    if (secondsUntilExpiration != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SECONDS_UNTIL_EXPIRATION,
           INFO_X509_CERTIFICATE_DISPNAME_SECONDS_UNTIL_EXPIRATION.get(),
           INFO_X509_CERTIFICATE_DESC_SECONDS_UNTIL_EXPIRATION.get(),
           secondsUntilExpiration);
    }

    if (humanReadableTimeUntilExpiration != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HUMAN_READABLE_TIME_UNTIL_EXPIRATION,
           INFO_X509_CERTIFICATE_DISPNAME_TIME_UNTIL_EXPIRATION.get(),
           INFO_X509_CERTIFICATE_DESC_TIME_UNTIL_EXPIRATION.get(),
           humanReadableTimeUntilExpiration);
    }

    if (currentlyValid != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENTLY_VALID,
           INFO_X509_CERTIFICATE_DISPNAME_CURRENTLY_VALID.get(),
           INFO_X509_CERTIFICATE_DESC_CURRENTLY_VALID.get(),
           currentlyValid);
    }

    if (invalidReason != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INVALID_REASON,
           INFO_X509_CERTIFICATE_DISPNAME_INVALID_REASON.get(),
           INFO_X509_CERTIFICATE_DESC_INVALID_REASON.get(),
           invalidReason);
    }

    if (serialNumber != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SERIAL_NUMBER,
           INFO_X509_CERTIFICATE_DISPNAME_SERIAL_NUMBER.get(),
           INFO_X509_CERTIFICATE_DESC_SERIAL_NUMBER.get(),
           serialNumber);
    }

    if (contextType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONTEXT_TYPE,
           INFO_X509_CERTIFICATE_DISPNAME_CONTEXT_TYPE.get(),
           INFO_X509_CERTIFICATE_DESC_CONTEXT_TYPE.get(),
           contextType);
    }

    if (componentType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPONENT_TYPE,
           INFO_X509_CERTIFICATE_DISPNAME_COMPONENT_TYPE.get(),
           INFO_X509_CERTIFICATE_DESC_COMPONENT_TYPE.get(),
           componentType);
    }

    if (componentName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPONENT_NAME,
           INFO_X509_CERTIFICATE_DISPNAME_COMPONENT_NAME.get(),
           INFO_X509_CERTIFICATE_DESC_COMPONENT_NAME.get(),
           componentName);
    }

    if (keyStoreType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_KEY_STORE_TYPE,
           INFO_X509_CERTIFICATE_DISPNAME_KEY_STORE_TYPE.get(),
           INFO_X509_CERTIFICATE_DESC_KEY_STORE_TYPE.get(),
           keyStoreType);
    }

    if (keyStoreFile != null)
    {
      addMonitorAttribute(attrs,
           ATTR_KEY_STORE_FILE,
           INFO_X509_CERTIFICATE_DISPNAME_KEY_STORE_FILE.get(),
           INFO_X509_CERTIFICATE_DESC_KEY_STORE_FILE.get(),
           keyStoreFile);
    }

    if (alias != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ALIAS,
           INFO_X509_CERTIFICATE_DISPNAME_ALIAS.get(),
           INFO_X509_CERTIFICATE_DESC_ALIAS.get(),
           alias);
    }

    if (providerType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PROVIDER_TYPE,
           INFO_X509_CERTIFICATE_DISPNAME_PROVIDER_TYPE.get(),
           INFO_X509_CERTIFICATE_DESC_PROVIDER_TYPE.get(),
           providerType);
    }

    if (! dependentComponents.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_DEPENDENT_COMPONENT,
           INFO_X509_CERTIFICATE_DISPNAME_DEPENDENT_COMPONENT.get(),
           INFO_X509_CERTIFICATE_DESC_DEPENDENT_COMPONENT.get(),
           dependentComponents);
    }

    if (! properties.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_PROPERTY,
           INFO_X509_CERTIFICATE_DISPNAME_PROPERTY.get(),
           INFO_X509_CERTIFICATE_DESC_PROPERTY.get(),
           properties);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
