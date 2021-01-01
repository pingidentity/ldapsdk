/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;

import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a simple data structure with information that may be
 * used to control the behavior of an {@link InMemoryDirectoryServer} instance.
 * At least one base DN must be specified.  For all other properties, the
 * following default values will be used unless an alternate configuration is
 * provided:
 * <UL>
 *   <LI>Listeners:  The server will provide a single listener that will use an
 *       automatically-selected port on all interfaces, which will not use SSL
 *       or StartTLS.</LI>
 *   <LI>Allowed Operation Types:  All types of operations will be allowed.</LI>
 *   <LI>Authentication Required Operation Types:  Authentication will not be
 *       required for any types of operations.</LI>
 *   <LI>Schema:  The server will use a schema with a number of standard
 *       attribute types and object classes.</LI>
 *   <LI>Additional Bind Credentials:  The server will not have any additional
 *       bind credentials.</LI>
 *   <LI>Referential Integrity Attributes:  Referential integrity will not be
 *       maintained.</LI>
 *   <LI>Generate Operational Attributes:  The server will automatically
 *       generate a number of operational attributes.</LI>
 *   <LI>Extended Operation Handlers:  The server will support the password
 *       modify extended operation as defined in RFC 3062, the start and end
 *       transaction extended operations as defined in RFC 5805, and the
 *       "Who Am I?" extended operation as defined in RFC 4532.</LI>
 *   <LI>SASL Bind Handlers:  The server will support the SASL PLAIN mechanism
 *       as defined in RFC 4616.</LI>
 *   <LI>Max ChangeLog Entries:  The server will not provide an LDAP
 *       changelog.</LI>
 *   <LI>Access Log Handler:  The server will not perform any access
 *       logging.</LI>
 *   <LI>Code Log Handler:  The server will not perform any code logging.</LI>
 *   <LI>LDAP Debug Log Handler:  The server will not perform any LDAP debug
 *       logging.</LI>
 *   <LI>Listener Exception Handler:  The server will not use a listener
 *       exception handler.</LI>
 *   <LI>Maximum Size Limit:  The server will not enforce a maximum search size
 *       limit.</LI>
 *   <LI>Password Attributes:  The server will use userPassword as the only
 *       password attribute.</LI>
 *   <LI>Password Encoders:  The server will not use any password encoders by
 *       default, so passwords will remain in clear text.</LI>
 * </UL>
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class InMemoryDirectoryServerConfig
{
  // Indicates whether to enforce the requirement that attribute values comply
  // with the associated attribute syntax.
  private boolean enforceAttributeSyntaxCompliance;

  // Indicates whether to enforce the requirement that entries contain exactly
  // one structural object class.
  private boolean enforceSingleStructuralObjectClass;

  // Indicates whether to automatically generate operational attributes.
  private boolean generateOperationalAttributes;

  // Indicates whether the code log should include sample code for processing
  // the requests.
  private boolean includeRequestProcessingInCodeLog;

  // The base DNs to use for the LDAP listener.
  @NotNull private DN[] baseDNs;

  // The log handler that should be used to record access log messages about
  // operations processed by the server.
  @Nullable private Handler accessLogHandler;

  // The log handler that should be used to record JSON-formatted access log
  // messages about operations processed by the server.
  @Nullable private Handler jsonAccessLogHandler;

  // The log handler that should be used to record detailed protocol-level
  // messages about LDAP operations processed by the server.
  @Nullable private Handler ldapDebugLogHandler;

  // The password encoder that will be used to encode new clear-text passwords.
  @Nullable private InMemoryPasswordEncoder primaryPasswordEncoder;

  // The maximum number of entries to retain in a generated changelog.
  private int maxChangeLogEntries;

  // The maximum number of concurrent connections that will be allowed.
  private int maxConnections;

  // The maximum size in bytes for encoded messages that the server will accept.
  private int maxMessageSizeBytes;

  // The maximum number of entries that may be returned in any single search
  // operation.
  private int maxSizeLimit;

  // The exception handler that should be used for the listener.
  @Nullable private LDAPListenerExceptionHandler exceptionHandler;

  // A set of custom attributes that should be included in the root DSE.
  @NotNull private List<Attribute> customRootDSEAttributes;

  // The extended operation handlers that may be used to process extended
  // operations in the server.
  @NotNull private final List<InMemoryExtendedOperationHandler>
       extendedOperationHandlers;

  // The listener configurations that should be used for accepting connections
  // to the server.
  @NotNull private final List<InMemoryListenerConfig> listenerConfigs;

  // The operation interceptors that should be used with the in-memory directory
  // server.
  @NotNull private final List<InMemoryOperationInterceptor>
       operationInterceptors;

  // A list of secondary password encoders that will be used to interact with
  // existing pre-encoded passwords, but will not be used to encode new
  // passwords.
  @NotNull private final List<InMemoryPasswordEncoder>
       secondaryPasswordEncoders;

  // The SASL bind handlers that may be used to process SASL bind requests in
  // the server.
  @NotNull private final List<InMemorySASLBindHandler> saslBindHandlers;

  // The names or OIDs of the attributes for which to maintain equality indexes.
  @NotNull private final List<String> equalityIndexAttributes;

  // A set of additional credentials that can be used for binding without
  // requiring a corresponding entry in the data set.
  @NotNull private final Map<DN,byte[]> additionalBindCredentials;

  // The entry to use for the server root DSE.
  @Nullable private ReadOnlyEntry rootDSEEntry;

  // The schema to use for the server.
  @Nullable private Schema schema;

  // The set of operation types that will be supported by the server.
  @NotNull private final Set<OperationType> allowedOperationTypes;

  // The set of operation types for which authentication will be required.
  @NotNull private final Set<OperationType>
       authenticationRequiredOperationTypes;

  // The set of attributes for which referential integrity should be maintained.
  @NotNull private final Set<String> referentialIntegrityAttributes;

  // The set of attributes that will hold user passwords.
  @NotNull private final Set<String> passwordAttributes;

  // The path to a file that should be written with code that may be used to
  // issue the requests received by the server.
  @Nullable private String codeLogPath;

  // The vendor name to report in the server root DSE.
  @Nullable private String vendorName;

  // The vendor version to report in the server root DSE.
  @Nullable private String vendorVersion;



  /**
   * Creates a new in-memory directory server config object with the provided
   * set of base DNs.
   *
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DN strings is null or
   *                         empty, or if any of the provided base DN strings
   *                         cannot be parsed as a valid DN.
   */
  public InMemoryDirectoryServerConfig(@NotNull final String... baseDNs)
         throws LDAPException
  {
    this(parseDNs(Schema.getDefaultStandardSchema(), baseDNs));
  }



  /**
   * Creates a new in-memory directory server config object with the default
   * settings.
   *
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DNs is null or empty.
   */
  public InMemoryDirectoryServerConfig(@NotNull final DN... baseDNs)
         throws LDAPException
  {
    if ((baseDNs == null) || (baseDNs.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NO_BASE_DNS.get());
    }

    this.baseDNs = baseDNs;

    listenerConfigs = new ArrayList<>(1);
    listenerConfigs.add(InMemoryListenerConfig.createLDAPConfig("default"));

    additionalBindCredentials            =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    accessLogHandler                     = null;
    jsonAccessLogHandler                 = null;
    ldapDebugLogHandler                  = null;
    enforceAttributeSyntaxCompliance     = true;
    enforceSingleStructuralObjectClass   = true;
    generateOperationalAttributes        = true;
    maxChangeLogEntries                  = 0;
    maxConnections                       = 0;
    maxMessageSizeBytes = LDAPListenerConfig.DEFAULT_MAX_MESSAGE_SIZE_BYTES;
    maxSizeLimit                         = 0;
    exceptionHandler                     = null;
    customRootDSEAttributes              = Collections.emptyList();
    equalityIndexAttributes              = new ArrayList<>(10);
    rootDSEEntry                         = null;
    schema                               = Schema.getDefaultStandardSchema();
    allowedOperationTypes                = EnumSet.allOf(OperationType.class);
    authenticationRequiredOperationTypes = EnumSet.noneOf(OperationType.class);
    referentialIntegrityAttributes       = new HashSet<>(0);
    vendorName                           = "Ping Identity Corporation";
    vendorVersion                        = Version.FULL_VERSION_STRING;
    codeLogPath                          = null;
    includeRequestProcessingInCodeLog    = false;

    operationInterceptors = new ArrayList<>(5);

    extendedOperationHandlers = new ArrayList<>(3);
    extendedOperationHandlers.add(new PasswordModifyExtendedOperationHandler());
    extendedOperationHandlers.add(new TransactionExtendedOperationHandler());
    extendedOperationHandlers.add(new WhoAmIExtendedOperationHandler());

    saslBindHandlers = new ArrayList<>(1);
    saslBindHandlers.add(new PLAINBindHandler());

    passwordAttributes = new LinkedHashSet<>(StaticUtils.computeMapCapacity(5));
    passwordAttributes.add("userPassword");

    primaryPasswordEncoder = null;

    secondaryPasswordEncoders = new ArrayList<>(5);
  }



  /**
   * Creates a new in-memory directory server config object that is a duplicate
   * of the provided config and may be altered without impacting the state of
   * the given config object.
   *
   * @param  cfg  The in-memory directory server config object for to be
   *              duplicated.
   */
  public InMemoryDirectoryServerConfig(
              @NotNull final InMemoryDirectoryServerConfig cfg)
  {
    baseDNs = new DN[cfg.baseDNs.length];
    System.arraycopy(cfg.baseDNs, 0, baseDNs, 0, baseDNs.length);

    listenerConfigs = new ArrayList<>(cfg.listenerConfigs);

    operationInterceptors = new ArrayList<>(cfg.operationInterceptors);

    extendedOperationHandlers = new ArrayList<>(cfg.extendedOperationHandlers);

    saslBindHandlers = new ArrayList<>(cfg.saslBindHandlers);

    additionalBindCredentials =
         new LinkedHashMap<>(cfg.additionalBindCredentials);

    referentialIntegrityAttributes =
         new HashSet<>(cfg.referentialIntegrityAttributes);

    allowedOperationTypes = EnumSet.noneOf(OperationType.class);
    allowedOperationTypes.addAll(cfg.allowedOperationTypes);

    authenticationRequiredOperationTypes = EnumSet.noneOf(OperationType.class);
    authenticationRequiredOperationTypes.addAll(
         cfg.authenticationRequiredOperationTypes);

    equalityIndexAttributes = new ArrayList<>(cfg.equalityIndexAttributes);

    enforceAttributeSyntaxCompliance   = cfg.enforceAttributeSyntaxCompliance;
    enforceSingleStructuralObjectClass = cfg.enforceSingleStructuralObjectClass;
    generateOperationalAttributes      = cfg.generateOperationalAttributes;
    accessLogHandler                   = cfg.accessLogHandler;
    jsonAccessLogHandler               = cfg.jsonAccessLogHandler;
    ldapDebugLogHandler                = cfg.ldapDebugLogHandler;
    maxChangeLogEntries                = cfg.maxChangeLogEntries;
    maxConnections                     = cfg.maxConnections;
    maxMessageSizeBytes                = cfg.maxMessageSizeBytes;
    maxSizeLimit                       = cfg.maxSizeLimit;
    exceptionHandler                   = cfg.exceptionHandler;
    customRootDSEAttributes            = cfg.customRootDSEAttributes;
    rootDSEEntry                       = cfg.rootDSEEntry;
    schema                             = cfg.schema;
    vendorName                         = cfg.vendorName;
    vendorVersion                      = cfg.vendorVersion;
    codeLogPath                        = cfg.codeLogPath;
    includeRequestProcessingInCodeLog  = cfg.includeRequestProcessingInCodeLog;
    primaryPasswordEncoder             = cfg.primaryPasswordEncoder;

    passwordAttributes = new LinkedHashSet<>(cfg.passwordAttributes);

    secondaryPasswordEncoders = new ArrayList<>(cfg.secondaryPasswordEncoders);
  }



  /**
   * Retrieves the set of base DNs that should be used for the directory server.
   *
   * @return  The set of base DNs that should be used for the directory server.
   */
  @NotNull()
  public DN[] getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * Specifies the set of base DNs that should be used for the directory server.
   *
   * @param  baseDNs  The set of base DNs that should be used for the directory
   *                  server.  It must not be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DN strings is null or
   *                         empty, or if any of the provided base DN strings
   *                         cannot be parsed as a valid DN.
   */
  public void setBaseDNs(@NotNull final String... baseDNs)
         throws LDAPException
  {
    setBaseDNs(parseDNs(schema, baseDNs));
  }



  /**
   * Specifies the set of base DNs that should be used for the directory server.
   *
   * @param  baseDNs  The set of base DNs that should be used for the directory
   *                  server.  It must not be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DNs is null or empty.
   */
  public void setBaseDNs(@NotNull final DN... baseDNs)
         throws LDAPException
  {
    if ((baseDNs == null) || (baseDNs.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NO_BASE_DNS.get());
    }

    this.baseDNs = baseDNs;
  }



  /**
   * Retrieves the list of listener configurations that should be used for the
   * directory server.
   *
   * @return  The list of listener configurations that should be used for the
   *          directory server.
   */
  @NotNull()
  public List<InMemoryListenerConfig> getListenerConfigs()
  {
    return listenerConfigs;
  }



  /**
   * Specifies the configurations for all listeners that should be used for the
   * directory server.
   *
   * @param  listenerConfigs  The configurations for all listeners that should
   *                          be used for the directory server.  It must not be
   *                          {@code null} or empty, and it must not contain
   *                          multiple configurations with the same name.
   *
   * @throws  LDAPException  If there is a problem with the provided set of
   *                         listener configurations.
   */
  public void setListenerConfigs(
                   @NotNull final InMemoryListenerConfig... listenerConfigs)
         throws LDAPException
  {
    setListenerConfigs(StaticUtils.toList(listenerConfigs));
  }



  /**
   * Specifies the configurations for all listeners that should be used for the
   * directory server.
   *
   * @param  listenerConfigs  The configurations for all listeners that should
   *                          be used for the directory server.  It must not be
   *                          {@code null} or empty, and it must not contain
   *                          multiple configurations with the same name.
   *
   * @throws  LDAPException  If there is a problem with the provided set of
   *                         listener configurations.
   */
  public void setListenerConfigs(
              @NotNull final Collection<InMemoryListenerConfig> listenerConfigs)
         throws LDAPException
  {
    if ((listenerConfigs == null) || listenerConfigs.isEmpty())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NO_LISTENERS.get());
    }

    final HashSet<String> listenerNames =
         new HashSet<>(StaticUtils.computeMapCapacity(listenerConfigs.size()));
    for (final InMemoryListenerConfig c : listenerConfigs)
    {
      final String name = StaticUtils.toLowerCase(c.getListenerName());
      if (listenerNames.contains(name))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MEM_DS_CFG_CONFLICTING_LISTENER_NAMES.get(name));
      }
      else
      {
        listenerNames.add(name);
      }
    }

    this.listenerConfigs.clear();
    this.listenerConfigs.addAll(listenerConfigs);
  }



  /**
   * Retrieves the set of operation types that will be allowed by the server.
   * Note that if the server is configured to support StartTLS, then it will be
   * allowed even if other types of extended operations are not allowed.
   *
   * @return  The set of operation types that will be allowed by the server.
   */
  @NotNull()
  public Set<OperationType> getAllowedOperationTypes()
  {
    return allowedOperationTypes;
  }



  /**
   * Specifies the set of operation types that will be allowed by the server.
   * Note that if the server is configured to support StartTLS, then it will be
   * allowed even if other types of extended operations are not allowed.
   *
   * @param  operationTypes  The set of operation types that will be allowed by
   *                         the server.
   */
  public void setAllowedOperationTypes(
                   @Nullable final OperationType... operationTypes)
  {
    allowedOperationTypes.clear();
    if (operationTypes != null)
    {
      allowedOperationTypes.addAll(Arrays.asList(operationTypes));
    }
  }



  /**
   * Specifies the set of operation types that will be allowed by the server.
   * Note that if the server is configured to support StartTLS, then it will be
   * allowed even if other types of extended operations are not allowed.
   *
   * @param  operationTypes  The set of operation types that will be allowed by
   *                         the server.
   */
  public void setAllowedOperationTypes(
                   @Nullable final Collection<OperationType> operationTypes)
  {
    allowedOperationTypes.clear();
    if (operationTypes != null)
    {
      allowedOperationTypes.addAll(operationTypes);
    }
  }



  /**
   * Retrieves the set of operation types that will only be allowed for
   * authenticated clients.  Note that authentication will never be required for
   * bind operations, and if the server is configured to support StartTLS, then
   * authentication will never be required for StartTLS operations even if it
   * is required for other types of extended operations.
   *
   * @return  The set of operation types that will only be allowed for
   *          authenticated clients.
   */
  @NotNull()
  public Set<OperationType> getAuthenticationRequiredOperationTypes()
  {
    return authenticationRequiredOperationTypes;
  }



  /**
   * Specifies the set of operation types that will only be allowed for
   * authenticated clients.  Note that authentication will never be required for
   * bind operations, and if the server is configured to support StartTLS, then
   * authentication will never be required for StartTLS operations even if it
   * is required for other types of extended operations.
   *
   * @param  operationTypes  The set of operation types that will be allowed for
   *                         authenticated clients.
   */
  public void setAuthenticationRequiredOperationTypes(
                   @Nullable final OperationType... operationTypes)
  {
    authenticationRequiredOperationTypes.clear();
    if (operationTypes != null)
    {
      authenticationRequiredOperationTypes.addAll(
           Arrays.asList(operationTypes));
    }
  }



  /**
   * Specifies the set of operation types that will only be allowed for
   * authenticated clients.  Note that authentication will never be required for
   * bind operations, and if the server is configured to support StartTLS, then
   * authentication will never be required for StartTLS operations even if it
   * is required for other types of extended operations.
   *
   * @param  operationTypes  The set of operation types that will be allowed for
   *                         authenticated clients.
   */
  public void setAuthenticationRequiredOperationTypes(
                   @Nullable final Collection<OperationType> operationTypes)
  {
    authenticationRequiredOperationTypes.clear();
    if (operationTypes != null)
    {
      authenticationRequiredOperationTypes.addAll(operationTypes);
    }
  }



  /**
   * Retrieves a map containing DNs and passwords of additional users that will
   * be allowed to bind to the server, even if their entries do not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * The map that is returned may be altered if desired.
   *
   * @return  A map containing DNs and passwords of additional users that will
   *          be allowed to bind to the server, even if their entries do not
   *          exist in the data set.
   */
  @NotNull()
  public Map<DN,byte[]> getAdditionalBindCredentials()
  {
    return additionalBindCredentials;
  }



  /**
   * Adds an additional bind DN and password combination that can be used to
   * bind to the server, even if the corresponding entry does not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * If a password has already been defined for the given DN, then it will be
   * replaced with the newly-supplied password.
   *
   * @param  dn        The bind DN to allow.  It must not be {@code null} or
   *                   represent the null DN.
   * @param  password  The password for the provided bind DN.  It must not be
   *                   {@code null} or empty.
   *
   * @throws  LDAPException  If there is a problem with the provided bind DN or
   *                         password.
   */
  public void addAdditionalBindCredentials(@NotNull final String dn,
                                           @NotNull final String password)
         throws LDAPException
  {
    addAdditionalBindCredentials(dn, StaticUtils.getBytes(password));
  }



  /**
   * Adds an additional bind DN and password combination that can be used to
   * bind to the server, even if the corresponding entry does not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * If a password has already been defined for the given DN, then it will be
   * replaced with the newly-supplied password.
   *
   * @param  dn        The bind DN to allow.  It must not be {@code null} or
   *                   represent the null DN.
   * @param  password  The password for the provided bind DN.  It must not be
   *                   {@code null} or empty.
   *
   * @throws  LDAPException  If there is a problem with the provided bind DN or
   *                         password.
   */
  public void addAdditionalBindCredentials(@NotNull final String dn,
                                           @NotNull final byte[] password)
         throws LDAPException
  {
    if (dn == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_DN.get());
    }

    final DN parsedDN = new DN(dn, schema);
    if (parsedDN.isNullDN())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_DN.get());
    }

    if ((password == null) || (password.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_PW.get());
    }

    additionalBindCredentials.put(parsedDN, password);
  }



  /**
   * Retrieves the object that should be used to handle any errors encountered
   * while attempting to interact with a client, if defined.
   *
   * @return  The object that should be used to handle any errors encountered
   *          while attempting to interact with a client, or {@code null} if no
   *          exception handler should be used.
   */
  @Nullable()
  public LDAPListenerExceptionHandler getListenerExceptionHandler()
  {
    return exceptionHandler;
  }



  /**
   * Specifies the LDAP listener exception handler that the server should use to
   * handle any errors encountered while attempting to interact with a client.
   *
   * @param  exceptionHandler  The LDAP listener exception handler that the
   *                           server should use to handle any errors
   *                           encountered while attempting to interact with a
   *                           client.  It may be {@code null} if no exception
   *                           handler should be used.
   */
  public void setListenerExceptionHandler(
              @Nullable final LDAPListenerExceptionHandler exceptionHandler)
  {
    this.exceptionHandler = exceptionHandler;
  }



  /**
   * Retrieves the schema that should be used by the server, if defined.  If a
   * schema is defined, then it will be used to validate entries and determine
   * which matching rules should be used for various types of matching
   * operations.
   *
   * @return  The schema that should be used by the server, or {@code null} if
   *          no schema should be used.
   */
  @Nullable()
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * Specifies the schema that should be used by the server.  If a schema is
   * defined, then it will be used to validate entries and determine which
   * matching rules should be used for various types of matching operations.
   *
   * @param  schema  The schema that should be used by the server.  It may be
   *                 {@code null} if no schema should be used.
   */
  public void setSchema(@Nullable final Schema schema)
  {
    this.schema = schema;
  }



  /**
   * Indicates whether the server should reject attribute values which violate
   * the constraints of the associated syntax.  This setting will be ignored if
   * a {@code null} schema is in place.
   *
   * @return  {@code true} if the server should reject attribute values which
   *          violate the constraints of the associated syntax, or {@code false}
   *          if not.
   */
  public boolean enforceAttributeSyntaxCompliance()
  {
    return enforceAttributeSyntaxCompliance;
  }



  /**
   * Specifies whether the server should reject attribute values which violate
   * the constraints of the associated syntax.  This setting will be ignored if
   * a {@code null} schema is in place.
   *
   * @param  enforceAttributeSyntaxCompliance  Indicates whether the server
   *                                           should reject attribute values
   *                                           which violate the constraints of
   *                                           the associated syntax.
   */
  public void setEnforceAttributeSyntaxCompliance(
                   final boolean enforceAttributeSyntaxCompliance)
  {
    this.enforceAttributeSyntaxCompliance = enforceAttributeSyntaxCompliance;
  }



  /**
   * Indicates whether the server should reject entries which do not contain
   * exactly one structural object class.  This setting will be ignored if a
   * {@code null} schema is in place.
   *
   * @return  {@code true} if the server should reject entries which do not
   *          contain exactly one structural object class, or {@code false} if
   *          it should allow entries which do not have any structural class or
   *          that have multiple structural classes.
   */
  public boolean enforceSingleStructuralObjectClass()
  {
    return enforceSingleStructuralObjectClass;
  }



  /**
   * Specifies whether the server should reject entries which do not contain
   * exactly one structural object class.  This setting will be ignored if a
   * {@code null} schema is in place.
   *
   * @param  enforceSingleStructuralObjectClass  Indicates whether the server
   *                                             should reject entries which do
   *                                             not contain exactly one
   *                                             structural object class.
   */
  public void setEnforceSingleStructuralObjectClass(
                   final boolean enforceSingleStructuralObjectClass)
  {
    this.enforceSingleStructuralObjectClass =
         enforceSingleStructuralObjectClass;
  }



  /**
   * Retrieves the log handler that should be used to record access log messages
   * about operations processed by the server, if any.
   *
   * @return  The log handler that should be used to record access log messages
   *          about operations processed by the server, or {@code null} if no
   *          access logging should be performed.
   */
  @Nullable()
  public Handler getAccessLogHandler()
  {
    return accessLogHandler;
  }



  /**
   * Specifies the log handler that should be used to record access log messages
   * about operations processed by the server.
   *
   * @param  accessLogHandler  The log handler that should be used to record
   *                           access log messages about operations processed by
   *                           the server.  It may be {@code null} if no access
   *                           logging should be performed.
   */
  public void setAccessLogHandler(@Nullable final Handler accessLogHandler)
  {
    this.accessLogHandler = accessLogHandler;
  }



  /**
   * Retrieves the log handler that should be used to record JSON-formatted
   * access log messages about operations processed by the server, if any.
   *
   * @return  The log handler that should be used to record JSON-formatted
   *          access log messages about operations processed by the server, or
   *          {@code null} if no access logging should be performed.
   */
  @Nullable()
  public Handler getJSONAccessLogHandler()
  {
    return jsonAccessLogHandler;
  }



  /**
   * Specifies the log handler that should be used to record JSON-formatted
   * access log messages about operations processed by the server.
   *
   * @param  jsonAccessLogHandler  The log handler that should be used to record
   *                               JSON-formatted access log messages about
   *                               operations processed by the server.  It may
   *                               be {@code null} if no access logging should
   *                               be performed.
   */
  public void setJSONAccessLogHandler(
                   @Nullable final Handler jsonAccessLogHandler)
  {
    this.jsonAccessLogHandler = jsonAccessLogHandler;
  }



  /**
   * Retrieves the log handler that should be used to record detailed messages
   * about LDAP communication to and from the server, which may be useful for
   * debugging purposes.
   *
   * @return  The log handler that should be used to record detailed
   *          protocol-level debug messages about LDAP communication to and from
   *          the server, or {@code null} if no debug logging should be
   *          performed.
   */
  @Nullable()
  public Handler getLDAPDebugLogHandler()
  {
    return ldapDebugLogHandler;
  }



  /**
   * Specifies the log handler that should be used to record detailed messages
   * about LDAP communication to and from the server, which may be useful for
   * debugging purposes.
   *
   * @param  ldapDebugLogHandler  The log handler that should be used to record
   *                              detailed messages about LDAP communication to
   *                              and from the server.  It may be {@code null}
   *                              if no LDAP debug logging should be performed.
   */
  public void setLDAPDebugLogHandler(
                   @Nullable final Handler ldapDebugLogHandler)
  {
    this.ldapDebugLogHandler = ldapDebugLogHandler;
  }



  /**
   * Retrieves the path to a file to be written with generated code that may
   * be used to construct the requests processed by the server.
   *
   * @return  The path to a file to be written with generated code that may be
   *          used to construct the requests processed by the server, or
   *          {@code null} if no code log should be written.
   */
  @Nullable()
  public String getCodeLogPath()
  {
    return codeLogPath;
  }



  /**
   * Indicates whether the code log should include sample code for processing
   * the generated requests.  This will only be used if {@link #getCodeLogPath}
   * returns a non-{@code null} value.
   *
   * @return  {@code false} if the code log should only include code that
   *          corresponds to requests received from clients, or {@code true} if
   *          the code log should also include sample code for processing the
   *          generated requests and interpreting the results.
   */
  public boolean includeRequestProcessingInCodeLog()
  {
    return includeRequestProcessingInCodeLog;
  }



  /**
   * Specifies information about code logging that should be performed by the
   * server, if any.
   *
   * @param  codeLogPath        The path to the file to which a code log should
   *                            be written.  It may be {@code null} if no code
   *                            log should be written.
   * @param  includeProcessing  Indicates whether to include sample code that
   *                            demonstrates how to process the requests and
   *                            interpret the results.  This will only be
   *                            used if the {@code codeLogPath} argument is
   *                            non-{@code null}.
   */
  public void setCodeLogDetails(@Nullable final String codeLogPath,
                                final boolean includeProcessing)
  {
    this.codeLogPath = codeLogPath;
    includeRequestProcessingInCodeLog = includeProcessing;
  }



  /**
   * Retrieves a list of the operation interceptors that may be used to
   * intercept and transform requests before they are processed by the in-memory
   * directory server, and/or to intercept and transform responses before they
   * are returned to the client.  The contents of the list may be altered by the
   * caller.
   *
   * @return  An updatable list of the operation interceptors that may be used
   *          to intercept and transform requests and/or responses.
   */
  @NotNull()
  public List<InMemoryOperationInterceptor> getOperationInterceptors()
  {
    return operationInterceptors;
  }



  /**
   * Adds the provided operation interceptor to the list of operation
   * interceptors that may be used to transform requests before they are
   * processed by the in-memory directory server, and/or to transform responses
   * before they are returned to the client.
   *
   * @param  interceptor  The operation interceptor that should be invoked in
   *                      the course of processing requests and responses.
   */
  public void addInMemoryOperationInterceptor(
                   @NotNull final InMemoryOperationInterceptor interceptor)
  {
    operationInterceptors.add(interceptor);
  }



  /**
   * Retrieves a list of the extended operation handlers that may be used to
   * process extended operations in the server.  The contents of the list may
   * be altered by the caller.
   *
   * @return  An updatable list of the extended operation handlers that may be
   *          used to process extended operations in the server.
   */
  @NotNull()
  public List<InMemoryExtendedOperationHandler> getExtendedOperationHandlers()
  {
    return extendedOperationHandlers;
  }



  /**
   * Adds the provided extended operation handler for use by the server for
   * processing certain types of extended operations.
   *
   * @param  handler  The extended operation handler that should be used by the
   *                  server for processing certain types of extended
   *                  operations.
   */
  public void addExtendedOperationHandler(
                   @NotNull final InMemoryExtendedOperationHandler handler)
  {
    extendedOperationHandlers.add(handler);
  }



  /**
   * Retrieves a list of the SASL bind handlers that may be used to process
   * SASL bind requests in the server.  The contents of the list may be altered
   * by the caller.
   *
   * @return  An updatable list of the SASL bind handlers that may be used to
   *          process SASL bind requests in the server.
   */
  @NotNull()
  public List<InMemorySASLBindHandler> getSASLBindHandlers()
  {
    return saslBindHandlers;
  }



  /**
   * Adds the provided SASL bind handler for use by the server for processing
   * certain types of SASL bind requests.
   *
   * @param  handler  The SASL bind handler that should be used by the server
   *                  for processing certain types of SASL bind requests.
   */
  public void addSASLBindHandler(@NotNull final InMemorySASLBindHandler handler)
  {
    saslBindHandlers.add(handler);
  }



  /**
   * Indicates whether the server should automatically generate operational
   * attributes (including entryDN, entryUUID, creatorsName, createTimestamp,
   * modifiersName, modifyTimestamp, and subschemaSubentry) for entries in the
   * server.
   *
   * @return  {@code true} if the server should automatically generate
   *          operational attributes for entries in the server, or {@code false}
   *          if not.
   */
  public boolean generateOperationalAttributes()
  {
    return generateOperationalAttributes;
  }



  /**
   * Specifies whether the server should automatically generate operational
   * attributes (including entryDN, entryUUID, creatorsName, createTimestamp,
   * modifiersName, modifyTimestamp, and subschemaSubentry) for entries in the
   * server.
   *
   * @param  generateOperationalAttributes  Indicates whether the server should
   *                                        automatically generate operational
   *                                        attributes for entries in the
   *                                        server.
   */
  public void setGenerateOperationalAttributes(
                   final boolean generateOperationalAttributes)
  {
    this.generateOperationalAttributes = generateOperationalAttributes;
  }



  /**
   * Retrieves the maximum number of changelog entries that the server should
   * maintain.
   *
   * @return  The maximum number of changelog entries that the server should
   *          maintain, or 0 if the server should not maintain a changelog.
   */
  public int getMaxChangeLogEntries()
  {
    return maxChangeLogEntries;
  }



  /**
   * Specifies the maximum number of changelog entries that the server should
   * maintain.  A value less than or equal to zero indicates that the server
   * should not attempt to maintain a changelog.
   *
   * @param  maxChangeLogEntries  The maximum number of changelog entries that
   *                              the server should maintain.
   */
  public void setMaxChangeLogEntries(final int maxChangeLogEntries)
  {
    if (maxChangeLogEntries < 0)
    {
      this.maxChangeLogEntries = 0;
    }
    else
    {
      this.maxChangeLogEntries = maxChangeLogEntries;
    }
  }



  /**
   * Retrieves the maximum number of concurrent connections that the server will
   * allow.  If a client tries to establish a new connection while the server
   * already has the maximum number of concurrent connections, then the new
   * connection will be rejected.  Note that if the server is configured with
   * multiple listeners, then each listener will be allowed to have up to this
   * number of connections.
   *
   * @return  The maximum number of concurrent connections that the server will
   *          allow, or zero if no limit should be enforced.
   */
  public int getMaxConnections()
  {
    return maxConnections;
  }



  /**
   * Specifies the maximum number of concurrent connections that the server will
   * allow.  If a client tries to establish a new connection while the server
   * already has the maximum number of concurrent connections, then the new
   * connection will be rejected.  Note that if the server is configured with
   * multiple listeners, then each listener will be allowed to have up to this
   * number of connections.
   *
   * @param  maxConnections  The maximum number of concurrent connections that
   *                         the server will allow.  A value that is less than
   *                         or equal to zero indicates no limit.
   */
  public void setMaxConnections(final int maxConnections)
  {
    if (maxConnections > 0)
    {
      this.maxConnections = maxConnections;
    }
    else
    {
      this.maxConnections = 0;
    }
  }



  /**
   * Retrieves the maximum size in bytes for LDAP messages that will be accepted
   * by the server.
   *
   * @return  The maximum size in bytes for LDAP messages that will be accepted
   *          by the server.
   */
  public int getMaxMessageSizeBytes()
  {
    return maxMessageSizeBytes;
  }



  /**
   * Specifies the maximum size in bytes for LDAP messages that will be accepted
   * by the server.
   *
   * @param  maxMessageSizeBytes  The maximum size in bytes for LDAP messages
   *                              that will be accepted by the server.  A
   *                              value that is less than or equal to zero will
   *                              use the maximum allowed message size.
   */
  public void setMaxMessageSizeBytes(final int maxMessageSizeBytes)
  {
    if (maxMessageSizeBytes > 0)
    {
      this.maxMessageSizeBytes = maxMessageSizeBytes;
    }
    else
    {
      this.maxMessageSizeBytes = Integer.MAX_VALUE;
    }
  }



  /**
   * Retrieves the maximum number of entries that the server should return in
   * any search operation.
   *
   * @return  The maximum number of entries that the server should return in any
   *          search operation, or zero if no limit should be enforced.
   */
  public int getMaxSizeLimit()
  {
    return maxSizeLimit;
  }



  /**
   * Specifies the maximum number of entries that the server should return in
   * any search operation.  A value less than or equal to zero indicates that no
   * maximum limit should be enforced.
   *
   * @param  maxSizeLimit  The maximum number of entries that the server should
   *                       return in any search operation.
   */
  public void setMaxSizeLimit(final int maxSizeLimit)
  {
    if (maxSizeLimit > 0)
    {
      this.maxSizeLimit = maxSizeLimit;
    }
    else
    {
      this.maxSizeLimit = 0;
    }
  }



  /**
   * Retrieves a list containing the names or OIDs of the attribute types for
   * which to maintain an equality index to improve the performance of certain
   * kinds of searches.
   *
   * @return  A list containing the names or OIDs of the attribute types for
   *          which to maintain an equality index to improve the performance of
   *          certain kinds of searches, or an empty list if no equality indexes
   *          should be created.
   */
  @NotNull()
  public List<String> getEqualityIndexAttributes()
  {
    return equalityIndexAttributes;
  }



  /**
   * Specifies the names or OIDs of the attribute types for which to maintain an
   * equality index to improve the performance of certain kinds of searches.
   *
   * @param  equalityIndexAttributes  The names or OIDs of the attributes for
   *                                  which to maintain an equality index to
   *                                  improve the performance of certain kinds
   *                                  of searches.  It may be {@code null} or
   *                                  empty to indicate that no equality indexes
   *                                  should be maintained.
   */
  public void setEqualityIndexAttributes(
                   @Nullable final String... equalityIndexAttributes)
  {
    setEqualityIndexAttributes(StaticUtils.toList(equalityIndexAttributes));
  }



  /**
   * Specifies the names or OIDs of the attribute types for which to maintain an
   * equality index to improve the performance of certain kinds of searches.
   *
   * @param  equalityIndexAttributes  The names or OIDs of the attributes for
   *                                  which to maintain an equality index to
   *                                  improve the performance of certain kinds
   *                                  of searches.  It may be {@code null} or
   *                                  empty to indicate that no equality indexes
   *                                  should be maintained.
   */
  public void setEqualityIndexAttributes(
                   @Nullable final Collection<String> equalityIndexAttributes)
  {
    this.equalityIndexAttributes.clear();
    if (equalityIndexAttributes != null)
    {
      this.equalityIndexAttributes.addAll(equalityIndexAttributes);
    }
  }



  /**
   * Retrieves the names of the attributes for which referential integrity
   * should be maintained.  If referential integrity is to be provided and an
   * entry is removed, then any other entries containing one of the specified
   * attributes with a value equal to the DN of the entry that was removed, then
   * that value will also be removed.  Similarly, if an entry is moved or
   * renamed, then any references to that entry in one of the specified
   * attributes will be updated to reflect the new DN.
   *
   * @return  The names of the attributes for which referential integrity should
   *          be maintained, or an empty set if referential integrity should not
   *          be maintained for any attributes.
   */
  @NotNull()
  public Set<String> getReferentialIntegrityAttributes()
  {
    return referentialIntegrityAttributes;
  }



  /**
   * Specifies the names of the attributes for which referential integrity
   * should be maintained.  If referential integrity is to be provided and an
   * entry is removed, then any other entries containing one of the specified
   * attributes with a value equal to the DN of the entry that was removed, then
   * that value will also be removed.  Similarly, if an entry is moved or
   * renamed, then any references to that entry in one of the specified
   * attributes will be updated to reflect the new DN.
   *
   * @param  referentialIntegrityAttributes  The names of the attributes for
   *                                          which referential integrity should
   *                                          be maintained.  The values of
   *                                          these attributes should be DNs.
   *                                          It may be {@code null} or empty if
   *                                          referential integrity should not
   *                                          be maintained.
   */
  public void setReferentialIntegrityAttributes(
                   @Nullable final String... referentialIntegrityAttributes)
  {
    setReferentialIntegrityAttributes(
         StaticUtils.toList(referentialIntegrityAttributes));
  }



  /**
   * Specifies the names of the attributes for which referential integrity
   * should be maintained.  If referential integrity is to be provided and an
   * entry is removed, then any other entries containing one of the specified
   * attributes with a value equal to the DN of the entry that was removed, then
   * that value will also be removed.  Similarly, if an entry is moved or
   * renamed, then any references to that entry in one of the specified
   * attributes will be updated to reflect the new DN.
   *
   * @param  referentialIntegrityAttributes  The names of the attributes for
   *                                          which referential integrity should
   *                                          be maintained.  The values of
   *                                          these attributes should be DNs.
   *                                          It may be {@code null} or empty if
   *                                          referential integrity should not
   *                                          be maintained.
   */
  public void setReferentialIntegrityAttributes(
              @Nullable final Collection<String> referentialIntegrityAttributes)
  {
    this.referentialIntegrityAttributes.clear();
    if (referentialIntegrityAttributes != null)
    {
      this.referentialIntegrityAttributes.addAll(
           referentialIntegrityAttributes);
    }
  }



  /**
   * Retrieves the vendor name value to report in the server root DSE.
   *
   * @return  The vendor name value to report in the server root DSE, or
   *          {@code null} if no vendor name should appear.
   */
  @Nullable()
  public String getVendorName()
  {
    return vendorName;
  }



  /**
   * Specifies the vendor name value to report in the server root DSE.
   *
   * @param  vendorName  The vendor name value to report in the server root DSE.
   *                     It may be {@code null} if no vendor name should appear.
   */
  public void setVendorName(@Nullable final String vendorName)
  {
    this.vendorName = vendorName;
  }



  /**
   * Retrieves the vendor version value to report in the server root DSE.
   *
   * @return  The vendor version value to report in the server root DSE, or
   *          {@code null} if no vendor version should appear.
   */
  @Nullable()
  public String getVendorVersion()
  {
    return vendorVersion;
  }



  /**
   * Specifies the vendor version value to report in the server root DSE.
   *
   * @param  vendorVersion  The vendor version value to report in the server
   *                        root DSE.  It may be {@code null} if no vendor
   *                        version should appear.
   */
  public void setVendorVersion(@Nullable final String vendorVersion)
  {
    this.vendorVersion = vendorVersion;
  }



  /**
   * Retrieves a predefined entry that should always be returned as the
   * in-memory directory server's root DSE, if defined.
   *
   * @return  A predefined entry that should always be returned as the in-memory
   *          directory server's root DSE, or {@code null} if the root DSE
   *          should be dynamically generated.
   */
  @Nullable()
  public ReadOnlyEntry getRootDSEEntry()
  {
    return rootDSEEntry;
  }



  /**
   * Specifies an entry that should always be returned as the in-memory
   * directory server's root DSE.  Note that if a specific root DSE entry is
   * provided, then the generated root DSE will not necessarily accurately
   * reflect the capabilities of the server, nor will it be dynamically updated
   * as operations are processed.  As an alternative, the
   * {@link #setCustomRootDSEAttributes} method may be used to specify custom
   * attributes that should be included in the root DSE entry while still having
   * the server generate dynamic values for other attributes.  If both a root
   * DSE entry and a custom set of root DSE attributes are specified, then the
   * root DSE entry will take precedence.
   *
   * @param  rootDSEEntry  An entry that should always be returned as the
   *                       in-memory directory server's root DSE, or
   *                       {@code null} to indicate that the root DSE should be
   *                       dynamically generated.
   */
  public void setRootDSEEntry(@Nullable final Entry rootDSEEntry)
  {
    if (rootDSEEntry == null)
    {
      this.rootDSEEntry = null;
      return;
    }

    final Entry e = rootDSEEntry.duplicate();
    e.setDN("");
    this.rootDSEEntry = new ReadOnlyEntry(e);
  }



  /**
   * Retrieves a list of custom attributes that should be included in the root
   * DSE that is dynamically generated by the in-memory directory server.
   *
   * @return  A list of custom attributes that will be included in the root DSE
   *          that is generated by the in-memory directory server, or an empty
   *          list if none should be included.
   */
  @NotNull()
  public List<Attribute> getCustomRootDSEAttributes()
  {
    return customRootDSEAttributes;
  }



  /**
   * Specifies a list of custom attributes that should be included in the root
   * DSE that is dynamically generated by the in-memory directory server.  Note
   * that this list of attributes will not be used if the
   * {@link #setRootDSEEntry} method is used to override the entire entry.  Also
   * note that any attributes provided in this list will override those that
   * would be dynamically generated by the in-memory directory server.
   *
   * @param  customRootDSEAttributes  A list of custom attributes that should
   *                                  be included in the root DSE that is
   *                                  dynamically generated by the in-memory
   *                                  directory server.  It may be {@code null}
   *                                  or empty if no custom attributes should be
   *                                  included in the root DSE.
   */
  public void setCustomRootDSEAttributes(
                   @Nullable final List<Attribute> customRootDSEAttributes)
  {
    if (customRootDSEAttributes == null)
    {
      this.customRootDSEAttributes = Collections.emptyList();
    }
    else
    {
      this.customRootDSEAttributes = Collections.unmodifiableList(
           new ArrayList<>(customRootDSEAttributes));
    }
  }



  /**
   * Retrieves an unmodifiable set containing the names or OIDs of the
   * attributes that may hold passwords.  These are the attributes whose values
   * will be used in bind processing, and clear-text values stored in these
   * attributes may be encoded using an {@link InMemoryPasswordEncoder}.
   *
   * @return  An unmodifiable set containing the names or OIDs of the attributes
   *          that may hold passwords, or an empty set if no password attributes
   *          have been defined.
   */
  @NotNull()
  public Set<String> getPasswordAttributes()
  {
    return Collections.unmodifiableSet(passwordAttributes);
  }



  /**
   * Specifies the names or OIDs of the attributes that may hold passwords.
   * These are the attributes whose values will be used in bind processing, and
   * clear-text values stored in these attributes may be encoded using an
   * {@link InMemoryPasswordEncoder}.
   *
   * @param  passwordAttributes  The names or OIDs of the attributes that may
   *                             hold passwords.  It may be {@code null} or
   *                             empty if there should not be any password
   *                             attributes, but that will prevent user
   *                             authentication from succeeding.
   */
  public void setPasswordAttributes(
                   @Nullable final String... passwordAttributes)
  {
    setPasswordAttributes(StaticUtils.toList(passwordAttributes));
  }



  /**
   * Specifies the names or OIDs of the attributes that may hold passwords.
   * These are the attributes whose values will be used in bind processing, and
   * clear-text values stored in these attributes may be encoded using an
   * {@link InMemoryPasswordEncoder}.
   *
   * @param  passwordAttributes  The names or OIDs of the attributes that may
   *                             hold passwords.  It may be {@code null} or
   *                             empty if there should not be any password
   *                             attributes, but that will prevent user
   *                             authentication from succeeding.
   */
  public void setPasswordAttributes(
                   @Nullable final Collection<String> passwordAttributes)
  {
    this.passwordAttributes.clear();

    if (passwordAttributes != null)
    {
      this.passwordAttributes.addAll(passwordAttributes);
    }
  }



  /**
   * Retrieves the primary password encoder for the in-memory directory server,
   * if any.  The primary password encoder will be used to encode the values of
   * any clear-text passwords provided in add or modify operations and in LDIF
   * imports, and will also be used during authentication processing for any
   * encoded passwords that start with the same prefix as this password encoder.
   *
   * @return  The primary password encoder for the in-memory directory server,
   *          or {@code null} if clear-text passwords should be left in the
   *          clear without any encoding.
   */
  @Nullable()
  public InMemoryPasswordEncoder getPrimaryPasswordEncoder()
  {
    return primaryPasswordEncoder;
  }



  /**
   * Retrieves an unmodifiable map of the secondary password encoders for the
   * in-memory directory server, indexed by prefix.  The secondary password
   * encoders will be used to interact with pre-encoded passwords, but will not
   * be used to encode new clear-text passwords.
   *
   * @return  An unmodifiable map of the secondary password encoders for the
   *          in-memory directory server, or an empty map if no secondary
   *          encoders are defined.
   */
  @NotNull()
  public List<InMemoryPasswordEncoder> getSecondaryPasswordEncoders()
  {
    return Collections.unmodifiableList(secondaryPasswordEncoders);
  }



  /**
   * Specifies the set of password encoders to use for the in-memory directory
   * server.  There must not be any conflicts between the prefixes used for any
   * of the password encoders (that is, none of the secondary password encoders
   * may use the same prefix as the primary password encoder or the same prefix
   * as any other secondary password encoder).
   * <BR><BR>
   * Either or both the primary and secondary encoders may be left undefined.
   * If both primary and secondary encoders are left undefined, then the server
   * will assume that all passwords are in the clear.  If only a primary encoder
   * is configured without any secondary encoders, then the server will encode
   * all new passwords that don't start with its prefix.  If only secondary
   * encoders are configured without a primary encoder, then all new passwords
   * will be left in the clear, but any existing pre-encoded passwords using
   * those mechanisms will be handled properly.
   *
   * @param  primaryEncoder     The primary password encoder to use for the
   *                            in-memory directory server.  This encoder will
   *                            be used to encode any new clear-text passwords
   *                            that are provided to the server in add or modify
   *                            operations or in LDIF imports.  It will also be
   *                            used to interact with pre-encoded passwords
   *                            for any encoded passwords that start with the
   *                            same prefix as this password encoder.  It may be
   *                            {@code null} if no password encoder is desired
   *                            and clear-text passwords should remain in the
   *                            clear.
   * @param  secondaryEncoders  The secondary password encoders to use when
   *                            interacting with pre-encoded passwords, but that
   *                            will not be used to encode new clear-text
   *                            passwords.  This may be {@code null} or empty if
   *                            no secondary password encoders are needed.
   *
   * @throws  LDAPException  If there is a conflict between the prefixes used by
   *                         two or more of the provided encoders.
   */
  public void setPasswordEncoders(
                   @Nullable final InMemoryPasswordEncoder primaryEncoder,
                   @Nullable final InMemoryPasswordEncoder... secondaryEncoders)
         throws LDAPException
  {
    setPasswordEncoders(primaryEncoder, StaticUtils.toList(secondaryEncoders));
  }



  /**
   * Specifies the set of password encoders to use for the in-memory directory
   * server.  There must not be any conflicts between the prefixes used for any
   * of the password encoders (that is, none of the secondary password encoders
   * may use the same prefix as the primary password encoder or the same prefix
   * as any other secondary password encoder).
   * <BR><BR>
   * Either or both the primary and secondary encoders may be left undefined.
   * If both primary and secondary encoders are left undefined, then the server
   * will assume that all passwords are in the clear.  If only a primary encoder
   * is configured without any secondary encoders, then the server will encode
   * all new passwords that don't start with its prefix.  If only secondary
   * encoders are configured without a primary encoder, then all new passwords
   * will be left in the clear, but any existing pre-encoded passwords using
   * those mechanisms will be handled properly.
   *
   * @param  primaryEncoder     The primary password encoder to use for the
   *                            in-memory directory server.  This encoder will
   *                            be used to encode any new clear-text passwords
   *                            that are provided to the server in add or modify
   *                            operations or in LDIF imports.  It will also be
   *                            used to interact with pre-encoded passwords
   *                            for any encoded passwords that start with the
   *                            same prefix as this password encoder.  It may be
   *                            {@code null} if no password encoder is desired
   *                            and clear-text passwords should remain in the
   *                            clear.
   * @param  secondaryEncoders  The secondary password encoders to use when
   *                            interacting with pre-encoded passwords, but that
   *                            will not be used to encode new clear-text
   *                            passwords.  This may be {@code null} or empty if
   *                            no secondary password encoders are needed.
   *
   * @throws  LDAPException  If there is a conflict between the prefixes used by
   *                         two or more of the provided encoders.
   */
  public void setPasswordEncoders(
       @Nullable final InMemoryPasswordEncoder primaryEncoder,
       @Nullable final Collection<InMemoryPasswordEncoder> secondaryEncoders)
         throws LDAPException
  {
    // Before applying the change, make sure that there aren't any conflicts in
    // their prefixes.
    final LinkedHashMap<String,InMemoryPasswordEncoder> newEncoderMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    if (primaryEncoder != null)
    {
      newEncoderMap.put(primaryEncoder.getPrefix(), primaryEncoder);
    }

    if (secondaryEncoders != null)
    {
      for (final InMemoryPasswordEncoder encoder : secondaryEncoders)
      {
        if (newEncoderMap.containsKey(encoder.getPrefix()))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MEM_DS_CFG_PW_ENCODER_CONFLICT.get(encoder.getPrefix()));
        }
        else
        {
          newEncoderMap.put(encoder.getPrefix(), encoder);
        }
      }
    }

    primaryPasswordEncoder = primaryEncoder;

    if (primaryEncoder != null)
    {
      newEncoderMap.remove(primaryEncoder.getPrefix());
    }

    secondaryPasswordEncoders.clear();
    secondaryPasswordEncoders.addAll(newEncoderMap.values());
  }



  /**
   * Parses the provided set of strings as DNs.
   *
   * @param  schema     The schema to use to generate the normalized
   *                    representations of the DNs, if available.
   * @param  dnStrings  The array of strings to be parsed as DNs.
   *
   * @return  The array of parsed DNs, or {@code null} if the provided array of
   *          DNs was {@code null}.
   *
   * @throws  LDAPException  If any of the provided strings cannot be parsed as
   *                         DNs.
   */
  @Nullable()
  private static DN[] parseDNs(@Nullable final Schema schema,
                               @Nullable final String... dnStrings)
          throws LDAPException
  {
    if (dnStrings == null)
    {
      return null;
    }

    final DN[] dns = new DN[dnStrings.length];
    for (int i=0; i < dns.length; i++)
    {
      dns[i] = new DN(dnStrings[i], schema);
    }
    return dns;
  }



  /**
   * Retrieves a string representation of this in-memory directory server
   * configuration.
   *
   * @return  A string representation of this in-memory directory server
   *          configuration.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this in-memory directory server
   * configuration to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("InMemoryDirectoryServerConfig(baseDNs={");

    for (int i=0; i < baseDNs.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      baseDNs[i].toString(buffer);
      buffer.append('\'');
    }
    buffer.append('}');

    buffer.append(", listenerConfigs={");

    final Iterator<InMemoryListenerConfig> listenerCfgIterator =
         listenerConfigs.iterator();
    while (listenerCfgIterator.hasNext())
    {
      listenerCfgIterator.next().toString(buffer);
      if (listenerCfgIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

    buffer.append(", schemaProvided=");
    buffer.append((schema != null));
    buffer.append(", enforceAttributeSyntaxCompliance=");
    buffer.append(enforceAttributeSyntaxCompliance);
    buffer.append(", enforceSingleStructuralObjectClass=");
    buffer.append(enforceSingleStructuralObjectClass);

    if (! additionalBindCredentials.isEmpty())
    {
      buffer.append(", additionalBindDNs={");

      final Iterator<DN> bindDNIterator =
           additionalBindCredentials.keySet().iterator();
      while (bindDNIterator.hasNext())
      {
        buffer.append('\'');
        bindDNIterator.next().toString(buffer);
        buffer.append('\'');
        if (bindDNIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if (! equalityIndexAttributes.isEmpty())
    {
      buffer.append(", equalityIndexAttributes={");

      final Iterator<String> attrIterator = equalityIndexAttributes.iterator();
      while (attrIterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(attrIterator.next());
        buffer.append('\'');
        if (attrIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if (! referentialIntegrityAttributes.isEmpty())
    {
      buffer.append(", referentialIntegrityAttributes={");

      final Iterator<String> attrIterator =
           referentialIntegrityAttributes.iterator();
      while (attrIterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(attrIterator.next());
        buffer.append('\'');
        if (attrIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    buffer.append(", generateOperationalAttributes=");
    buffer.append(generateOperationalAttributes);

    if (maxChangeLogEntries > 0)
    {
      buffer.append(", maxChangelogEntries=");
      buffer.append(maxChangeLogEntries);
    }

    buffer.append(", maxConnections=");
    buffer.append(maxConnections);
    buffer.append(", maxMessageSizeBytes=");
    buffer.append(maxMessageSizeBytes);
    buffer.append(", maxSizeLimit=");
    buffer.append(maxSizeLimit);

    if (! extendedOperationHandlers.isEmpty())
    {
      buffer.append(", extendedOperationHandlers={");

      final Iterator<InMemoryExtendedOperationHandler>
           handlerIterator = extendedOperationHandlers.iterator();
      while (handlerIterator.hasNext())
      {
        buffer.append(handlerIterator.next().toString());
        if (handlerIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if (! saslBindHandlers.isEmpty())
    {
      buffer.append(", saslBindHandlers={");

      final Iterator<InMemorySASLBindHandler>
           handlerIterator = saslBindHandlers.iterator();
      while (handlerIterator.hasNext())
      {
        buffer.append(handlerIterator.next().toString());
        if (handlerIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    buffer.append(", passwordAttributes={");
    final Iterator<String> pwAttrIterator = passwordAttributes.iterator();
    while (pwAttrIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(pwAttrIterator.next());
      buffer.append('\'');

      if (pwAttrIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

    if (primaryPasswordEncoder == null)
    {
      buffer.append(", primaryPasswordEncoder=null");
    }
    else
    {
      buffer.append(", primaryPasswordEncoderPrefix='");
      buffer.append(primaryPasswordEncoder.getPrefix());
      buffer.append('\'');
    }

    buffer.append(", secondaryPasswordEncoderPrefixes={");
    final Iterator<InMemoryPasswordEncoder> encoderIterator =
         secondaryPasswordEncoders.iterator();
    while (encoderIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(encoderIterator.next().getPrefix());
      buffer.append('\'');

      if (encoderIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

    if (accessLogHandler != null)
    {
      buffer.append(", accessLogHandlerClass='");
      buffer.append(accessLogHandler.getClass().getName());
      buffer.append('\'');
    }

    if (jsonAccessLogHandler != null)
    {
      buffer.append(", jsonAccessLogHandlerClass='");
      buffer.append(jsonAccessLogHandler.getClass().getName());
      buffer.append('\'');
    }

    if (ldapDebugLogHandler != null)
    {
      buffer.append(", ldapDebugLogHandlerClass='");
      buffer.append(ldapDebugLogHandler.getClass().getName());
      buffer.append('\'');
    }

    if (codeLogPath != null)
    {
      buffer.append(", codeLogPath='");
      buffer.append(codeLogPath);
      buffer.append("', includeRequestProcessingInCodeLog=");
      buffer.append(includeRequestProcessingInCodeLog);
    }

    if (exceptionHandler != null)
    {
      buffer.append(", listenerExceptionHandlerClass='");
      buffer.append(exceptionHandler.getClass().getName());
      buffer.append('\'');
    }

    if (vendorName != null)
    {
      buffer.append(", vendorName='");
      buffer.append(vendorName);
      buffer.append('\'');
    }

    if (vendorVersion != null)
    {
      buffer.append(", vendorVersion='");
      buffer.append(vendorVersion);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
