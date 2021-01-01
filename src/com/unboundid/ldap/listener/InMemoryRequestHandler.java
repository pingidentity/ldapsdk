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
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.matchingrules.GeneralizedTimeMatchingRule;
import com.unboundid.ldap.matchingrules.IntegerMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.EntrySorter;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.DITContentRuleDefinition;
import com.unboundid.ldap.sdk.schema.DITStructureRuleDefinition;
import com.unboundid.ldap.sdk.schema.EntryValidator;
import com.unboundid.ldap.sdk.schema.MatchingRuleUseDefinition;
import com.unboundid.ldap.sdk.schema.NameFormDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.DontUseCopyRequestControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadResponseControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.RFC3672SubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortResponseControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.controls.TransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewResponseControl;
import com.unboundid.ldap.sdk.experimental.
            DraftZeilengaLDAPNoOp12RequestControl;
import com.unboundid.ldap.sdk.extensions.AbortedTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an LDAP request handler that can be
 * used to store entries in memory and process operations on those entries.
 * It is primarily intended for use in creating a simple embeddable directory
 * server that can be used for testing purposes.  It performs only very basic
 * validation, and is not intended to be a fully standards-compliant server.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryRequestHandler
       extends LDAPListenerRequestHandler
{
  /**
   * A pre-allocated array containing no controls.
   */
  @NotNull private static final Control[] NO_CONTROLS = new Control[0];



  /**
   * The OID for a proprietary control that can be used to indicate that the
   * associated operation should be considered an internal operation that was
   * requested by a method call in the in-memory directory server class rather
   * than from an LDAP client.  It may be used to bypass certain restrictions
   * that might otherwise be enforced (e.g., allowed operation types, write
   * access to NO-USER-MODIFICATION attributes, etc.).
   */
  @NotNull static final String OID_INTERNAL_OPERATION_REQUEST_CONTROL =
       "1.3.6.1.4.1.30221.2.5.18";



  // The change number for the first changelog entry in the server.
  @NotNull private final AtomicLong firstChangeNumber;

  // The change number for the last changelog entry in the server.
  @NotNull private final AtomicLong lastChangeNumber;

  // A delay (in milliseconds) to insert before processing operations.
  @NotNull private final AtomicLong processingDelayMillis;

  // The reference to the entry validator that will be used for schema checking,
  // if appropriate.
  @NotNull private final AtomicReference<EntryValidator> entryValidatorRef;

  // The entry to use as the subschema subentry.
  @NotNull private final AtomicReference<ReadOnlyEntry> subschemaSubentryRef;

  // The reference to the schema that will be used for this request handler.
  @NotNull private final AtomicReference<Schema> schemaRef;

  // Indicates whether to generate operational attributes for writes.
  private final boolean generateOperationalAttributes;

  // The DN of the currently-authenticated user for the associated connection.
  @NotNull private DN authenticatedDN;

  // The base DN for the server changelog.
  @NotNull private final DN changeLogBaseDN;

  // The DN of the subschema subentry.
  @NotNull private final DN subschemaSubentryDN;

  // The configuration used to create this request handler.
  @NotNull private final InMemoryDirectoryServerConfig config;

  // A snapshot containing the server content as it initially appeared.  It
  // will not contain any user data, but may contain a changelog base entry.
  @NotNull private final InMemoryDirectoryServerSnapshot initialSnapshot;

  // The primary password encoder for the server.
  @Nullable private final InMemoryPasswordEncoder primaryPasswordEncoder;

  // The maximum number of changelog entries to maintain.
  private final int maxChangelogEntries;

  // The maximum number of entries to return from any single search.
  private final int maxSizeLimit;

  // The client connection for this request handler instance.
  @Nullable private final LDAPListenerClientConnection connection;

  // The list of all password encoders (primary and secondary) configured for
  // the in-memory directory server.
  @NotNull private final List<InMemoryPasswordEncoder> passwordEncoders;

  // The list of password attributes as requested by the user.  This will be a
  // minimal list, without multiple forms for each attribute type.
  @NotNull private final List<String> configuredPasswordAttributes;

  // The list of extended password attributes, including alternate names and
  // OIDs for each attribute type, when available.
  @NotNull private final List<String> extendedPasswordAttributes;

  // The set of equality indexes defined for the server.
  @NotNull private final Map<AttributeTypeDefinition,
     InMemoryDirectoryServerEqualityAttributeIndex> equalityIndexes;

  // An additional set of credentials that may be used for bind operations.
  @NotNull private final Map<DN,byte[]> additionalBindCredentials;

  // A map of the available extended operation handlers by request OID.
  @NotNull private final Map<String,InMemoryExtendedOperationHandler>
       extendedRequestHandlers;

  // A map of the available SASL bind handlers by mechanism name.
  @NotNull private final Map<String,InMemorySASLBindHandler> saslBindHandlers;

  // A map of state information specific to the associated connection.
  @NotNull private final Map<String,Object> connectionState;

  // The set of base DNs for the server.
  @NotNull private final Set<DN> baseDNs;

  // The set of referential integrity attributes for the server.
  @NotNull private final Set<String> referentialIntegrityAttributes;

  // The map of entries currently held in the server.
  @NotNull private final Map<DN,ReadOnlyEntry> entryMap;



  /**
   * Creates a new instance of this request handler with an initially-empty
   * data set.
   *
   * @param  config  The configuration that should be used for the in-memory
   *                 directory server.
   *
   * @throws  LDAPException  If there is a problem with the provided
   *                         configuration.
   */
  public InMemoryRequestHandler(
              @NotNull final InMemoryDirectoryServerConfig config)
         throws LDAPException
  {
    this.config = config;

    schemaRef            = new AtomicReference<>();
    entryValidatorRef    = new AtomicReference<>();
    subschemaSubentryRef = new AtomicReference<>();

    final Schema schema = config.getSchema();
    schemaRef.set(schema);
    if (schema != null)
    {
      final EntryValidator entryValidator = new EntryValidator(schema);
      entryValidatorRef.set(entryValidator);
      entryValidator.setCheckAttributeSyntax(
           config.enforceAttributeSyntaxCompliance());
      entryValidator.setCheckStructuralObjectClasses(
           config.enforceSingleStructuralObjectClass());
    }

    final DN[] baseDNArray = config.getBaseDNs();
    if ((baseDNArray == null) || (baseDNArray.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_NO_BASE_DNS.get());
    }

    entryMap = new TreeMap<>();

    final LinkedHashSet<DN> baseDNSet =
         new LinkedHashSet<>(Arrays.asList(baseDNArray));
    if (baseDNSet.contains(DN.NULL_DN))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_NULL_BASE_DN.get());
    }

    changeLogBaseDN = new DN("cn=changelog", schema);
    if (baseDNSet.contains(changeLogBaseDN))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_CHANGELOG_BASE_DN.get(changeLogBaseDN));
    }

    maxChangelogEntries = config.getMaxChangeLogEntries();

    if (config.getMaxSizeLimit() <= 0)
    {
      maxSizeLimit = Integer.MAX_VALUE;
    }
    else
    {
      maxSizeLimit = config.getMaxSizeLimit();
    }

    final TreeMap<String,InMemoryExtendedOperationHandler> extOpHandlers =
         new TreeMap<>();
    for (final InMemoryExtendedOperationHandler h :
         config.getExtendedOperationHandlers())
    {
      for (final String oid : h.getSupportedExtendedRequestOIDs())
      {
        if (extOpHandlers.containsKey(oid))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MEM_HANDLER_EXTENDED_REQUEST_HANDLER_CONFLICT.get(oid));
        }
        else
        {
          extOpHandlers.put(oid, h);
        }
      }
    }
    extendedRequestHandlers = Collections.unmodifiableMap(extOpHandlers);

    final TreeMap<String,InMemorySASLBindHandler> saslHandlers =
         new TreeMap<>();
    for (final InMemorySASLBindHandler h : config.getSASLBindHandlers())
    {
      final String mech = h.getSASLMechanismName();
      if (saslHandlers.containsKey(mech))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MEM_HANDLER_SASL_BIND_HANDLER_CONFLICT.get(mech));
      }
      else
      {
        saslHandlers.put(mech, h);
      }
    }
    saslBindHandlers = Collections.unmodifiableMap(saslHandlers);

    additionalBindCredentials = Collections.unmodifiableMap(
         config.getAdditionalBindCredentials());

    final List<String> eqIndexAttrs = config.getEqualityIndexAttributes();
    equalityIndexes = new HashMap<>(
         StaticUtils.computeMapCapacity(eqIndexAttrs.size()));
    for (final String s : eqIndexAttrs)
    {
      final InMemoryDirectoryServerEqualityAttributeIndex i =
           new InMemoryDirectoryServerEqualityAttributeIndex(s, schema);
      equalityIndexes.put(i.getAttributeType(), i);
    }

    final Set<String> pwAttrSet = config.getPasswordAttributes();
    final LinkedHashSet<String> basePWAttrSet =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(pwAttrSet.size()));
    final LinkedHashSet<String> extendedPWAttrSet = new LinkedHashSet<>(
         StaticUtils.computeMapCapacity(pwAttrSet.size()*2));
    for (final String attr : pwAttrSet)
    {
      basePWAttrSet.add(attr);
      extendedPWAttrSet.add(StaticUtils.toLowerCase(attr));

      if (schema != null)
      {
        final AttributeTypeDefinition attrType = schema.getAttributeType(attr);
        if (attrType != null)
        {
          for (final String name : attrType.getNames())
          {
            extendedPWAttrSet.add(StaticUtils.toLowerCase(name));
          }
          extendedPWAttrSet.add(StaticUtils.toLowerCase(attrType.getOID()));
        }
      }
    }

    configuredPasswordAttributes =
         Collections.unmodifiableList(new ArrayList<>(basePWAttrSet));
    extendedPasswordAttributes =
         Collections.unmodifiableList(new ArrayList<>(extendedPWAttrSet));

    referentialIntegrityAttributes = Collections.unmodifiableSet(
         config.getReferentialIntegrityAttributes());

    primaryPasswordEncoder = config.getPrimaryPasswordEncoder();

    final ArrayList<InMemoryPasswordEncoder> encoderList = new ArrayList<>(10);
    if (primaryPasswordEncoder != null)
    {
      encoderList.add(primaryPasswordEncoder);
    }
    encoderList.addAll(config.getSecondaryPasswordEncoders());
    passwordEncoders = Collections.unmodifiableList(encoderList);

    baseDNs = Collections.unmodifiableSet(baseDNSet);
    generateOperationalAttributes = config.generateOperationalAttributes();
    authenticatedDN               = new DN("cn=Internal Root User", schema);
    connection                    = null;
    connectionState               = Collections.emptyMap();
    firstChangeNumber             = new AtomicLong(0L);
    lastChangeNumber              = new AtomicLong(0L);
    processingDelayMillis         = new AtomicLong(0L);

    final ReadOnlyEntry subschemaSubentry = generateSubschemaSubentry(schema);
    subschemaSubentryRef.set(subschemaSubentry);
    subschemaSubentryDN = subschemaSubentry.getParsedDN();

    if (baseDNs.contains(subschemaSubentryDN))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_SCHEMA_BASE_DN.get(subschemaSubentryDN));
    }

    if (maxChangelogEntries > 0)
    {
      baseDNSet.add(changeLogBaseDN);

      final ReadOnlyEntry changeLogBaseEntry = new ReadOnlyEntry(
           changeLogBaseDN, schema,
           new Attribute("objectClass", "top", "namedObject"),
           new Attribute("cn", "changelog"),
           new Attribute("entryDN",
                DistinguishedNameMatchingRule.getInstance(),
                "cn=changelog"),
           new Attribute("entryUUID", UUID.randomUUID().toString()),
           new Attribute("creatorsName",
                DistinguishedNameMatchingRule.getInstance(),
                DN.NULL_DN.toString()),
           new Attribute("createTimestamp",
                GeneralizedTimeMatchingRule.getInstance(),
                StaticUtils.encodeGeneralizedTime(new Date())),
           new Attribute("modifiersName",
                DistinguishedNameMatchingRule.getInstance(),
                DN.NULL_DN.toString()),
           new Attribute("modifyTimestamp",
                GeneralizedTimeMatchingRule.getInstance(),
                StaticUtils.encodeGeneralizedTime(new Date())),
           new Attribute("subschemaSubentry",
                DistinguishedNameMatchingRule.getInstance(),
                subschemaSubentryDN.toString()));
      entryMap.put(changeLogBaseDN, changeLogBaseEntry);
      indexAdd(changeLogBaseEntry);
    }

    initialSnapshot = createSnapshot();
  }



  /**
   * Creates a new instance of this request handler that will use the provided
   * entry map object.
   *
   * @param  parent      The parent request handler instance.
   * @param  connection  The client connection for this instance.
   */
  private InMemoryRequestHandler(@NotNull final InMemoryRequestHandler parent,
               @NotNull final LDAPListenerClientConnection connection)
  {
    this.connection = connection;

    authenticatedDN = DN.NULL_DN;
    connectionState =
         Collections.synchronizedMap(new LinkedHashMap<String,Object>(0));

    config                         = parent.config;
    generateOperationalAttributes  = parent.generateOperationalAttributes;
    additionalBindCredentials      = parent.additionalBindCredentials;
    baseDNs                        = parent.baseDNs;
    changeLogBaseDN                = parent.changeLogBaseDN;
    firstChangeNumber              = parent.firstChangeNumber;
    lastChangeNumber               = parent.lastChangeNumber;
    processingDelayMillis          = parent.processingDelayMillis;
    maxChangelogEntries            = parent.maxChangelogEntries;
    maxSizeLimit                   = parent.maxSizeLimit;
    equalityIndexes                = parent.equalityIndexes;
    referentialIntegrityAttributes = parent.referentialIntegrityAttributes;
    entryMap                       = parent.entryMap;
    entryValidatorRef              = parent.entryValidatorRef;
    extendedRequestHandlers        = parent.extendedRequestHandlers;
    saslBindHandlers               = parent.saslBindHandlers;
    schemaRef                      = parent.schemaRef;
    subschemaSubentryRef           = parent.subschemaSubentryRef;
    subschemaSubentryDN            = parent.subschemaSubentryDN;
    initialSnapshot                = parent.initialSnapshot;
    configuredPasswordAttributes   = parent.configuredPasswordAttributes;
    extendedPasswordAttributes     = parent.extendedPasswordAttributes;
    primaryPasswordEncoder         = parent.primaryPasswordEncoder;
    passwordEncoders               = parent.passwordEncoders;
  }



  /**
   * Creates a new instance of this request handler that will be used to process
   * requests read by the provided connection.
   *
   * @param  connection  The connection with which this request handler instance
   *                     will be associated.
   *
   * @return  The request handler instance that will be used for the provided
   *          connection.
   *
   * @throws  LDAPException  If the connection should not be accepted.
   */
  @Override()
  @NotNull()
  public InMemoryRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new InMemoryRequestHandler(this, connection);
  }



  /**
   * Creates a point-in-time snapshot of the information contained in this
   * in-memory request handler.  If desired, it may be restored using the
   * {@link #restoreSnapshot} method.
   *
   * @return  The snapshot created based on the current content of this
   *          in-memory request handler.
   */
  @NotNull()
  public InMemoryDirectoryServerSnapshot createSnapshot()
  {
    synchronized (entryMap)
    {
      return new InMemoryDirectoryServerSnapshot(entryMap,
           firstChangeNumber.get(), lastChangeNumber.get());
    }
  }



  /**
   * Updates the content of this in-memory request handler to match what it was
   * at the time the snapshot was created.
   *
   * @param  snapshot  The snapshot to be restored.  It must not be
   *                   {@code null}.
   */
  public void restoreSnapshot(
                   @NotNull final InMemoryDirectoryServerSnapshot snapshot)
  {
    synchronized (entryMap)
    {
      entryMap.clear();
      entryMap.putAll(snapshot.getEntryMap());

      for (final InMemoryDirectoryServerEqualityAttributeIndex i :
           equalityIndexes.values())
      {
        i.clear();
        for (final Entry e : entryMap.values())
        {
          try
          {
            i.processAdd(e);
          }
          catch (final Exception ex)
          {
            Debug.debugException(ex);
          }
        }
      }

      firstChangeNumber.set(snapshot.getFirstChangeNumber());
      lastChangeNumber.set(snapshot.getLastChangeNumber());
    }
  }



  /**
   * Retrieves the schema that will be used by the server, if any.
   *
   * @return  The schema that will be used by the server, or {@code null} if
   *          none has been configured.
   */
  @Nullable()
  public Schema getSchema()
  {
    return schemaRef.get();
  }



  /**
   * Retrieves a list of the base DNs configured for use by the server.
   *
   * @return  A list of the base DNs configured for use by the server.
   */
  @NotNull()
  public List<DN> getBaseDNs()
  {
    return Collections.unmodifiableList(new ArrayList<>(baseDNs));
  }



  /**
   * Retrieves the client connection associated with this request handler
   * instance.
   *
   * @return  The client connection associated with this request handler
   *          instance, or {@code null} if this instance is not associated with
   *          any client connection.
   */
  @Nullable()
  public LDAPListenerClientConnection getClientConnection()
  {
    return connection;
  }



  /**
   * Retrieves the DN of the user currently authenticated on the connection
   * associated with this request handler instance.
   *
   * @return  The DN of the user currently authenticated on the connection
   *          associated with this request handler instance, or
   *          {@code DN#NULL_DN} if the connection is unauthenticated or is
   *          authenticated as the anonymous user.
   */
  @NotNull()
  public synchronized DN getAuthenticatedDN()
  {
    return authenticatedDN;
  }



  /**
   * Sets the DN of the user currently authenticated on the connection
   * associated with this request handler instance.
   *
   * @param  authenticatedDN  The DN of the user currently authenticated on the
   *                          connection associated with this request handler.
   *                          It may be {@code null} or {@link DN#NULL_DN} to
   *                          indicate that the connection is unauthenticated.
   */
  public synchronized void setAuthenticatedDN(
                                @Nullable final DN authenticatedDN)
  {
    if (authenticatedDN == null)
    {
      this.authenticatedDN = DN.NULL_DN;
    }
    else
    {
      this.authenticatedDN = authenticatedDN;
    }
  }



  /**
   * Retrieves an unmodifiable map containing the defined set of additional bind
   * credentials, mapped from bind DN to password bytes.
   *
   * @return  An unmodifiable map containing the defined set of additional bind
   *          credentials, or an empty map if no additional credentials have
   *          been defined.
   */
  @NotNull()
  public Map<DN,byte[]> getAdditionalBindCredentials()
  {
    return additionalBindCredentials;
  }



  /**
   * Retrieves the password for the given DN from the set of additional bind
   * credentials.
   *
   * @param  dn  The DN for which to retrieve the corresponding password.
   *
   * @return  The password bytes for the given DN, or {@code null} if the
   *          additional bind credentials does not include information for the
   *          provided DN.
   */
  @Nullable()
  public byte[] getAdditionalBindCredentials(@NotNull final DN dn)
  {
    return additionalBindCredentials.get(dn);
  }



  /**
   * Retrieves a map that may be used to hold state information specific to the
   * connection associated with this request handler instance.  It may be
   * queried and updated if necessary to store state information that may be
   * needed at multiple different times in the life of a connection (e.g., when
   * processing a multi-stage SASL bind).
   *
   * @return  An updatable map that may be used to hold state information
   *          specific to the connection associated with this request handler
   *          instance.
   */
  @NotNull()
  public Map<String,Object> getConnectionState()
  {
    return connectionState;
  }



  /**
   * Retrieves the delay in milliseconds that the server should impose before
   * beginning processing for operations.
   *
   * @return  The delay in milliseconds that the server should impose before
   *          beginning processing for operations, or 0 if there should be no
   *          delay inserted when processing operations.
   */
  public long getProcessingDelayMillis()
  {
    return processingDelayMillis.get();
  }



  /**
   * Specifies the delay in milliseconds that the server should impose before
   * beginning processing for operations.
   *
   * @param  processingDelayMillis  The delay in milliseconds that the server
   *                                should impose before beginning processing
   *                                for operations.  A value less than or equal
   *                                to zero may be used to indicate that there
   *                                should be no delay.
   */
  public void setProcessingDelayMillis(final long processingDelayMillis)
  {
    if (processingDelayMillis > 0)
    {
      this.processingDelayMillis.set(processingDelayMillis);
    }
    else
    {
      this.processingDelayMillis.set(0L);
    }
  }



  /**
   * Processes the provided add request.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   *
   * @param  addRequest  The add request to be processed.  It must not be
   *                     {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public LDAPResult add(@NotNull final AddRequest addRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(addRequest.getControlList());
    requestControlList.add(new Control(OID_INTERNAL_OPERATION_REQUEST_CONTROL,
         false));

    final LDAPMessage responseMessage = processAddRequest(1,
         new AddRequestProtocolOp(addRequest.getDN(),
              addRequest.getAttributes()),
         requestControlList);

    final AddResponseProtocolOp addResponse =
         responseMessage.getAddResponseProtocolOp();

    final LDAPResult ldapResult = new LDAPResult(responseMessage.getMessageID(),
         ResultCode.valueOf(addResponse.getResultCode()),
         addResponse.getDiagnosticMessage(), addResponse.getMatchedDN(),
         addResponse.getReferralURLs(), responseMessage.getControls());

    switch (addResponse.getResultCode())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;
      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Attempts to add an entry to the in-memory data set.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The provided entry has a malformed DN.</LI>
   *   <LI>The provided entry has the null DN.</LI>
   *   <LI>The provided entry has a DN that is the same as or subordinate to the
   *       subschema subentry.</LI>
   *   <LI>The provided entry has a DN that is the same as or subordinate to the
   *       changelog base entry.</LI>
   *   <LI>An entry already exists with the same DN as the entry in the provided
   *       request.</LI>
   *   <LI>The entry is outside the set of base DNs for the server.</LI>
   *   <LI>The entry is below one of the defined base DNs but the immediate
   *       parent entry does not exist.</LI>
   *   <LI>If a schema was provided, and the entry is not valid according to the
   *       constraints of that schema.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the add
   *                    request.
   * @param  request    The add request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code AddResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processAddRequest(final int messageID,
                          @NotNull final AddRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(OperationType.ADD)))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.ADD)))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_REQUIRES_AUTH.get(), null));
      }


      // See if this add request is part of a transaction.  If so, then perform
      // appropriate processing for it and return success immediately without
      // actually doing any further processing.
      try
      {
        final ASN1OctetString txnID =
             processTransactionRequest(messageID, request, controlMap);
        if (txnID != null)
        {
          return new LDAPMessage(messageID, new AddResponseProtocolOp(
               ResultCode.SUCCESS_INT_VALUE, null,
               INFO_MEM_HANDLER_OP_IN_TXN.get(txnID.stringValue()), null));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID,
             new AddResponseProtocolOp(le.getResultCode().intValue(),
                  le.getMatchedDN(), le.getDiagnosticMessage(),
                  StaticUtils.toList(le.getReferralURLs())),
             le.getResponseControls());
      }


      // Get the entry to be added.  If a schema was provided, then make sure
      // the attributes are created with the appropriate matching rules.
      final Entry entry;
      final Schema schema = schemaRef.get();
      if (schema == null)
      {
        entry = new Entry(request.getDN(), request.getAttributes());
      }
      else
      {
        final List<Attribute> providedAttrs = request.getAttributes();
        final List<Attribute> newAttrs = new ArrayList<>(providedAttrs.size());
        for (final Attribute a : providedAttrs)
        {
          final String baseName = a.getBaseName();
          final MatchingRule matchingRule =
               MatchingRule.selectEqualityMatchingRule(baseName, schema);
          newAttrs.add(new Attribute(a.getName(), matchingRule,
               a.getRawValues()));
        }

        entry = new Entry(request.getDN(), schema, newAttrs);
      }

      // Make sure that the DN is valid.
      final DN dn;
      try
      {
        dn = entry.getParsedDN();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_MALFORMED_DN.get(request.getDN(),
                  le.getMessage()),
             null));
      }

      // See if the DN is the null DN, the schema entry DN, or a changelog
      // entry.
      if (dn.isNullDN())
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_ROOT_DSE.get(), null));
      }
      else if (dn.isDescendantOf(subschemaSubentryDN, true))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_SCHEMA.get(subschemaSubentryDN.toString()),
             null));
      }
      else if (dn.isDescendantOf(changeLogBaseDN, true))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_CHANGELOG.get(changeLogBaseDN.toString()),
             null));
      }

      // See if there is a referral at or above the target entry.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(dn);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new AddResponseProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(dn, referralEntry)));
        }
      }

      // See if another entry exists with the same DN.
      if (entryMap.containsKey(dn))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_ALREADY_EXISTS.get(request.getDN()), null));
      }

      // Make sure that all RDN attribute values are present in the entry.
      final RDN      rdn           = dn.getRDN();
      final String[] rdnAttrNames  = rdn.getAttributeNames();
      final byte[][] rdnAttrValues = rdn.getByteArrayAttributeValues();
      for (int i=0; i < rdnAttrNames.length; i++)
      {
        final MatchingRule matchingRule =
             MatchingRule.selectEqualityMatchingRule(rdnAttrNames[i], schema);
        entry.addAttribute(new Attribute(rdnAttrNames[i], matchingRule,
             rdnAttrValues[i]));
      }

      // Make sure that all superior object classes are present in the entry.
      if (schema != null)
      {
        final String[] objectClasses = entry.getObjectClassValues();
        if (objectClasses != null)
        {
          final LinkedHashMap<String,String> ocMap = new LinkedHashMap<>(
               StaticUtils.computeMapCapacity(objectClasses.length));
          for (final String ocName : objectClasses)
          {
            final ObjectClassDefinition oc = schema.getObjectClass(ocName);
            if (oc == null)
            {
              ocMap.put(StaticUtils.toLowerCase(ocName), ocName);
            }
            else
            {
              ocMap.put(StaticUtils.toLowerCase(oc.getNameOrOID()), ocName);
              for (final ObjectClassDefinition supClass :
                   oc.getSuperiorClasses(schema, true))
              {
                ocMap.put(StaticUtils.toLowerCase(supClass.getNameOrOID()),
                     supClass.getNameOrOID());
              }
            }
          }

          final String[] newObjectClasses = new String[ocMap.size()];
          ocMap.values().toArray(newObjectClasses);
          entry.setAttribute("objectClass", newObjectClasses);
        }
      }

      // If a schema was provided, then make sure the entry complies with it.
      // Also make sure that there are no attributes marked with
      // NO-USER-MODIFICATION.
      final EntryValidator entryValidator = entryValidatorRef.get();
      if (entryValidator != null)
      {
        final ArrayList<String> invalidReasons = new ArrayList<>(1);
        if (! entryValidator.entryIsValid(entry, invalidReasons))
        {
          return new LDAPMessage(messageID, new AddResponseProtocolOp(
               ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE, null,
               ERR_MEM_HANDLER_ADD_VIOLATES_SCHEMA.get(request.getDN(),
                    StaticUtils.concatenateStrings(invalidReasons)), null));
        }

        if ((! isInternalOp) && (schema != null) &&
            (! controlMap.containsKey(IgnoreNoUserModificationRequestControl.
                    IGNORE_NO_USER_MODIFICATION_REQUEST_OID)))
        {
          for (final Attribute a : entry.getAttributes())
          {
            final AttributeTypeDefinition at =
                 schema.getAttributeType(a.getBaseName());
            if ((at != null) && at.isNoUserModification())
            {
              return new LDAPMessage(messageID, new AddResponseProtocolOp(
                   ResultCode.CONSTRAINT_VIOLATION_INT_VALUE, null,
                   ERR_MEM_HANDLER_ADD_CONTAINS_NO_USER_MOD.get(request.getDN(),
                        a.getName()), null));
            }
          }
        }
      }

      // If the entry contains a proxied authorization control, then process it.
      final DN authzDN;
      try
      {
        authzDN = handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // Add a number of operational attributes to the entry.
      if (generateOperationalAttributes)
      {
        final Date d = new Date();
        if (! entry.hasAttribute("entryDN"))
        {
          entry.addAttribute(new Attribute("entryDN",
               DistinguishedNameMatchingRule.getInstance(),
               dn.toNormalizedString()));
        }
        if (! entry.hasAttribute("entryUUID"))
        {
          entry.addAttribute(new Attribute("entryUUID",
               UUID.randomUUID().toString()));
        }
        if (! entry.hasAttribute("subschemaSubentry"))
        {
          entry.addAttribute(new Attribute("subschemaSubentry",
               DistinguishedNameMatchingRule.getInstance(),
               subschemaSubentryDN.toString()));
        }
        if (! entry.hasAttribute("creatorsName"))
        {
          entry.addAttribute(new Attribute("creatorsName",
               DistinguishedNameMatchingRule.getInstance(),
               authzDN.toString()));
        }
        if (! entry.hasAttribute("createTimestamp"))
        {
          entry.addAttribute(new Attribute("createTimestamp",
               GeneralizedTimeMatchingRule.getInstance(),
               StaticUtils.encodeGeneralizedTime(d)));
        }
        if (! entry.hasAttribute("modifiersName"))
        {
          entry.addAttribute(new Attribute("modifiersName",
               DistinguishedNameMatchingRule.getInstance(),
               authzDN.toString()));
        }
        if (! entry.hasAttribute("modifyTimestamp"))
        {
          entry.addAttribute(new Attribute("modifyTimestamp",
               GeneralizedTimeMatchingRule.getInstance(),
               StaticUtils.encodeGeneralizedTime(d)));
        }
      }

      // If the request includes the assertion request control, then check it
      // now.
      try
      {
        handleAssertionRequestControl(controlMap, entry);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // See if the entry contains any passwords.  If so, then make sure their
      // values are properly encoded.
      if ((! passwordEncoders.isEmpty()) &&
          (! configuredPasswordAttributes.isEmpty()))
      {
        final ReadOnlyEntry readOnlyEntry =
             new ReadOnlyEntry(entry.duplicate());
        for (final String passwordAttribute : configuredPasswordAttributes)
        {
          for (final Attribute attr :
               readOnlyEntry.getAttributesWithOptions(passwordAttribute, null))
          {
            final ArrayList<byte[]> newValues = new ArrayList<>(attr.size());
            for (final ASN1OctetString value : attr.getRawValues())
            {
              try
              {
                newValues.add(encodeAddPassword(value, readOnlyEntry,
                     Collections.<Modification>emptyList()).getValue());
              }
              catch (final LDAPException le)
              {
                Debug.debugException(le);
                return new LDAPMessage(messageID, new AddResponseProtocolOp(
                     ResultCode.UNWILLING_TO_PERFORM_INT_VALUE,
                     le.getMatchedDN(), le.getMessage(), null));
              }
            }

            final byte[][] newValuesArray = new byte[newValues.size()][];
            newValues.toArray(newValuesArray);
            entry.setAttribute(new Attribute(attr.getName(), schema,
                 newValuesArray));
          }
        }
      }

      // If the request includes the post-read request control, then create the
      // appropriate response control.
      final PostReadResponseControl postReadResponse =
           handlePostReadControl(controlMap, entry);
      if (postReadResponse != null)
      {
        responseControls.add(postReadResponse);
      }

      // See if the entry DN is one of the defined base DNs.  If so, then we can
      // add the entry.
      if (baseDNs.contains(dn))
      {
        entryMap.put(dn, new ReadOnlyEntry(entry));
        indexAdd(entry);
        addChangeLogEntry(request, authzDN);
        return new LDAPMessage(messageID,
             new AddResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null, null,
                  null),
             responseControls);
      }

      // See if the parent entry exists.  If so, then we can add the entry.
      final DN parentDN = dn.getParent();
      if ((parentDN != null) && entryMap.containsKey(parentDN))
      {
        entryMap.put(dn, new ReadOnlyEntry(entry));
        indexAdd(entry);
        addChangeLogEntry(request, authzDN);
        return new LDAPMessage(messageID,
             new AddResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null, null,
                  null),
             responseControls);
      }

      // The add attempt must fail because the parent doesn't exist.  See if
      // it's just that the parent doesn't exist or whether the entry isn't
      // within any of the configured base DNs.
      for (final DN baseDN : baseDNs)
      {
        if (dn.isDescendantOf(baseDN, true))
        {
          return new LDAPMessage(messageID, new AddResponseProtocolOp(
               ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
               ERR_MEM_HANDLER_ADD_MISSING_PARENT.get(request.getDN(),
                    dn.getParentString()),
               null));
        }
      }

      return new LDAPMessage(messageID, new AddResponseProtocolOp(
           ResultCode.NO_SUCH_OBJECT_INT_VALUE, null,
           ERR_MEM_HANDLER_ADD_NOT_BELOW_BASE_DN.get(request.getDN()),
           null));
    }
  }



  /**
   * Encodes the provided password as appropriate.
   *
   * @param  password  The password to be encoded.
   * @param  entry     The entry in which the password occurs.
   * @param  mods      A list of modifications being applied to the entry, or
   *                   an empty list if there are no modifications.
   *
   * @return  The encoded password.
   *
   * @throws  LDAPException  If a problem is encountered while encoding the
   *                         password.
   */
  @NotNull()
  private ASN1OctetString encodeAddPassword(
                               @NotNull final ASN1OctetString password,
                               @NotNull final ReadOnlyEntry entry,
                               @NotNull final List<Modification> mods)
          throws LDAPException
  {
    for (final InMemoryPasswordEncoder encoder : passwordEncoders)
    {
      if (encoder.passwordStartsWithPrefix(password))
      {
        encoder.ensurePreEncodedPasswordAppearsValid(password, entry, mods);
        return password;
      }
    }

    if (primaryPasswordEncoder != null)
    {
      return primaryPasswordEncoder.encodePassword(password, entry, mods);
    }
    else
    {
      return password;
    }
  }



  /**
   * Attempts to process the provided bind request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The bind request is for a SASL bind for which no SASL mechanism
   *       handler is defined.</LI>
   *   <LI>The bind request contains a malformed bind DN.</LI>
   *   <LI>The bind DN is not the null DN and is not the DN of any entry in the
   *       data set.</LI>
   *   <LI>The bind password is empty and the bind DN is not the null DN.</LI>
   *   <LI>The target user does not have any password value that matches the
   *       provided bind password.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the bind
   *                    request.
   * @param  request    The bind request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code BindResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processBindRequest(final int messageID,
                          @NotNull final BindRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // If this operation type is not allowed, then reject it.
      if (! config.getAllowedOperationTypes().contains(OperationType.BIND))
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_BIND_NOT_ALLOWED.get(), null, null));
      }


      authenticatedDN = DN.NULL_DN;


      // If this operation type requires authentication and it is a simple bind
      // request, then ensure that the request includes credentials.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.BIND)))
      {
        if ((request.getCredentialsType() ==
             BindRequestProtocolOp.CRED_TYPE_SIMPLE) &&
             ((request.getSimplePassword() == null) ||
                  request.getSimplePassword().getValueLength() == 0))
        {
          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               ResultCode.INVALID_CREDENTIALS_INT_VALUE, null,
               ERR_MEM_HANDLER_BIND_REQUIRES_AUTH.get(), null, null));
        }
      }


      // Get the parsed bind DN.
      final DN bindDN;
      try
      {
        bindDN = new DN(request.getBindDN(), schemaRef.get());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_BIND_MALFORMED_DN.get(request.getBindDN(),
                  le.getMessage()),
             null, null));
      }

      // If the bind request is for a SASL bind, then see if there is a SASL
      // mechanism handler that can be used to process it.
      if (request.getCredentialsType() == BindRequestProtocolOp.CRED_TYPE_SASL)
      {
        final String mechanism = request.getSASLMechanism();
        final InMemorySASLBindHandler handler = saslBindHandlers.get(mechanism);
        if (handler == null)
        {
          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               ResultCode.AUTH_METHOD_NOT_SUPPORTED_INT_VALUE, null,
               ERR_MEM_HANDLER_SASL_MECH_NOT_SUPPORTED.get(mechanism), null,
               null));
        }

        try
        {
          final BindResult bindResult = handler.processSASLBind(this, messageID,
               bindDN, request.getSASLCredentials(), controls);

          // If the SASL bind was successful but the connection is
          // unauthenticated, then see if we allow that.
          if ((bindResult.getResultCode() == ResultCode.SUCCESS) &&
               (authenticatedDN == DN.NULL_DN) &&
               config.getAuthenticationRequiredOperationTypes().contains(
                    OperationType.BIND))
          {
            return new LDAPMessage(messageID, new BindResponseProtocolOp(
                 ResultCode.INVALID_CREDENTIALS_INT_VALUE, null,
                 ERR_MEM_HANDLER_BIND_REQUIRES_AUTH.get(), null, null));
          }

          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               bindResult.getResultCode().intValue(),
               bindResult.getMatchedDN(), bindResult.getDiagnosticMessage(),
               Arrays.asList(bindResult.getReferralURLs()),
               bindResult.getServerSASLCredentials()),
               Arrays.asList(bindResult.getResponseControls()));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               ResultCode.OTHER_INT_VALUE, null,
               ERR_MEM_HANDLER_SASL_BIND_FAILURE.get(
                    StaticUtils.getExceptionMessage(e)),
               null, null));
        }
      }

      // If we've gotten here, then the bind must use simple authentication.
      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null, null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);

      // If the bind DN is the null DN, then the bind will be considered
      // successful as long as the password is also empty.
      final ASN1OctetString bindPassword = request.getSimplePassword();
      if (bindDN.isNullDN())
      {
        if (bindPassword.getValueLength() == 0)
        {
          if (controlMap.containsKey(AuthorizationIdentityRequestControl.
               AUTHORIZATION_IDENTITY_REQUEST_OID))
          {
            responseControls.add(new AuthorizationIdentityResponseControl(""));
          }
          return new LDAPMessage(messageID,
               new BindResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                    null, null, null),
               responseControls);
        }
        else
        {
          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               ResultCode.INVALID_CREDENTIALS_INT_VALUE,
               getMatchedDNString(bindDN),
               ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()),
               null, null));
        }
      }

      // If the bind DN is not null and the password is empty, then reject the
      // request.
      if ((! bindDN.isNullDN()) && (bindPassword.getValueLength() == 0))
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_BIND_SIMPLE_DN_WITHOUT_PASSWORD.get(), null,
             null));
      }

      // See if the bind DN is in the set of additional bind credentials.  If
      // so, then use the password there.
      final byte[] additionalCreds = additionalBindCredentials.get(bindDN);
      if (additionalCreds != null)
      {
        if (Arrays.equals(additionalCreds, bindPassword.getValue()))
        {
          authenticatedDN = bindDN;
          if (controlMap.containsKey(AuthorizationIdentityRequestControl.
               AUTHORIZATION_IDENTITY_REQUEST_OID))
          {
            responseControls.add(new AuthorizationIdentityResponseControl(
                 "dn:" + bindDN.toString()));
          }
          return new LDAPMessage(messageID,
               new BindResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                    null, null, null),
               responseControls);
        }
        else
        {
          return new LDAPMessage(messageID, new BindResponseProtocolOp(
               ResultCode.INVALID_CREDENTIALS_INT_VALUE,
               getMatchedDNString(bindDN),
               ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()),
               null, null));
        }
      }

      // If the target user doesn't exist, then reject the request.
      final ReadOnlyEntry userEntry = entryMap.get(bindDN);
      if (userEntry == null)
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.INVALID_CREDENTIALS_INT_VALUE,
             getMatchedDNString(bindDN),
             ERR_MEM_HANDLER_BIND_NO_SUCH_USER.get(request.getBindDN()), null,
             null));
      }


      // Get a list of the user's passwords, restricted to those that match the
      // provided clear-text password.  If the list is empty, then the
      // authentication failed.
      final List<InMemoryDirectoryServerPassword> matchingPasswords =
           getPasswordsInEntry(userEntry, bindPassword);
      if (matchingPasswords.isEmpty())
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.INVALID_CREDENTIALS_INT_VALUE,
             getMatchedDNString(bindDN),
             ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()), null,
             null));
      }


      // If we've gotten here, then authentication was successful.
      authenticatedDN = bindDN;
      if (controlMap.containsKey(AuthorizationIdentityRequestControl.
           AUTHORIZATION_IDENTITY_REQUEST_OID))
      {
        responseControls.add(new AuthorizationIdentityResponseControl(
             "dn:" + bindDN.toString()));
      }
      return new LDAPMessage(messageID,
           new BindResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                null, null, null),
           responseControls);
    }
  }



  /**
   * Attempts to process the provided compare request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The compare request contains a malformed target DN.</LI>
   *   <LI>The target entry does not exist.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the
   *                    compare request.
   * @param  request    The compare request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code CompareResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processCompareRequest(final int messageID,
                          @NotNull final CompareRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(
                OperationType.COMPARE)))
      {
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_COMPARE_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.COMPARE)))
      {
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_COMPARE_REQUIRES_AUTH.get(), null));
      }


      // Get the parsed target DN.
      final DN dn;
      try
      {
        dn = new DN(request.getDN(), schemaRef.get());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_COMPARE_MALFORMED_DN.get(request.getDN(),
                  le.getMessage()),
             null));
      }

      // See if the target entry or one of its superiors is a smart referral.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(dn);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new CompareResponseProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(dn, referralEntry)));
        }
      }

      // Get the target entry (optionally checking for the root DSE or subschema
      // subentry).  If it does not exist, then fail.
      final Entry entry;
      if (dn.isNullDN())
      {
        entry = generateRootDSE();
      }
      else if (dn.equals(subschemaSubentryDN))
      {
        entry = subschemaSubentryRef.get();
      }
      else
      {
        entry = entryMap.get(dn);
      }
      if (entry == null)
      {
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
             ERR_MEM_HANDLER_COMPARE_NO_SUCH_ENTRY.get(request.getDN()), null));
      }

      // If the request includes an assertion or proxied authorization control,
      // then perform the appropriate processing.
      try
      {
        handleAssertionRequestControl(controlMap, entry);
        handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new CompareResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // See if the entry contains the assertion value.
      final int resultCode;
      if (entry.hasAttributeValue(request.getAttributeName(),
           request.getAssertionValue().getValue()))
      {
        resultCode = ResultCode.COMPARE_TRUE_INT_VALUE;
      }
      else
      {
        resultCode = ResultCode.COMPARE_FALSE_INT_VALUE;
      }
      return new LDAPMessage(messageID,
           new CompareResponseProtocolOp(resultCode, null, null, null),
           responseControls);
    }
  }



  /**
   * Processes the provided delete request.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether delete operations are
   * allowed in the server.
   *
   * @param  deleteRequest  The delete request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public LDAPResult delete(@NotNull final DeleteRequest deleteRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(deleteRequest.getControlList());
    requestControlList.add(new Control(OID_INTERNAL_OPERATION_REQUEST_CONTROL,
         false));

    final LDAPMessage responseMessage = processDeleteRequest(1,
         new DeleteRequestProtocolOp(deleteRequest.getDN()),
         requestControlList);

    final DeleteResponseProtocolOp deleteResponse =
         responseMessage.getDeleteResponseProtocolOp();

    final LDAPResult ldapResult = new LDAPResult(responseMessage.getMessageID(),
         ResultCode.valueOf(deleteResponse.getResultCode()),
         deleteResponse.getDiagnosticMessage(), deleteResponse.getMatchedDN(),
         deleteResponse.getReferralURLs(), responseMessage.getControls());

    switch (deleteResponse.getResultCode())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;
      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Attempts to process the provided delete request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The delete request contains a malformed target DN.</LI>
   *   <LI>The target entry is the root DSE.</LI>
   *   <LI>The target entry is the subschema subentry.</LI>
   *   <LI>The target entry is at or below the changelog base entry.</LI>
   *   <LI>The target entry does not exist.</LI>
   *   <LI>The target entry has one or more subordinate entries.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the delete
   *                    request.
   * @param  request    The delete request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code DeleteResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processDeleteRequest(final int messageID,
                          @NotNull final DeleteRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(OperationType.DELETE)))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.DELETE)))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_REQUIRES_AUTH.get(), null));
      }


      // See if this delete request is part of a transaction.  If so, then
      // perform appropriate processing for it and return success immediately
      // without actually doing any further processing.
      try
      {
        final ASN1OctetString txnID =
             processTransactionRequest(messageID, request, controlMap);
        if (txnID != null)
        {
          return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
               ResultCode.SUCCESS_INT_VALUE, null,
               INFO_MEM_HANDLER_OP_IN_TXN.get(txnID.stringValue()), null));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID,
             new DeleteResponseProtocolOp(le.getResultCode().intValue(),
                  le.getMatchedDN(), le.getDiagnosticMessage(),
                  StaticUtils.toList(le.getReferralURLs())),
             le.getResponseControls());
      }


      // Get the parsed target DN.
      final DN dn;
      try
      {
        dn = new DN(request.getDN(), schemaRef.get());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_MALFORMED_DN.get(request.getDN(),
                  le.getMessage()),
             null));
      }

      // See if the target entry or one of its superiors is a smart referral.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(dn);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(dn, referralEntry)));
        }
      }

      // Make sure the target entry isn't the root DSE or schema, or a changelog
      // entry.
      if (dn.isNullDN())
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_ROOT_DSE.get(), null));
      }
      else if (dn.equals(subschemaSubentryDN))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_SCHEMA.get(subschemaSubentryDN.toString()),
             null));
      }
      else if (dn.isDescendantOf(changeLogBaseDN, true))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_CHANGELOG.get(request.getDN()), null));
      }

      // Get the target entry.  If it does not exist, then fail.
      final Entry entry = entryMap.get(dn);
      if (entry == null)
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
             ERR_MEM_HANDLER_DELETE_NO_SUCH_ENTRY.get(request.getDN()), null));
      }

      // Create a list with the DN of the target entry, and all the DNs of its
      // subordinates.  If the entry has subordinates and the subtree delete
      // control was not provided, then fail.
      final ArrayList<DN> subordinateDNs = new ArrayList<>(entryMap.size());
      for (final DN mapEntryDN : entryMap.keySet())
      {
        if (mapEntryDN.isDescendantOf(dn, false))
        {
          subordinateDNs.add(mapEntryDN);
        }
      }

      if ((! subordinateDNs.isEmpty()) &&
           (! controlMap.containsKey(
                SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID)))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_HAS_SUBORDINATES.get(request.getDN()),
             null));
      }

      // Handle the necessary processing for the assertion, pre-read, and
      // proxied auth controls.
      final DN authzDN;
      try
      {
        handleAssertionRequestControl(controlMap, entry);

        final PreReadResponseControl preReadResponse =
             handlePreReadControl(controlMap, entry);
        if (preReadResponse != null)
        {
          responseControls.add(preReadResponse);
        }

        authzDN = handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // At this point, the entry will be removed.  However, if this will be a
      // subtree delete, then we want to delete all of its subordinates first so
      // that the changelog will show the deletes in the appropriate order.
      for (int i=(subordinateDNs.size() - 1); i >= 0; i--)
      {
        final DN subordinateDN = subordinateDNs.get(i);
        final Entry subEntry = entryMap.remove(subordinateDN);
        indexDelete(subEntry);
        addDeleteChangeLogEntry(subEntry, authzDN);
        handleReferentialIntegrityDelete(subordinateDN);
      }

      // Finally, remove the target entry and create a changelog entry for it.
      entryMap.remove(dn);
      indexDelete(entry);
      addDeleteChangeLogEntry(entry, authzDN);
      handleReferentialIntegrityDelete(dn);

      return new LDAPMessage(messageID,
           new DeleteResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                null, null),
           responseControls);
    }
  }



  /**
   * Handles any appropriate referential integrity processing for a delete
   * operation.
   *
   * @param  dn  The DN of the entry that has been deleted.
   */
  private void handleReferentialIntegrityDelete(@NotNull final DN dn)
  {
    if (referentialIntegrityAttributes.isEmpty())
    {
      return;
    }

    final ArrayList<DN> entryDNs = new ArrayList<>(entryMap.keySet());
    for (final DN mapDN : entryDNs)
    {
      final ReadOnlyEntry e = entryMap.get(mapDN);

      boolean referenceFound = false;
      final Schema schema = schemaRef.get();
      for (final String attrName : referentialIntegrityAttributes)
      {
        final Attribute a = e.getAttribute(attrName, schema);
        if ((a != null) &&
            a.hasValue(dn.toNormalizedString(),
                 DistinguishedNameMatchingRule.getInstance()))
        {
          referenceFound = true;
          break;
        }
      }

      if (referenceFound)
      {
        final Entry copy = e.duplicate();
        for (final String attrName : referentialIntegrityAttributes)
        {
          copy.removeAttributeValue(attrName, dn.toNormalizedString(),
               DistinguishedNameMatchingRule.getInstance());
        }
        entryMap.put(mapDN, new ReadOnlyEntry(copy));
        indexDelete(e);
        indexAdd(copy);
      }
    }
  }



  /**
   * Attempts to process the provided extended request, if an extended operation
   * handler is defined for the given request OID.
   *
   * @param  messageID  The message ID of the LDAP message containing the
   *                    extended request.
   * @param  request    The extended request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ExtendedResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processExtendedRequest(final int messageID,
                          @NotNull final ExtendedRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      boolean isInternalOp = false;
      for (final Control c : controls)
      {
        if (c.getOID().equals(OID_INTERNAL_OPERATION_REQUEST_CONTROL))
        {
          isInternalOp = true;
          break;
        }
      }


      // If this operation type is not allowed, then reject it.
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(
                OperationType.EXTENDED)))
      {
        return new LDAPMessage(messageID, new ExtendedResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_EXTENDED_NOT_ALLOWED.get(), null, null, null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.EXTENDED)))
      {
        return new LDAPMessage(messageID, new ExtendedResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_EXTENDED_REQUIRES_AUTH.get(), null, null, null));
      }


      final String oid = request.getOID();
      final InMemoryExtendedOperationHandler handler =
           extendedRequestHandlers.get(oid);
      if (handler == null)
      {
        return new LDAPMessage(messageID, new ExtendedResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_EXTENDED_OP_NOT_SUPPORTED.get(oid), null, null,
             null));
      }

      try
      {
        final Control[] controlArray = new Control[controls.size()];
        controls.toArray(controlArray);

        final ExtendedRequest extendedRequest = new ExtendedRequest(oid,
             request.getValue(), controlArray);

        final ExtendedResult extendedResult =
             handler.processExtendedOperation(this, messageID, extendedRequest);

        return new LDAPMessage(messageID,
             new ExtendedResponseProtocolOp(
                  extendedResult.getResultCode().intValue(),
                  extendedResult.getMatchedDN(),
                  extendedResult.getDiagnosticMessage(),
                  Arrays.asList(extendedResult.getReferralURLs()),
                  extendedResult.getOID(), extendedResult.getValue()),
             extendedResult.getResponseControls());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        return new LDAPMessage(messageID, new ExtendedResponseProtocolOp(
             ResultCode.OTHER_INT_VALUE, null,
             ERR_MEM_HANDLER_EXTENDED_OP_FAILURE.get(
                  StaticUtils.getExceptionMessage(e)),
             null, null, null));
      }
    }
  }



  /**
   * Processes the provided modify request.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   *
   * @param  modifyRequest  The modify request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public LDAPResult modify(@NotNull final ModifyRequest modifyRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(modifyRequest.getControlList());
    requestControlList.add(new Control(OID_INTERNAL_OPERATION_REQUEST_CONTROL,
         false));

    final LDAPMessage responseMessage = processModifyRequest(1,
         new ModifyRequestProtocolOp(modifyRequest.getDN(),
              modifyRequest.getModifications()),
         requestControlList);

    final ModifyResponseProtocolOp modifyResponse =
         responseMessage.getModifyResponseProtocolOp();

    final LDAPResult ldapResult = new LDAPResult(responseMessage.getMessageID(),
         ResultCode.valueOf(modifyResponse.getResultCode()),
         modifyResponse.getDiagnosticMessage(), modifyResponse.getMatchedDN(),
         modifyResponse.getReferralURLs(), responseMessage.getControls());

    switch (modifyResponse.getResultCode())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;
      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Attempts to process the provided modify request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The modify request contains a malformed target DN.</LI>
   *   <LI>The target entry is the root DSE.</LI>
   *   <LI>The target entry is the subschema subentry.</LI>
   *   <LI>The target entry does not exist.</LI>
   *   <LI>Any of the modifications cannot be applied to the entry.</LI>
   *   <LI>If a schema was provided, and the entry violates any of the
   *       constraints of that schema.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the modify
   *                    request.
   * @param  request    The modify request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ModifyResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyRequest(final int messageID,
                          @NotNull final ModifyRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(OperationType.MODIFY)))
      {
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MODIFY_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.MODIFY)))
      {
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_MODIFY_REQUIRES_AUTH.get(), null));
      }


      // See if this modify request is part of a transaction.  If so, then
      // perform appropriate processing for it and return success immediately
      // without actually doing any further processing.
      try
      {
        final ASN1OctetString txnID =
             processTransactionRequest(messageID, request, controlMap);
        if (txnID != null)
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               ResultCode.SUCCESS_INT_VALUE, null,
               INFO_MEM_HANDLER_OP_IN_TXN.get(txnID.stringValue()), null));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID,
             new ModifyResponseProtocolOp(le.getResultCode().intValue(),
                  le.getMatchedDN(), le.getDiagnosticMessage(),
                  StaticUtils.toList(le.getReferralURLs())),
             le.getResponseControls());
      }


      // Get the parsed target DN.
      final DN dn;
      final Schema schema = schemaRef.get();
      try
      {
        dn = new DN(request.getDN(), schema);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_MALFORMED_DN.get(request.getDN(),
                  le.getMessage()),
             null));
      }

      // See if the target entry or one of its superiors is a smart referral.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(dn);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(dn, referralEntry)));
        }
      }

      // See if the target entry is the root DSE, the subschema subentry, or a
      // changelog entry.
      if (dn.isNullDN())
      {
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_ROOT_DSE.get(), null));
      }
      else if (dn.equals(subschemaSubentryDN))
      {
        try
        {
          validateSchemaMods(request);
        }
        catch (final LDAPException le)
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               le.getResultCode().intValue(), le.getMatchedDN(),
               le.getMessage(), null));
        }
      }
      else if (dn.isDescendantOf(changeLogBaseDN, true))
      {
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_CHANGELOG.get(request.getDN()), null));
      }

      // Get the target entry.  If it does not exist, then fail.
      Entry entry = entryMap.get(dn);
      if (entry == null)
      {
        if (dn.equals(subschemaSubentryDN))
        {
          entry = subschemaSubentryRef.get().duplicate();
        }
        else
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
               ERR_MEM_HANDLER_MOD_NO_SUCH_ENTRY.get(request.getDN()), null));
        }
      }


      // If any of the modifications target password attributes, then make sure
      // they are properly encoded.
      final ReadOnlyEntry readOnlyEntry = new ReadOnlyEntry(entry);
      final List<Modification> unencodedMods = request.getModifications();
      final ArrayList<Modification> modifications =
           new ArrayList<>(unencodedMods.size());
      for (final Modification m : unencodedMods)
      {
        try
        {
          modifications.add(encodeModificationPasswords(m, readOnlyEntry,
               unencodedMods));
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          if (le.getResultCode().isClientSideResultCode())
          {
            return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
                 ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, le.getMatchedDN(),
                 le.getMessage(), null));
          }
          else
          {
            return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
                 le.getResultCode().intValue(), le.getMatchedDN(),
                 le.getMessage(), null));
          }
        }
      }


      // Attempt to apply the modifications to the entry.  If successful, then a
      // copy of the entry will be returned with the modifications applied.
      final Entry modifiedEntry;
      try
      {
        modifiedEntry = Entry.applyModifications(entry,
             controlMap.containsKey(
                  PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID),
             modifications);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             le.getResultCode().intValue(), null,
             ERR_MEM_HANDLER_MOD_FAILED.get(request.getDN(), le.getMessage()),
             null));
      }

      // If a schema was provided, use it to validate the resulting entry.
      // Also, ensure that no NO-USER-MODIFICATION attributes were targeted.
      final EntryValidator entryValidator = entryValidatorRef.get();
      if (entryValidator != null)
      {
        final ArrayList<String> invalidReasons = new ArrayList<>(1);
        if (! entryValidator.entryIsValid(modifiedEntry, invalidReasons))
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE, null,
               ERR_MEM_HANDLER_MOD_VIOLATES_SCHEMA.get(request.getDN(),
                    StaticUtils.concatenateStrings(invalidReasons)),
               null));
        }

        for (final Modification m : modifications)
        {
          final Attribute a = m.getAttribute();
          final String baseName = a.getBaseName();
          final AttributeTypeDefinition at = schema.getAttributeType(baseName);
          if ((! isInternalOp) && (at != null) && at.isNoUserModification())
          {
            return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
                 ResultCode.CONSTRAINT_VIOLATION_INT_VALUE, null,
                 ERR_MEM_HANDLER_MOD_NO_USER_MOD.get(request.getDN(),
                      a.getName()), null));
          }
        }
      }


      // Perform the appropriate processing for the assertion and proxied
      // authorization controls.
      // Perform the appropriate processing for the assertion, pre-read,
      // post-read, and proxied authorization controls.
      final DN authzDN;
      try
      {
        handleAssertionRequestControl(controlMap, entry);

        authzDN = handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // Update modifiersName and modifyTimestamp.
      if (generateOperationalAttributes)
      {
        modifiedEntry.setAttribute(new Attribute("modifiersName",
             DistinguishedNameMatchingRule.getInstance(),
             authzDN.toString()));
        modifiedEntry.setAttribute(new Attribute("modifyTimestamp",
             GeneralizedTimeMatchingRule.getInstance(),
             StaticUtils.encodeGeneralizedTime(new Date())));
      }

      // Perform the appropriate processing for the pre-read and post-read
      // controls.
      final PreReadResponseControl preReadResponse =
           handlePreReadControl(controlMap, entry);
      if (preReadResponse != null)
      {
        responseControls.add(preReadResponse);
      }

      final PostReadResponseControl postReadResponse =
           handlePostReadControl(controlMap, modifiedEntry);
      if (postReadResponse != null)
      {
        responseControls.add(postReadResponse);
      }


      // Replace the entry in the map and return a success result.
      if (dn.equals(subschemaSubentryDN))
      {
        final Schema newSchema = new Schema(modifiedEntry);
        subschemaSubentryRef.set(new ReadOnlyEntry(modifiedEntry));
        schemaRef.set(newSchema);
        entryValidatorRef.set(new EntryValidator(newSchema));
      }
      else
      {
        entryMap.put(dn, new ReadOnlyEntry(modifiedEntry));
        indexDelete(entry);
        indexAdd(modifiedEntry);
      }
      addChangeLogEntry(request, authzDN);
      return new LDAPMessage(messageID,
           new ModifyResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                null, null),
           responseControls);
    }
  }



  /**
   * Checks to see if the provided modification targets a password attribute.
   * If so, then it makes sure that the modification is properly encoded.
   *
   * @param  mod    The modification being processed.
   * @param  entry  The entry being modified.
   * @param  mods   The full set of modifications.
   *
   * @return  The encoded form of the provided modification if appropriate, or
   *          the original modification if no encoding is needed.
   *
   * @throws  LDAPException  If a problem is encountered during processing.
   */
  @NotNull()
  private Modification encodeModificationPasswords(
                            @NotNull final Modification mod,
                            @NotNull final ReadOnlyEntry entry,
                            @NotNull final List<Modification> mods)
          throws LDAPException
  {
    // If the modification doesn't have any values, then we don't need to do
    // anything.
    final ASN1OctetString[] originalValues = mod.getRawValues();
    if (originalValues.length == 0)
    {
      return mod;
    }


    // If no password attributes are defined, or if no password encoders are
    // defined, then we don't need to do anything.
    // If no password attributes are defined, then we don't need to do anything.
    if (extendedPasswordAttributes.isEmpty() || passwordEncoders.isEmpty())
    {
      return mod;
    }


    // If the modification doesn't target a password attribute, then we don't
    // need to do anything.
    boolean isPasswordAttribute = false;
    for (final String passwordAttribute : extendedPasswordAttributes)
    {
      if (mod.getAttribute().getBaseName().equalsIgnoreCase(passwordAttribute))
      {
        isPasswordAttribute = true;
        break;
      }
    }

    if (! isPasswordAttribute)
    {
      return mod;
    }


    // Process the modification based on its modification type.
    final ASN1OctetString[] newValues =
         new ASN1OctetString[originalValues.length];
    for (int i=0; i < originalValues.length; i++)
    {
      newValues[i] = encodeModValue(originalValues[i], mod, entry, mods);
    }

    return new Modification(mod.getModificationType(), mod.getAttributeName(),
         newValues);
  }



  /**
   * Encodes the provided modification value, if necessary.
   *
   * @param  value  The modification value being processed.
   * @param  mod    The modification being processed.
   * @param  entry  The unaltered form of the entry being modified.
   * @param  mods   The full set of modifications being processed.
   *
   * @return  The encoded modification value, or the original value if no
   *          encoding is necessary.
   *
   * @throws  LDAPException  If a problem is encountered during processing.
   */
  @NotNull()
  private ASN1OctetString encodeModValue(@NotNull final ASN1OctetString value,
                                         @NotNull final Modification mod,
                                         @NotNull final ReadOnlyEntry entry,
                                         @NotNull final List<Modification> mods)
          throws LDAPException
  {
    // First, see if the password is already encoded.  If so, then just return
    // it if that encoded representation looks valid.
    for (final InMemoryPasswordEncoder encoder : passwordEncoders)
    {
      if (encoder.passwordStartsWithPrefix(value))
      {
        encoder.ensurePreEncodedPasswordAppearsValid(value, entry, mods);
        return value;
      }
    }


    // If the modification type is add or replace, then we should just encode
    // the password in accordance with the primary encoder.
    final ModificationType modificationType = mod.getModificationType();
    if ((modificationType == ModificationType.ADD) ||
        (modificationType == ModificationType.REPLACE))
    {
      // If there is no primary password encoder, then just leave the value in
      // the clear.  Otherwise, encode it with the primary encoder.
      if (primaryPasswordEncoder == null)
      {
        return value;
      }
      else
      {
        return primaryPasswordEncoder.encodePassword(value, entry, mods);
      }
    }


    // If the modification type is a delete, then we should see if the
    // clear-text value matches any of the values stored in the entry, whether
    // encoded or not.  If the provided clear-text password matches an existing
    // encoded value, then we'll return the encoded value.  If the clear-text
    // password matches an existing clear-text password, then we'll return that
    // clear-text password.  But even if it doesn't match anything, then we'll
    // still return the clear-text password.
    if (modificationType == ModificationType.DELETE)
    {
      final Attribute existingAttribute =
           entry.getAttribute(mod.getAttributeName());
      if (existingAttribute == null)
      {
        return value;
      }

      for (final ASN1OctetString existingValue :
           existingAttribute.getRawValues())
      {
        if (value.equalsIgnoreType(existingValue))
        {
          return value;
        }

        for (final InMemoryPasswordEncoder encoder : passwordEncoders)
        {
          if (encoder.clearPasswordMatchesEncodedPassword(value, existingValue,
                   entry))
          {
            return existingValue;
          }
        }
      }

      return value;
    }


    // The only way we should be able to get here is for an increment
    // modification type, which is just stupid.  But in that case, we'll just
    // return the value as-is.
    return value;
  }



  /**
   * Validates a modify request targeting the server schema.  Modifications to
   * attribute syntaxes and matching rules will not be allowed.  Modifications
   * to other schema elements will only be allowed for add and delete
   * modification types, and adds will only be allowed with a valid syntax.
   *
   * @param  request  The modify request to validate.
   *
   * @throws  LDAPException  If a problem is encountered.
   */
  private void validateSchemaMods(
                    @NotNull final ModifyRequestProtocolOp request)
          throws LDAPException
  {
    // If there is no schema, then we won't allow modifications at all.
    if (schemaRef.get() == null)
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_MEM_HANDLER_MOD_SCHEMA.get(subschemaSubentryDN.toString()));
    }


    for (final Modification m : request.getModifications())
    {
      // If the modification targets attribute syntaxes or matching rules, then
      // reject it.
      final String attrName = m.getAttributeName();
      if (attrName.equalsIgnoreCase(Schema.ATTR_ATTRIBUTE_SYNTAX) ||
           attrName.equalsIgnoreCase(Schema.ATTR_MATCHING_RULE))
      {
        throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
             ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_ATTR.get(attrName));
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_ATTRIBUTE_TYPE))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new AttributeTypeDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_OBJECT_CLASS))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new ObjectClassDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_NAME_FORM))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new NameFormDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_DIT_CONTENT_RULE))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new DITContentRuleDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_DIT_STRUCTURE_RULE))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new DITStructureRuleDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
      else if (attrName.equalsIgnoreCase(Schema.ATTR_MATCHING_RULE_USE))
      {
        if (m.getModificationType() == ModificationType.ADD)
        {
          for (final String value : m.getValues())
          {
            new MatchingRuleUseDefinition(value);
          }
        }
        else if (m.getModificationType() != ModificationType.DELETE)
        {
          throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
               ERR_MEM_HANDLER_MOD_SCHEMA_DISALLOWED_MOD_TYPE.get(
                    m.getModificationType().getName(), attrName));
        }
      }
    }
  }



  /**
   * Processes the provided modify DN request.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify DN operations are
   * allowed in the server.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  @NotNull()
  public LDAPResult modifyDN(@NotNull final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(modifyDNRequest.getControlList());
    requestControlList.add(new Control(OID_INTERNAL_OPERATION_REQUEST_CONTROL,
         false));

    final LDAPMessage responseMessage = processModifyDNRequest(
         1, new ModifyDNRequestProtocolOp(modifyDNRequest.getDN(),
              modifyDNRequest.getNewRDN(), modifyDNRequest.deleteOldRDN(),
              modifyDNRequest.getNewSuperiorDN()),
         requestControlList);

    final ModifyDNResponseProtocolOp modifyDNResponse =
         responseMessage.getModifyDNResponseProtocolOp();

    final LDAPResult ldapResult = new LDAPResult(responseMessage.getMessageID(),
         ResultCode.valueOf(modifyDNResponse.getResultCode()),
         modifyDNResponse.getDiagnosticMessage(),
         modifyDNResponse.getMatchedDN(), modifyDNResponse.getReferralURLs(),
         responseMessage.getControls());

    switch (modifyDNResponse.getResultCode())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;
      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Attempts to process the provided modify DN request.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The modify DN request contains a malformed target DN, new RDN, or
   *       new superior DN.</LI>
   *   <LI>The original or new DN is that of the root DSE.</LI>
   *   <LI>The original or new DN is that of the subschema subentry.</LI>
   *   <LI>The new DN of the entry would conflict with the DN of an existing
   *       entry.</LI>
   *   <LI>The new DN of the entry would exist outside the set of defined
   *       base DNs.</LI>
   *   <LI>The new DN of the entry is not a defined base DN and does not exist
   *       immediately below an existing entry.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the modify
   *                    DN request.
   * @param  request    The modify DN request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ModifyDNResponseProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          @NotNull final ModifyDNRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      sleepBeforeProcessing();

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(
                OperationType.MODIFY_DN)))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MODIFY_DN_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.MODIFY_DN)))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_MODIFY_DN_REQUIRES_AUTH.get(), null));
      }


      // See if this modify DN request is part of a transaction.  If so, then
      // perform appropriate processing for it and return success immediately
      // without actually doing any further processing.
      try
      {
        final ASN1OctetString txnID =
             processTransactionRequest(messageID, request, controlMap);
        if (txnID != null)
        {
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.SUCCESS_INT_VALUE, null,
               INFO_MEM_HANDLER_OP_IN_TXN.get(txnID.stringValue()), null));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID,
             new ModifyDNResponseProtocolOp(le.getResultCode().intValue(),
                  le.getMatchedDN(), le.getDiagnosticMessage(),
                  StaticUtils.toList(le.getReferralURLs())),
             le.getResponseControls());
      }


      // Get the parsed target DN, new RDN, and new superior DN values.
      final DN dn;
      final Schema schema = schemaRef.get();
      try
      {
        dn = new DN(request.getDN(), schema);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_MALFORMED_DN.get(request.getDN(),
                  le.getMessage()),
             null));
      }

      final RDN newRDN;
      try
      {
        newRDN = new RDN(request.getNewRDN(), schema);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_MALFORMED_NEW_RDN.get(request.getDN(),
                  request.getNewRDN(), le.getMessage()),
             null));
      }

      final DN newSuperiorDN;
      final String newSuperiorString = request.getNewSuperiorDN();
      if (newSuperiorString == null)
      {
        newSuperiorDN = null;
      }
      else
      {
        try
        {
          newSuperiorDN = new DN(newSuperiorString, schema);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
               ERR_MEM_HANDLER_MOD_DN_MALFORMED_NEW_SUPERIOR.get(
                    request.getDN(), request.getNewSuperiorDN(),
                    le.getMessage()),
               null));
        }
      }

      // See if the target entry or one of its superiors is a smart referral.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(dn);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(dn, referralEntry)));
        }
      }

      // See if the target is the root DSE, the subschema subentry, or a
      // changelog entry.
      if (dn.isNullDN())
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_ROOT_DSE.get(), null));
      }
      else if (dn.equals(subschemaSubentryDN))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_SOURCE_IS_SCHEMA.get(), null));
      }
      else if (dn.isDescendantOf(changeLogBaseDN, true))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_SOURCE_IS_CHANGELOG.get(), null));
      }

      // Construct the new DN.
      final DN newDN;
      if (newSuperiorDN == null)
      {
        final DN originalParent = dn.getParent();
        if (originalParent == null)
        {
          newDN = new DN(newRDN);
        }
        else
        {
          newDN = new DN(newRDN, originalParent);
        }
      }
      else
      {
        newDN = new DN(newRDN, newSuperiorDN);
      }

      // If the new DN matches the old DN, then fail.
      if (newDN.equals(dn))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_NEW_DN_SAME_AS_OLD.get(request.getDN()),
             null));
      }

      // If the new DN is below a smart referral, then fail.
      if (! controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
      {
        final Entry referralEntry = findNearestReferral(newDN);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, referralEntry.getDN(),
               ERR_MEM_HANDLER_MOD_DN_NEW_DN_BELOW_REFERRAL.get(request.getDN(),
                    referralEntry.getDN().toString(), newDN.toString()),
               null));
        }
      }

      // If the target entry doesn't exist, then fail.
      final Entry originalEntry = entryMap.get(dn);
      if (originalEntry == null)
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
             ERR_MEM_HANDLER_MOD_DN_NO_SUCH_ENTRY.get(request.getDN()), null));
      }

      // If the new DN matches the subschema subentry DN, then fail.
      if (newDN.equals(subschemaSubentryDN))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_TARGET_IS_SCHEMA.get(request.getDN(),
                  newDN.toString()),
             null));
      }

      // If the new DN is at or below the changelog base DN, then fail.
      if (newDN.isDescendantOf(changeLogBaseDN, true))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_TARGET_IS_CHANGELOG.get(request.getDN(),
                  newDN.toString()),
             null));
      }

      // If the new DN already exists, then fail.
      if (entryMap.containsKey(newDN))
      {
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.ENTRY_ALREADY_EXISTS_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_TARGET_ALREADY_EXISTS.get(request.getDN(),
                  newDN.toString()),
             null));
      }

      // If the new DN is not a base DN and its parent does not exist, then
      // fail.
      if (baseDNs.contains(newDN))
      {
        // The modify DN can be processed.
      }
      else
      {
        final DN newParent = newDN.getParent();
        if ((newParent != null) && entryMap.containsKey(newParent))
        {
          // The modify DN can be processed.
        }
        else
        {
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(newDN),
               ERR_MEM_HANDLER_MOD_DN_PARENT_DOESNT_EXIST.get(request.getDN(),
                    newDN.toString()),
               null));
        }
      }

      // Create a copy of the entry and update it to reflect the new DN (with
      // attribute value changes).
      final RDN originalRDN = dn.getRDN();
      final Entry updatedEntry = originalEntry.duplicate();
      updatedEntry.setDN(newDN);
      if (request.deleteOldRDN())
      {
        final String[] oldRDNNames  = originalRDN.getAttributeNames();
        final byte[][] oldRDNValues = originalRDN.getByteArrayAttributeValues();
        for (int i=0; i < oldRDNNames.length; i++)
        {
          updatedEntry.removeAttributeValue(oldRDNNames[i], oldRDNValues[i]);
        }
      }

      final String[] newRDNNames  = newRDN.getAttributeNames();
      final byte[][] newRDNValues = newRDN.getByteArrayAttributeValues();
      for (int i=0; i < newRDNNames.length; i++)
      {
        final MatchingRule matchingRule =
             MatchingRule.selectEqualityMatchingRule(newRDNNames[i], schema);
        updatedEntry.addAttribute(new Attribute(newRDNNames[i], matchingRule,
             newRDNValues[i]));
      }

      // If a schema was provided, then make sure the updated entry conforms to
      // the schema.  Also, reject the attempt if any of the new RDN attributes
      // is marked with NO-USER-MODIFICATION.
      final EntryValidator entryValidator = entryValidatorRef.get();
      if (entryValidator != null)
      {
        final ArrayList<String> invalidReasons = new ArrayList<>(1);
        if (! entryValidator.entryIsValid(updatedEntry, invalidReasons))
        {
          return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
               ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE, null,
               ERR_MEM_HANDLER_MOD_DN_VIOLATES_SCHEMA.get(request.getDN(),
                    StaticUtils.concatenateStrings(invalidReasons)),
               null));
        }

        final String[] oldRDNNames = originalRDN.getAttributeNames();
        for (int i=0; i < oldRDNNames.length; i++)
        {
          final String name = oldRDNNames[i];
          final AttributeTypeDefinition at = schema.getAttributeType(name);
          if ((! isInternalOp) && (at != null) && at.isNoUserModification())
          {
            final byte[] value = originalRDN.getByteArrayAttributeValues()[i];
            if (! updatedEntry.hasAttributeValue(name, value))
            {
              return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
                   ResultCode.CONSTRAINT_VIOLATION_INT_VALUE, null,
                   ERR_MEM_HANDLER_MOD_DN_NO_USER_MOD.get(request.getDN(),
                        name), null));
            }
          }
        }

        for (int i=0; i < newRDNNames.length; i++)
        {
          final String name = newRDNNames[i];
          final AttributeTypeDefinition at = schema.getAttributeType(name);
          if ((! isInternalOp) && (at != null) && at.isNoUserModification())
          {
            final byte[] value = newRDN.getByteArrayAttributeValues()[i];
            if (! originalEntry.hasAttributeValue(name, value))
            {
              return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
                   ResultCode.CONSTRAINT_VIOLATION_INT_VALUE, null,
                   ERR_MEM_HANDLER_MOD_DN_NO_USER_MOD.get(request.getDN(),
                        name), null));
            }
          }
        }
      }

      // Perform the appropriate processing for the assertion and proxied
      // authorization controls
      final DN authzDN;
      try
      {
        handleAssertionRequestControl(controlMap, originalEntry);

        authzDN = handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // Update the modifiersName, modifyTimestamp, and entryDN operational
      // attributes.
      if (generateOperationalAttributes)
      {
        updatedEntry.setAttribute(new Attribute("modifiersName",
             DistinguishedNameMatchingRule.getInstance(),
             authzDN.toString()));
        updatedEntry.setAttribute(new Attribute("modifyTimestamp",
             GeneralizedTimeMatchingRule.getInstance(),
             StaticUtils.encodeGeneralizedTime(new Date())));
        updatedEntry.setAttribute(new Attribute("entryDN",
             DistinguishedNameMatchingRule.getInstance(),
             newDN.toNormalizedString()));
      }

      // Perform the appropriate processing for the pre-read and post-read
      // controls.
      final PreReadResponseControl preReadResponse =
           handlePreReadControl(controlMap, originalEntry);
      if (preReadResponse != null)
      {
        responseControls.add(preReadResponse);
      }

      final PostReadResponseControl postReadResponse =
           handlePostReadControl(controlMap, updatedEntry);
      if (postReadResponse != null)
      {
        responseControls.add(postReadResponse);
      }

      // Remove the old entry and add the new one.
      entryMap.remove(dn);
      entryMap.put(newDN, new ReadOnlyEntry(updatedEntry));
      indexDelete(originalEntry);
      indexAdd(updatedEntry);

      // If the target entry had any subordinates, then rename them as well.
      final RDN[] oldDNComps = dn.getRDNs();
      final RDN[] newDNComps = newDN.getRDNs();
      final Set<DN> dnSet = new LinkedHashSet<>(entryMap.keySet());
      for (final DN mapEntryDN : dnSet)
      {
        if (mapEntryDN.isDescendantOf(dn, false))
        {
          final Entry o = entryMap.remove(mapEntryDN);
          final Entry e = o.duplicate();

          final RDN[] oldMapEntryComps = mapEntryDN.getRDNs();
          final int compsToSave = oldMapEntryComps.length - oldDNComps.length;

          final RDN[] newMapEntryComps =
               new RDN[compsToSave + newDNComps.length];
          System.arraycopy(oldMapEntryComps, 0, newMapEntryComps, 0,
               compsToSave);
          System.arraycopy(newDNComps, 0, newMapEntryComps, compsToSave,
               newDNComps.length);

          final DN newMapEntryDN = new DN(newMapEntryComps);
          e.setDN(newMapEntryDN);
          if (generateOperationalAttributes)
          {
            e.setAttribute(new Attribute("entryDN",
                 DistinguishedNameMatchingRule.getInstance(),
                 newMapEntryDN.toNormalizedString()));
          }
          entryMap.put(newMapEntryDN, new ReadOnlyEntry(e));
          indexDelete(o);
          indexAdd(e);
          handleReferentialIntegrityModifyDN(mapEntryDN, newMapEntryDN);
        }
      }

      addChangeLogEntry(request, authzDN);
      handleReferentialIntegrityModifyDN(dn, newDN);
      return new LDAPMessage(messageID,
           new ModifyDNResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                null, null),
           responseControls);
    }
  }



  /**
   * Handles any appropriate referential integrity processing for a modify DN
   * operation.
   *
   * @param  oldDN  The old DN for the entry.
   * @param  newDN  The new DN for the entry.
   */
  private void handleReferentialIntegrityModifyDN(@NotNull final DN oldDN,
                                                  @NotNull final DN newDN)
  {
    if (referentialIntegrityAttributes.isEmpty())
    {
      return;
    }

    final ArrayList<DN> entryDNs = new ArrayList<>(entryMap.keySet());
    for (final DN mapDN : entryDNs)
    {
      final ReadOnlyEntry e = entryMap.get(mapDN);

      boolean referenceFound = false;
      final Schema schema = schemaRef.get();
      for (final String attrName : referentialIntegrityAttributes)
      {
        final Attribute a = e.getAttribute(attrName, schema);
        if ((a != null) &&
            a.hasValue(oldDN.toNormalizedString(),
                 DistinguishedNameMatchingRule.getInstance()))
        {
          referenceFound = true;
          break;
        }
      }

      if (referenceFound)
      {
        final Entry copy = e.duplicate();
        for (final String attrName : referentialIntegrityAttributes)
        {
          if (copy.removeAttributeValue(attrName, oldDN.toNormalizedString(),
                   DistinguishedNameMatchingRule.getInstance()))
          {
            copy.addAttribute(attrName, newDN.toString());
          }
        }
        entryMap.put(mapDN, new ReadOnlyEntry(copy));
        indexDelete(e);
        indexAdd(copy);
      }
    }
  }



  /**
   * Attempts to process the provided search request.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The modify DN request contains a malformed target DN, new RDN, or
   *       new superior DN.</LI>
   *   <LI>The new DN of the entry would conflict with the DN of an existing
   *       entry.</LI>
   *   <LI>The new DN of the entry would exist outside the set of defined
   *       base DNs.</LI>
   *   <LI>The new DN of the entry is not a defined base DN and does not exist
   *       immediately below an existing entry.</LI>
   * </UL>
   *
   * @param  messageID  The message ID of the LDAP message containing the search
   *                    request.
   * @param  request    The search request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code SearchResultDoneProtocolOp}.
   */
  @Override()
  @NotNull()
  public LDAPMessage processSearchRequest(final int messageID,
                          @NotNull final SearchRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    synchronized (entryMap)
    {
      final List<SearchResultEntry> entryList =
           new ArrayList<>(entryMap.size());
      final List<SearchResultReference> referenceList =
           new ArrayList<>(entryMap.size());

      final LDAPMessage returnMessage = processSearchRequest(messageID, request,
           controls, entryList, referenceList);

      for (final SearchResultEntry e : entryList)
      {
        try
        {
          connection.sendSearchResultEntry(messageID, e, e.getControls());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(le.getResultCode().intValue(),
                    le.getMatchedDN(), le.getDiagnosticMessage(),
                    StaticUtils.toList(le.getReferralURLs())),
               le.getResponseControls());
        }
      }

      for (final SearchResultReference r : referenceList)
      {
        try
        {
          connection.sendSearchResultReference(messageID,
               new SearchResultReferenceProtocolOp(
                    StaticUtils.toList(r.getReferralURLs())),
               r.getControls());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(le.getResultCode().intValue(),
                    le.getMatchedDN(), le.getDiagnosticMessage(),
                    StaticUtils.toList(le.getReferralURLs())),
               le.getResponseControls());
        }
      }

      return returnMessage;
    }
  }



  /**
   * Attempts to process the provided search request.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>There is a problem with any of the request controls.</LI>
   *   <LI>The modify DN request contains a malformed target DN, new RDN, or
   *       new superior DN.</LI>
   *   <LI>The new DN of the entry would conflict with the DN of an existing
   *       entry.</LI>
   *   <LI>The new DN of the entry would exist outside the set of defined
   *       base DNs.</LI>
   *   <LI>The new DN of the entry is not a defined base DN and does not exist
   *       immediately below an existing entry.</LI>
   * </UL>
   *
   * @param  messageID      The message ID of the LDAP message containing the
   *                        search request.
   * @param  request        The search request that was included in the LDAP
   *                        message that was received.
   * @param  controls       The set of controls included in the LDAP message.
   *                        It may be empty if there were no controls, but will
   *                        not be {@code null}.
   * @param  entryList      A list to which to add search result entries
   *                        intended for return to the client.  It must not be
   *                        {@code null}.
   * @param  referenceList  A list to which to add search result references
   *                        intended for return to the client.  It must not be
   *                        {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code SearchResultDoneProtocolOp}.
   */
  @NotNull()
  LDAPMessage processSearchRequest(final int messageID,
                   @NotNull final SearchRequestProtocolOp request,
                   @NotNull final List<Control> controls,
                   @NotNull final List<SearchResultEntry> entryList,
                   @NotNull final List<SearchResultReference> referenceList)
  {
    synchronized (entryMap)
    {
      // Sleep before processing, if appropriate.
      final long processingStartTime = System.currentTimeMillis();
      sleepBeforeProcessing();

      // Look at the filter and see if it contains any unsupported elements.
      try
      {
        ensureFilterSupported(request.getFilter());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // Look at the time limit for the search request and see if sleeping
      // would have caused us to exceed that time limit.  It's extremely
      // unlikely that any search in the in-memory directory server would take
      // a second or more to complete, and that's the minimum time limit that
      // can be requested, so there's no need to check the time limit in most
      // cases.  However, someone may want to force a "time limit exceeded"
      // response by configuring a delay that is greater than the requested time
      // limit, so we should check now to see if that's been exceeded.
      final long timeLimitMillis = 1000L * request.getTimeLimit();
      if (timeLimitMillis > 0L)
      {
        final long timeLimitExpirationTime =
             processingStartTime + timeLimitMillis;
        if (System.currentTimeMillis() >= timeLimitExpirationTime)
        {
          return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
               ResultCode.TIME_LIMIT_EXCEEDED_INT_VALUE, null,
               ERR_MEM_HANDLER_TIME_LIMIT_EXCEEDED.get(), null));
        }
      }

      // Process the provided request controls.
      final Map<String,Control> controlMap;
      try
      {
        controlMap = RequestControlPreProcessor.processControls(
             LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST, controls);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }
      final ArrayList<Control> responseControls = new ArrayList<>(1);


      // If this operation type is not allowed, then reject it.
      final boolean isInternalOp =
           controlMap.containsKey(OID_INTERNAL_OPERATION_REQUEST_CONTROL);
      if ((! isInternalOp) &&
           (! config.getAllowedOperationTypes().contains(OperationType.SEARCH)))
      {
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
             ERR_MEM_HANDLER_SEARCH_NOT_ALLOWED.get(), null));
      }


      // If this operation type requires authentication, then ensure that the
      // client is authenticated.
      if ((authenticatedDN.isNullDN() &&
           config.getAuthenticationRequiredOperationTypes().contains(
                OperationType.SEARCH)))
      {
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS_INT_VALUE, null,
             ERR_MEM_HANDLER_SEARCH_REQUIRES_AUTH.get(), null));
      }


      // Get the parsed base DN.
      final DN baseDN;
      final Schema schema = schemaRef.get();
      try
      {
        baseDN = new DN(request.getBaseDN(), schema);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_SEARCH_MALFORMED_BASE.get(request.getBaseDN(),
                  le.getMessage()),
             null));
      }

      // See if the search base or one of its superiors is a smart referral.
      final boolean hasManageDsaIT = controlMap.containsKey(
           ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID);
      if (! hasManageDsaIT)
      {
        final Entry referralEntry = findNearestReferral(baseDN);
        if (referralEntry != null)
        {
          return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
               ResultCode.REFERRAL_INT_VALUE, referralEntry.getDN(),
               INFO_MEM_HANDLER_REFERRAL_ENCOUNTERED.get(),
               getReferralURLs(baseDN, referralEntry)));
        }
      }

      // Make sure that the base entry exists.  It may be the root DSE or
      // subschema subentry.
      final Entry baseEntry;
      boolean includeChangeLog = true;
      if (baseDN.isNullDN())
      {
        baseEntry = generateRootDSE();
        includeChangeLog = false;
      }
      else if (baseDN.equals(subschemaSubentryDN))
      {
        baseEntry = subschemaSubentryRef.get();
      }
      else
      {
        baseEntry = entryMap.get(baseDN);
      }

      if (baseEntry == null)
      {
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(baseDN),
             ERR_MEM_HANDLER_SEARCH_BASE_DOES_NOT_EXIST.get(
                  request.getBaseDN()),
             null));
      }

      // Perform any necessary processing for the assertion and proxied auth
      // controls.
      try
      {
        handleAssertionRequestControl(controlMap, baseEntry);
        handleProxiedAuthControl(controlMap);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
             le.getResultCode().intValue(), null, le.getMessage(), null));
      }

      // Determine whether to include subentries in search results.
      final boolean includeSubEntries;
      final boolean includeNonSubEntries;
      final SearchScope scope = request.getScope();
      if (scope == SearchScope.BASE)
      {
        includeSubEntries = true;
        includeNonSubEntries = true;
      }
      else if (controlMap.containsKey(
           DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID))
      {
        includeSubEntries = true;
        includeNonSubEntries = false;
      }
      else if (controlMap.containsKey(
           RFC3672SubentriesRequestControl.SUBENTRIES_REQUEST_OID))
      {
        includeSubEntries = true;

        final RFC3672SubentriesRequestControl c =
             (RFC3672SubentriesRequestControl) controlMap.get(
                  RFC3672SubentriesRequestControl.SUBENTRIES_REQUEST_OID);
        includeNonSubEntries = (! c.returnOnlySubEntries());
      }
      else if (baseEntry.hasObjectClass("ldapSubEntry") ||
               baseEntry.hasObjectClass("inheritableLDAPSubEntry"))
      {
        includeSubEntries = true;
        includeNonSubEntries = true;
      }
      else if (filterIncludesLDAPSubEntry(request.getFilter()))
      {
        includeSubEntries = true;
        includeNonSubEntries = true;
      }
      else
      {
        includeSubEntries = false;
        includeNonSubEntries = true;
      }

      // Create a temporary list to hold all of the entries to be returned.
      // These entries will not have been pared down based on the requested
      // attributes.
      final List<Entry> fullEntryList = new ArrayList<>(entryMap.size());

findEntriesAndRefs:
      {
        // Check the scope.  If it is a base-level search, then we only need to
        // examine the base entry.  Otherwise, we'll have to scan the entire
        // entry map.
        final Filter filter = request.getFilter();
        if (scope == SearchScope.BASE)
        {
          try
          {
            if (filter.matchesEntry(baseEntry, schema))
            {
              processSearchEntry(baseEntry, includeSubEntries,
                   includeNonSubEntries, includeChangeLog, hasManageDsaIT,
                   fullEntryList, referenceList);
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }

          break findEntriesAndRefs;
        }

        // If the search uses a single-level scope and the base DN is the root
        // DSE, then we will only examine the defined base entries for the data
        // set.
        if ((scope == SearchScope.ONE) && baseDN.isNullDN())
        {
          for (final DN dn : baseDNs)
          {
            final Entry e = entryMap.get(dn);
            if (e != null)
            {
              try
              {
                if (filter.matchesEntry(e, schema))
                {
                  processSearchEntry(e, includeSubEntries, includeNonSubEntries,
                       includeChangeLog, hasManageDsaIT, fullEntryList,
                       referenceList);
                }
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);
              }
            }
          }

          break findEntriesAndRefs;
        }


        // Try to use indexes to process the request.  If we can't use any
        // indexes to get a candidate list, then just iterate over all the
        // entries.  It's not necessary to consider the root DSE for non-base
        // scopes.
        final Set<DN> candidateDNs = indexSearch(filter);
        if (candidateDNs == null)
        {
          for (final Map.Entry<DN,ReadOnlyEntry> me : entryMap.entrySet())
          {
            final DN dn = me.getKey();
            final Entry entry = me.getValue();
            try
            {
              if (dn.matchesBaseAndScope(baseDN, scope) &&
                   filter.matchesEntry(entry, schema))
              {
                processSearchEntry(entry, includeSubEntries,
                     includeNonSubEntries, includeChangeLog, hasManageDsaIT,
                     fullEntryList, referenceList);
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }
        }
        else
        {
          for (final DN dn : candidateDNs)
          {
            try
            {
              if (! dn.matchesBaseAndScope(baseDN, scope))
              {
                continue;
              }

              final Entry entry = entryMap.get(dn);
              if (filter.matchesEntry(entry, schema))
              {
                processSearchEntry(entry, includeSubEntries,
                     includeNonSubEntries, includeChangeLog, hasManageDsaIT,
                     fullEntryList, referenceList);
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }
        }
      }


      // If the request included the server-side sort request control, then sort
      // the matching entries appropriately.
      final ServerSideSortRequestControl sortRequestControl =
           (ServerSideSortRequestControl) controlMap.get(
                ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID);
      if (sortRequestControl != null)
      {
        final EntrySorter entrySorter = new EntrySorter(false, schema,
             sortRequestControl.getSortKeys());
        final SortedSet<Entry> sortedEntrySet = entrySorter.sort(fullEntryList);
        fullEntryList.clear();
        fullEntryList.addAll(sortedEntrySet);

        responseControls.add(new ServerSideSortResponseControl(
             ResultCode.SUCCESS, null));
      }


      // If the request included the simple paged results control, then handle
      // it.
      final SimplePagedResultsControl pagedResultsControl =
           (SimplePagedResultsControl)
                controlMap.get(SimplePagedResultsControl.PAGED_RESULTS_OID);
      if (pagedResultsControl != null)
      {
        final int totalSize = fullEntryList.size();
        final int pageSize = pagedResultsControl.getSize();
        final ASN1OctetString cookie = pagedResultsControl.getCookie();

        final int offset;
        if ((cookie == null) || (cookie.getValueLength() == 0))
        {
          // This is the first request in the series, so start at the beginning
          // of the list.
          offset = 0;
        }
        else
        {
          // The cookie value will simply be an integer representation of the
          // offset within the result list at which to start the next batch.
          try
          {
            final ASN1Integer offsetInteger =
                 ASN1Integer.decodeAsInteger(cookie.getValue());
            offset = offsetInteger.intValue();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return new LDAPMessage(messageID,
                 new SearchResultDoneProtocolOp(
                      ResultCode.PROTOCOL_ERROR_INT_VALUE, null,
                      ERR_MEM_HANDLER_MALFORMED_PAGED_RESULTS_COOKIE.get(),
                      null),
                 responseControls);
          }
        }

        // Create an iterator that will be used to remove entries from the
        // result set that are outside of the requested page of results.
        int pos = 0;
        final Iterator<Entry> iterator = fullEntryList.iterator();

        // First, remove entries at the beginning of the list until we hit the
        // offset.
        while (iterator.hasNext() && (pos < offset))
        {
          iterator.next();
          iterator.remove();
          pos++;
        }

        // Next, skip over the entries that should be returned.
        int keptEntries = 0;
        while (iterator.hasNext() && (keptEntries < pageSize))
        {
          iterator.next();
          pos++;
          keptEntries++;
        }

        // If there are still entries left, then remove them and create a cookie
        // to include in the response.  Otherwise, use an empty cookie.
        if (iterator.hasNext())
        {
          responseControls.add(new SimplePagedResultsControl(totalSize,
               new ASN1OctetString(new ASN1Integer(pos).encode()), false));
          while (iterator.hasNext())
          {
            iterator.next();
            iterator.remove();
          }
        }
        else
        {
          responseControls.add(new SimplePagedResultsControl(totalSize,
               new ASN1OctetString(), false));
        }
      }


      // If the request includes the virtual list view request control, then
      // handle it.
      final VirtualListViewRequestControl vlvRequest =
           (VirtualListViewRequestControl) controlMap.get(
                VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID);
      if (vlvRequest != null)
      {
        final int totalEntries = fullEntryList.size();
        final ASN1OctetString assertionValue = vlvRequest.getAssertionValue();

        // Figure out the position of the target entry in the list.
        int offset = vlvRequest.getTargetOffset();
        if (assertionValue == null)
        {
          // The offset is one-based, so we need to adjust it for the list's
          // zero-based offset.  Also, make sure to put it within the bounds of
          // the list.
          offset--;
          offset = Math.max(0, offset);
          offset = Math.min(fullEntryList.size(), offset);
        }
        else
        {
          final SortKey primarySortKey = sortRequestControl.getSortKeys()[0];

          final Entry testEntry = new Entry("cn=test", schema,
               new Attribute(primarySortKey.getAttributeName(),
                    assertionValue));

          final EntrySorter entrySorter =
               new EntrySorter(false, schema, primarySortKey);

          offset = fullEntryList.size();
          for (int i=0; i < fullEntryList.size(); i++)
          {
            if (entrySorter.compare(fullEntryList.get(i), testEntry) >= 0)
            {
              offset = i;
              break;
            }
          }
        }

        // Get the start and end positions based on the before and after counts.
        final int beforeCount = Math.max(0, vlvRequest.getBeforeCount());
        final int afterCount  = Math.max(0, vlvRequest.getAfterCount());

        final int start = Math.max(0, (offset - beforeCount));
        final int end =
             Math.min(fullEntryList.size(), (offset + afterCount + 1));

        // Create an iterator to use to alter the list so that it only contains
        // the appropriate set of entries.
        int pos = 0;
        final Iterator<Entry> iterator = fullEntryList.iterator();
        while (iterator.hasNext())
        {
          iterator.next();
          if ((pos < start) || (pos >= end))
          {
            iterator.remove();
          }
          pos++;
        }

        // Create the appropriate response control.
        responseControls.add(new VirtualListViewResponseControl((offset+1),
             totalEntries, ResultCode.SUCCESS, null));
      }


      // Process the set of requested attributes so that we can pare down the
      // entries.
      final SearchEntryParer parer = new SearchEntryParer(
           request.getAttributes(), schema);
      final int sizeLimit;
      if (request.getSizeLimit() > 0)
      {
        sizeLimit = Math.min(request.getSizeLimit(), maxSizeLimit);
      }
      else
      {
        sizeLimit = maxSizeLimit;
      }

      int entryCount = 0;
      for (final Entry e : fullEntryList)
      {
        entryCount++;
        if (entryCount > sizeLimit)
        {
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(
                    ResultCode.SIZE_LIMIT_EXCEEDED_INT_VALUE, null,
                    ERR_MEM_HANDLER_SEARCH_SIZE_LIMIT_EXCEEDED.get(), null),
               responseControls);
        }

        final Entry trimmedEntry = parer.pareEntry(e);
        if (request.typesOnly())
        {
          final Entry typesOnlyEntry = new Entry(trimmedEntry.getDN(), schema);
          for (final Attribute a : trimmedEntry.getAttributes())
          {
            typesOnlyEntry.addAttribute(new Attribute(a.getName()));
          }
          entryList.add(new SearchResultEntry(typesOnlyEntry));
        }
        else
        {
          entryList.add(new SearchResultEntry(trimmedEntry));
        }
      }

      return new LDAPMessage(messageID,
           new SearchResultDoneProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                null, null),
           responseControls);
    }
  }



  /**
   * Ensures that the provided filter is supported in the in-memory directory
   * server.
   *
   * @param  filter  The filter being validated.
   *
   * @throws  LDAPException  If the provided filter is not acceptable.
   */
  private static void ensureFilterSupported(@NotNull final Filter filter)
          throws LDAPException
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        // Make sure that all of the embedded components are supported.
        for (final Filter component : filter.getComponents())
        {
          ensureFilterSupported(component);
        }
        return;

      case Filter.FILTER_TYPE_NOT:
        // Make sure that the embedded component is supported.
        ensureFilterSupported(filter.getNOTComponent());
        return;

      case Filter.FILTER_TYPE_EQUALITY:
      case Filter.FILTER_TYPE_SUBSTRING:
      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
      case Filter.FILTER_TYPE_PRESENCE:
        // These are always acceptable.
        return;

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        // Approximate match filters are never supported.
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_MEM_HANDLER_FILTER_UNSUPPORTED_APPROXIMATE_MATCH_FILTER.get());

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        // Extensible match filters are never supported.
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_MEM_HANDLER_FILTER_UNSUPPORTED_EXTENSIBLE_MATCH_FILTER.get());

      default:
        // Unrecognized filter types are never supported.
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_MEM_HANDLER_FILTER_UNRECOGNIZED_FILTER_TYPE.get(
                  StaticUtils.toHex(filter.getFilterType())));
    }
  }



  /**
   * Indicates whether the provided filter includes a component that targets the
   * ldapSubEntry object class.
   *
   * @param  filter  The filter for which to make the determination.
   *
   * @return  {@code true} if the provided filter includes a component that
   *          targets the ldapSubEntry object class or {@code false} if not.
   */
  private static boolean filterIncludesLDAPSubEntry(
                              @NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        for (final Filter f : filter.getComponents())
        {
          if (filterIncludesLDAPSubEntry(f))
          {
            return true;
          }
        }
        return false;

      case Filter.FILTER_TYPE_EQUALITY:
        return  (filter.getAttributeName().equalsIgnoreCase("objectClass") ||
             filter.getAttributeName().equals("2.5.4.0"));

      default:
        return false;
    }
  }



  /**
   * Performs any necessary index processing to add the provided entry.
   *
   * @param  entry  The entry that has been added.
   */
  private void indexAdd(@NotNull final Entry entry)
  {
    for (final InMemoryDirectoryServerEqualityAttributeIndex i :
         equalityIndexes.values())
    {
      try
      {
        i.processAdd(entry);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }
  }



  /**
   * Performs any necessary index processing to delete the provided entry.
   *
   * @param  entry  The entry that has been deleted.
   */
  private void indexDelete(@NotNull final Entry entry)
  {
    for (final InMemoryDirectoryServerEqualityAttributeIndex i :
         equalityIndexes.values())
    {
      try
      {
        i.processDelete(entry);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }
  }



  /**
   * Attempts to use indexes to obtain a candidate list for the provided filter.
   *
   * @param  filter  The filter to be processed.
   *
   * @return  The DNs of entries which may match the given filter, or
   *          {@code null} if the filter is not indexed.
   */
  @Nullable()
  private Set<DN> indexSearch(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        Filter[] comps = filter.getComponents();
        if (comps.length == 0)
        {
          return null;
        }
        else if (comps.length == 1)
        {
          return indexSearch(comps[0]);
        }
        else
        {
          Set<DN> candidateSet = null;
          for (final Filter f : comps)
          {
            final Set<DN> dnSet = indexSearch(f);
            if (dnSet != null)
            {
              if (candidateSet == null)
              {
                candidateSet = new TreeSet<>(dnSet);
              }
              else
              {
                candidateSet.retainAll(dnSet);
              }
            }
          }
          return candidateSet;
        }

      case Filter.FILTER_TYPE_OR:
        comps = filter.getComponents();
        if (comps.length == 0)
        {
          return Collections.emptySet();
        }
        else if (comps.length == 1)
        {
          return indexSearch(comps[0]);
        }
        else
        {
          Set<DN> candidateSet = null;
          for (final Filter f : comps)
          {
            final Set<DN> dnSet = indexSearch(f);
            if (dnSet == null)
            {
              return null;
            }

            if (candidateSet == null)
            {
              candidateSet = new TreeSet<>(dnSet);
            }
            else
            {
              candidateSet.addAll(dnSet);
            }
          }
          return candidateSet;
        }

      case Filter.FILTER_TYPE_EQUALITY:
        final Schema schema = schemaRef.get();
        if (schema == null)
        {
          return null;
        }
        final AttributeTypeDefinition at =
             schema.getAttributeType(filter.getAttributeName());
        if (at == null)
        {
          return null;
        }
        final InMemoryDirectoryServerEqualityAttributeIndex i =
             equalityIndexes.get(at);
        if (i == null)
        {
          return null;
        }
        try
        {
          return i.getMatchingEntries(filter.getRawAssertionValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return null;
        }

      default:
        return null;
    }
  }



  /**
   * Determines whether the provided set of controls includes a transaction
   * specification request control.  If so, then it will verify that it
   * references a valid transaction for the client.  If the request is part of a
   * valid transaction, then the transaction specification request control will
   * be removed and the request will be stashed in the client connection state
   * so that it can be retrieved and processed when the transaction is
   * committed.
   *
   * @param  messageID  The message ID for the request to be processed.
   * @param  request    The protocol op for the request to be processed.
   * @param  controls   The set of controls for the request to be processed.
   *
   * @return  The transaction ID for the associated transaction, or {@code null}
   *          if the request is not part of any transaction.
   *
   * @throws  LDAPException  If the transaction specification request control is
   *                         present but does not refer to a valid transaction
   *                         for the associated client connection.
   */
  @SuppressWarnings("unchecked")
  @Nullable()
  private ASN1OctetString processTransactionRequest(final int messageID,
                               @NotNull final ProtocolOp request,
                               @NotNull final Map<String,Control> controls)
          throws LDAPException
  {
    final TransactionSpecificationRequestControl txnControl =
         (TransactionSpecificationRequestControl)
         controls.remove(TransactionSpecificationRequestControl.
              TRANSACTION_SPECIFICATION_REQUEST_OID);
    if (txnControl == null)
    {
      return null;
    }

    // See if the client has an active transaction.  If not, then fail.
    final ASN1OctetString txnID = txnControl.getTransactionID();
    final ObjectPair<ASN1OctetString,List<LDAPMessage>> txnInfo =
         (ObjectPair<ASN1OctetString,List<LDAPMessage>>) connectionState.get(
              TransactionExtendedOperationHandler.STATE_VARIABLE_TXN_INFO);
    if (txnInfo == null)
    {
      throw new LDAPException(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
           ERR_MEM_HANDLER_TXN_CONTROL_WITHOUT_TXN.get(txnID.stringValue()));
    }


    // Make sure that the active transaction has a transaction ID that matches
    // the transaction ID from the control.  If not, then abort the existing
    // transaction and fail.
    final ASN1OctetString existingTxnID = txnInfo.getFirst();
    if (! txnID.stringValue().equals(existingTxnID.stringValue()))
    {
      connectionState.remove(
           TransactionExtendedOperationHandler.STATE_VARIABLE_TXN_INFO);
      connection.sendUnsolicitedNotification(
           new AbortedTransactionExtendedResult(existingTxnID,
                ResultCode.CONSTRAINT_VIOLATION,
                ERR_MEM_HANDLER_TXN_ABORTED_BY_CONTROL_TXN_ID_MISMATCH.get(
                     existingTxnID.stringValue(), txnID.stringValue()),
                null, null, null));
      throw new LDAPException(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
           ERR_MEM_HANDLER_TXN_CONTROL_ID_MISMATCH.get(txnID.stringValue(),
                existingTxnID.stringValue()));
    }


    // Stash the request in the transaction state information so that it will
    // be processed when the transaction is committed.
    txnInfo.getSecond().add(new LDAPMessage(messageID, request,
         new ArrayList<>(controls.values())));

    return txnID;
  }



  /**
   * Sleeps for a period of time (if appropriate) before beginning processing
   * for an operation.
   */
  private void sleepBeforeProcessing()
  {
    final long delay = processingDelayMillis.get();
    if (delay > 0)
    {
      try
      {
        Thread.sleep(delay);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
        }
      }
    }
  }



  /**
   * Retrieves the configured list of password attributes.
   *
   * @return  The configured list of password attributes.
   */
  @NotNull()
  public List<String> getPasswordAttributes()
  {
    return configuredPasswordAttributes;
  }



  /**
   * Retrieves the primary password encoder that has been configured for the
   * server.
   *
   * @return  The primary password encoder that has been configured for the
   *          server.
   */
  @Nullable()
  public InMemoryPasswordEncoder getPrimaryPasswordEncoder()
  {
    return primaryPasswordEncoder;
  }



  /**
   * Retrieves a list of all password encoders configured for the server.
   *
   * @return  A list of all password encoders configured for the server.
   */
  @NotNull()
  public List<InMemoryPasswordEncoder> getAllPasswordEncoders()
  {
    return passwordEncoders;
  }



  /**
   * Retrieves a list of the passwords contained in the provided entry.
   *
   * @param  entry                 The entry from which to obtain the list of
   *                               passwords.  It must not be {@code null}.
   * @param  clearPasswordToMatch  An optional clear-text password that should
   *                               match the values that are returned.  If this
   *                               is {@code null}, then all passwords contained
   *                               in the provided entry will be returned.  If
   *                               this is non-{@code null}, then only passwords
   *                               matching the clear-text password will be
   *                               returned.
   *
   * @return  A list of the passwords contained in the provided entry,
   *          optionally restricted to those matching the provided clear-text
   *          password, or an empty list if the entry does not contain any
   *          passwords.
   */
  @NotNull()
  public List<InMemoryDirectoryServerPassword> getPasswordsInEntry(
              @NotNull final Entry entry,
              @Nullable final ASN1OctetString clearPasswordToMatch)
  {
    final ArrayList<InMemoryDirectoryServerPassword> passwordList =
         new ArrayList<>(5);
    final ReadOnlyEntry readOnlyEntry = new ReadOnlyEntry(entry);

    for (final String passwordAttributeName : configuredPasswordAttributes)
    {
      final List<Attribute> passwordAttributeList =
           entry.getAttributesWithOptions(passwordAttributeName, null);

      for (final Attribute passwordAttribute : passwordAttributeList)
      {
        for (final ASN1OctetString value : passwordAttribute.getRawValues())
        {
          final InMemoryDirectoryServerPassword password =
               new InMemoryDirectoryServerPassword(value, readOnlyEntry,
                    passwordAttribute.getName(), passwordEncoders);

          if (clearPasswordToMatch != null)
          {
            try
            {
              if (! password.matchesClearPassword(clearPasswordToMatch))
              {
                continue;
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              continue;
            }
          }

          passwordList.add(new InMemoryDirectoryServerPassword(value,
               readOnlyEntry, passwordAttribute.getName(), passwordEncoders));
        }
      }
    }

    return passwordList;
  }



  /**
   * Retrieves the number of entries currently held in the server.
   *
   * @param  includeChangeLog  Indicates whether to include entries that are
   *                           part of the changelog in the count.
   *
   * @return  The number of entries currently held in the server.
   */
  public int countEntries(final boolean includeChangeLog)
  {
    synchronized (entryMap)
    {
      if (includeChangeLog || (maxChangelogEntries == 0))
      {
        return entryMap.size();
      }
      else
      {
        int count = 0;

        for (final DN dn : entryMap.keySet())
        {
          if (! dn.isDescendantOf(changeLogBaseDN, true))
          {
            count++;
          }
        }

        return count;
      }
    }
  }



  /**
   * Retrieves the number of entries currently held in the server whose DN
   * matches or is subordinate to the provided base DN.
   *
   * @param  baseDN  The base DN to use for the determination.
   *
   * @return  The number of entries currently held in the server whose DN
   *          matches or is subordinate to the provided base DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public int countEntriesBelow(@NotNull final String baseDN)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final DN parsedBaseDN = new DN(baseDN, schemaRef.get());

      int count = 0;
      for (final DN dn : entryMap.keySet())
      {
        if (dn.isDescendantOf(parsedBaseDN, true))
        {
          count++;
        }
      }

      return count;
    }
  }



  /**
   * Removes all entries currently held in the server.  If a changelog is
   * enabled, then all changelog entries will also be cleared but the base
   * "cn=changelog" entry will be retained.
   */
  public void clear()
  {
    synchronized (entryMap)
    {
      restoreSnapshot(initialSnapshot);
    }
  }



  /**
   * Reads entries from the provided LDIF reader and adds them to the server,
   * optionally clearing any existing entries before beginning to add the new
   * entries.  If an error is encountered while adding entries from LDIF then
   * the server will remain populated with the data it held before the import
   * attempt (even if the {@code clear} is given with a value of {@code true}).
   *
   * @param  clear       Indicates whether to remove all existing entries prior
   *                     to adding entries read from LDIF.
   * @param  ldifReader  The LDIF reader to use to obtain the entries to be
   *                     imported.  It will be closed by this method.
   *
   * @return  The number of entries read from LDIF and added to the server.
   *
   * @throws  LDAPException  If a problem occurs while reading entries or adding
   *                         them to the server.
   */
  public int importFromLDIF(final boolean clear,
                            @NotNull final LDIFReader ldifReader)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final InMemoryDirectoryServerSnapshot snapshot = createSnapshot();
      boolean restoreSnapshot = true;

      try
      {
        if (clear)
        {
          restoreSnapshot(initialSnapshot);
        }

        int entriesAdded = 0;
        while (true)
        {
          final Entry entry;
          try
          {
            entry = ldifReader.readEntry();
            if (entry == null)
            {
              restoreSnapshot = false;
              return entriesAdded;
            }
          }
          catch (final LDIFException le)
          {
            Debug.debugException(le);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_INIT_FROM_LDIF_READ_ERROR.get(le.getMessage()),
                 le);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_INIT_FROM_LDIF_READ_ERROR.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }

          addEntry(entry, true);
          entriesAdded++;
        }
      }
      finally
      {
        try
        {
          ldifReader.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        if (restoreSnapshot)
        {
          restoreSnapshot(snapshot);
        }
      }
    }
  }



  /**
   * Writes all entries contained in the server to LDIF using the provided
   * writer.
   *
   * @param  ldifWriter             The LDIF writer to use when writing the
   *                                entries.  It must not be {@code null}.
   * @param  excludeGeneratedAttrs  Indicates whether to exclude automatically
   *                                generated operational attributes like
   *                                entryUUID, entryDN, creatorsName, etc.
   * @param  excludeChangeLog       Indicates whether to exclude entries
   *                                contained in the changelog.
   * @param  closeWriter            Indicates whether the LDIF writer should be
   *                                closed after all entries have been written.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         write an entry to LDIF.
   */
  public int exportToLDIF(@NotNull final LDIFWriter ldifWriter,
                          final boolean excludeGeneratedAttrs,
                          final boolean excludeChangeLog,
                          final boolean closeWriter)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      boolean exceptionThrown = false;

      try
      {
        int entriesWritten = 0;

        for (final Map.Entry<DN,ReadOnlyEntry> me : entryMap.entrySet())
        {
          final DN dn = me.getKey();
          if (excludeChangeLog && dn.isDescendantOf(changeLogBaseDN, true))
          {
            continue;
          }

          final Entry entry;
          if (excludeGeneratedAttrs)
          {
            entry = me.getValue().duplicate();
            entry.removeAttribute("entryDN");
            entry.removeAttribute("entryUUID");
            entry.removeAttribute("subschemaSubentry");
            entry.removeAttribute("creatorsName");
            entry.removeAttribute("createTimestamp");
            entry.removeAttribute("modifiersName");
            entry.removeAttribute("modifyTimestamp");
          }
          else
          {
            entry = me.getValue();
          }

          try
          {
            ldifWriter.writeEntry(entry);
            entriesWritten++;
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            exceptionThrown = true;
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_LDIF_WRITE_ERROR.get(entry.getDN(),
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }

        return entriesWritten;
      }
      finally
      {
        if (closeWriter)
        {
          try
          {
            ldifWriter.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            if (! exceptionThrown)
            {
              throw new LDAPException(ResultCode.LOCAL_ERROR,
                   ERR_MEM_HANDLER_LDIF_WRITE_CLOSE_ERROR.get(
                        StaticUtils.getExceptionMessage(e)),
                   e);
            }
          }
        }
      }
    }
  }



  /**
   * Reads entries from the provided LDIF reader and adds them to the server,
   * optionally clearing any existing entries before beginning to add the new
   * entries.  If an error is encountered while adding entries from LDIF then
   * the server will remain populated with the data it held before the import
   * attempt (even if the {@code clear} is given with a value of {@code true}).
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  ldifReader  The LDIF reader to use to obtain the change records to
   *                     be applied.
   *
   * @return  The number of changes applied from the LDIF file.
   *
   * @throws  LDAPException  If a problem occurs while reading change records
   *                         or applying them to the server.
   */
  public int applyChangesFromLDIF(@NotNull final LDIFReader ldifReader)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final InMemoryDirectoryServerSnapshot snapshot = createSnapshot();
      boolean restoreSnapshot = true;

      try
      {
        int changesApplied = 0;
        while (true)
        {
          final LDIFChangeRecord changeRecord;
          try
          {
            changeRecord = ldifReader.readChangeRecord(true);
            if (changeRecord == null)
            {
              restoreSnapshot = false;
              return changesApplied;
            }
          }
          catch (final LDIFException le)
          {
            Debug.debugException(le);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_APPLY_CHANGES_FROM_LDIF_READ_ERROR.get(
                      le.getMessage()),
                 le);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_APPLY_CHANGES_FROM_LDIF_READ_ERROR.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }

          if (changeRecord instanceof LDIFAddChangeRecord)
          {
            final LDIFAddChangeRecord addChangeRecord =
                 (LDIFAddChangeRecord) changeRecord;
            add(addChangeRecord.toAddRequest());
          }
          else if (changeRecord instanceof LDIFDeleteChangeRecord)
          {
            final LDIFDeleteChangeRecord deleteChangeRecord =
                 (LDIFDeleteChangeRecord) changeRecord;
            delete(deleteChangeRecord.toDeleteRequest());
          }
          else if (changeRecord instanceof LDIFModifyChangeRecord)
          {
            final LDIFModifyChangeRecord modifyChangeRecord =
                 (LDIFModifyChangeRecord) changeRecord;
            modify(modifyChangeRecord.toModifyRequest());
          }
          else if (changeRecord instanceof LDIFModifyDNChangeRecord)
          {
            final LDIFModifyDNChangeRecord modifyDNChangeRecord =
                 (LDIFModifyDNChangeRecord) changeRecord;
            modifyDN(modifyDNChangeRecord.toModifyDNRequest());
          }
          else
          {
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_HANDLER_APPLY_CHANGES_UNSUPPORTED_CHANGE.get(
                      String.valueOf(changeRecord)));
          }

          changesApplied++;
        }
      }
      finally
      {
        try
        {
          ldifReader.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        if (restoreSnapshot)
        {
          restoreSnapshot(snapshot);
        }
      }
    }
  }



  /**
   * Attempts to add the provided entry to the in-memory data set.  The attempt
   * will fail if any of the following conditions is true:
   * <UL>
   *   <LI>The provided entry has a malformed DN.</LI>
   *   <LI>The provided entry has the null DN.</LI>
   *   <LI>The provided entry has a DN that is the same as or subordinate to the
   *       subschema subentry.</LI>
   *   <LI>An entry already exists with the same DN as the entry in the provided
   *       request.</LI>
   *   <LI>The entry is outside the set of base DNs for the server.</LI>
   *   <LI>The entry is below one of the defined base DNs but the immediate
   *       parent entry does not exist.</LI>
   *   <LI>If a schema was provided, and the entry is not valid according to the
   *       constraints of that schema.</LI>
   * </UL>
   *
   * @param  entry                     The entry to be added.  It must not be
   *                                   {@code null}.
   * @param  ignoreNoUserModification  Indicates whether to ignore constraints
   *                                   normally imposed by the
   *                                   NO-USER-MODIFICATION element in attribute
   *                                   type definitions.
   *
   * @throws  LDAPException  If a problem occurs while attempting to add the
   *                         provided entry.
   */
  public void addEntry(@NotNull final Entry entry,
                       final boolean ignoreNoUserModification)
         throws LDAPException
  {
    final List<Control> controls;
    if (ignoreNoUserModification)
    {
      controls = new ArrayList<>(1);
      controls.add(new Control(OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));
    }
    else
    {
      controls = Collections.emptyList();
    }

    final AddRequestProtocolOp addRequest = new AddRequestProtocolOp(
         entry.getDN(), new ArrayList<>(entry.getAttributes()));

    final LDAPMessage resultMessage =
         processAddRequest(-1, addRequest, controls);

    final AddResponseProtocolOp addResponse =
         resultMessage.getAddResponseProtocolOp();
    if (addResponse.getResultCode() != ResultCode.SUCCESS_INT_VALUE)
    {
      throw new LDAPException(ResultCode.valueOf(addResponse.getResultCode()),
           addResponse.getDiagnosticMessage(), addResponse.getMatchedDN(),
           stringListToArray(addResponse.getReferralURLs()));
    }
  }



  /**
   * Attempts to add all of the provided entries to the server.  If an error is
   * encountered during processing, then the contents of the server will be the
   * same as they were before this method was called.
   *
   * @param  entries  The collection of entries to be added.
   *
   * @throws  LDAPException  If a problem was encountered while attempting to
   *                         add any of the entries to the server.
   */
  public void addEntries(@NotNull final List<? extends Entry> entries)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final InMemoryDirectoryServerSnapshot snapshot = createSnapshot();
      boolean restoreSnapshot = true;

      try
      {
        for (final Entry e : entries)
        {
          addEntry(e, false);
        }
        restoreSnapshot = false;
      }
      finally
      {
        if (restoreSnapshot)
        {
          restoreSnapshot(snapshot);
        }
      }
    }
  }



  /**
   * Removes the entry with the specified DN and any subordinate entries it may
   * have.
   *
   * @param  baseDN  The DN of the entry to be deleted.  It must not be
   *                 {@code null} or represent the null DN.
   *
   * @return  The number of entries actually removed, or zero if the specified
   *          base DN does not represent an entry in the server.
   *
   * @throws  LDAPException  If the provided base DN is not a valid DN, or is
   *                         the DN of an entry that cannot be deleted (e.g.,
   *                         the null DN).
   */
  public int deleteSubtree(@NotNull final String baseDN)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final DN dn = new DN(baseDN, schemaRef.get());
      if (dn.isNullDN())
      {
        throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
             ERR_MEM_HANDLER_DELETE_ROOT_DSE.get());
      }

      int numDeleted = 0;

      final Iterator<Map.Entry<DN,ReadOnlyEntry>> iterator =
           entryMap.entrySet().iterator();
      while (iterator.hasNext())
      {
        final Map.Entry<DN,ReadOnlyEntry> e = iterator.next();
        if (e.getKey().isDescendantOf(dn, true))
        {
          iterator.remove();
          numDeleted++;
        }
      }

      return numDeleted;
    }
  }



  /**
   * Attempts to apply the provided set of modifications to the specified entry.
   * The attempt will fail if any of the following conditions is true:
   * <UL>
   *   <LI>The target DN is malformed.</LI>
   *   <LI>The target entry is the root DSE.</LI>
   *   <LI>The target entry is the subschema subentry.</LI>
   *   <LI>The target entry does not exist.</LI>
   *   <LI>Any of the modifications cannot be applied to the entry.</LI>
   *   <LI>If a schema was provided, and the entry violates any of the
   *       constraints of that schema.</LI>
   * </UL>
   *
   * @param  dn    The DN of the entry to be modified.
   * @param  mods  The set of modifications to be applied to the entry.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         update the specified entry.
   */
  public void modifyEntry(@NotNull final String dn,
                          @NotNull final List<Modification> mods)
         throws LDAPException
  {
    final ModifyRequestProtocolOp modifyRequest =
         new ModifyRequestProtocolOp(dn, mods);

    final LDAPMessage resultMessage = processModifyRequest(-1, modifyRequest,
         Collections.<Control>emptyList());

    final ModifyResponseProtocolOp modifyResponse =
         resultMessage.getModifyResponseProtocolOp();
    if (modifyResponse.getResultCode() != ResultCode.SUCCESS_INT_VALUE)
    {
      throw new LDAPException(
           ResultCode.valueOf(modifyResponse.getResultCode()),
           modifyResponse.getDiagnosticMessage(), modifyResponse.getMatchedDN(),
           stringListToArray(modifyResponse.getReferralURLs()));
    }
  }



  /**
   * Retrieves a read-only representation the entry with the specified DN, if
   * it exists.
   *
   * @param  dn  The DN of the entry to retrieve.
   *
   * @return  The requested entry, or {@code null} if no entry exists with the
   *          given DN.
   *
   * @throws  LDAPException  If the provided DN is malformed.
   */
  @Nullable()
  public ReadOnlyEntry getEntry(@NotNull final String dn)
         throws LDAPException
  {
    return getEntry(new DN(dn, schemaRef.get()));
  }



  /**
   * Retrieves a read-only representation the entry with the specified DN, if
   * it exists.
   *
   * @param  dn  The DN of the entry to retrieve.
   *
   * @return  The requested entry, or {@code null} if no entry exists with the
   *          given DN.
   */
  @Nullable()
  public ReadOnlyEntry getEntry(@NotNull final DN dn)
  {
    synchronized (entryMap)
    {
      if (dn.isNullDN())
      {
        return generateRootDSE();
      }
      else if (dn.equals(subschemaSubentryDN))
      {
        return subschemaSubentryRef.get();
      }
      else
      {
        final Entry e = entryMap.get(dn);
        if (e == null)
        {
          return null;
        }
        else
        {
          return new ReadOnlyEntry(e);
        }
      }
    }
  }



  /**
   * Retrieves a list of all entries in the server which match the given
   * search criteria.
   *
   * @param  baseDN  The base DN to use for the search.  It must not be
   *                 {@code null}.
   * @param  scope   The scope to use for the search.  It must not be
   *                 {@code null}.
   * @param  filter  The filter to use for the search.  It must not be
   *                 {@code null}.
   *
   * @return  A list of the entries that matched the provided search criteria.
   *
   * @throws  LDAPException  If a problem is encountered while performing the
   *                         search.
   */
  @NotNull()
  public List<ReadOnlyEntry> search(@NotNull final String baseDN,
                                    @NotNull final SearchScope scope,
                                    @NotNull final Filter filter)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final DN parsedDN;
      final Schema schema = schemaRef.get();
      try
      {
        parsedDN = new DN(baseDN, schema);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_MEM_HANDLER_SEARCH_MALFORMED_BASE.get(baseDN, le.getMessage()),
             le);
      }

      final ReadOnlyEntry baseEntry;
      if (parsedDN.isNullDN())
      {
        baseEntry = generateRootDSE();
      }
      else if (parsedDN.equals(subschemaSubentryDN))
      {
        baseEntry = subschemaSubentryRef.get();
      }
      else
      {
        final Entry e = entryMap.get(parsedDN);
        if (e == null)
        {
          throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
               ERR_MEM_HANDLER_SEARCH_BASE_DOES_NOT_EXIST.get(baseDN),
               getMatchedDNString(parsedDN), null);
        }

        baseEntry = new ReadOnlyEntry(e);
      }

      if (scope == SearchScope.BASE)
      {
        final List<ReadOnlyEntry> entryList = new ArrayList<>(1);

        try
        {
          if (filter.matchesEntry(baseEntry, schema))
          {
            entryList.add(baseEntry);
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }

        return Collections.unmodifiableList(entryList);
      }

      if ((scope == SearchScope.ONE) && parsedDN.isNullDN())
      {
        final List<ReadOnlyEntry> entryList =
             new ArrayList<>(baseDNs.size());

        try
        {
          for (final DN dn : baseDNs)
          {
            final Entry e = entryMap.get(dn);
            if ((e != null) && filter.matchesEntry(e, schema))
            {
              entryList.add(new ReadOnlyEntry(e));
            }
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }

        return Collections.unmodifiableList(entryList);
      }

      final List<ReadOnlyEntry> entryList = new ArrayList<>(10);
      for (final Map.Entry<DN,ReadOnlyEntry> me : entryMap.entrySet())
      {
        final DN dn = me.getKey();
        if (dn.matchesBaseAndScope(parsedDN, scope))
        {
          // We don't want to return changelog entries searches based at the
          // root DSE.
          if (parsedDN.isNullDN() && dn.isDescendantOf(changeLogBaseDN, true))
          {
            continue;
          }

          try
          {
            final Entry entry = me.getValue();
            if (filter.matchesEntry(entry, schema))
            {
              entryList.add(new ReadOnlyEntry(entry));
            }
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
          }
        }
      }

      return Collections.unmodifiableList(entryList);
    }
  }



  /**
   * Generates an entry to use as the server root DSE.
   *
   * @return  The generated root DSE entry.
   */
  @NotNull()
  private ReadOnlyEntry generateRootDSE()
  {
    final ReadOnlyEntry rootDSEFromCfg = config.getRootDSEEntry();
    if (rootDSEFromCfg != null)
    {
      return rootDSEFromCfg;
    }

    final Entry rootDSEEntry = new Entry(DN.NULL_DN, schemaRef.get());
    rootDSEEntry.addAttribute("objectClass", "top", "ds-root-dse");
    rootDSEEntry.addAttribute(new Attribute("supportedLDAPVersion",
         IntegerMatchingRule.getInstance(), "3"));

    final String vendorName = config.getVendorName();
    if (vendorName != null)
    {
      rootDSEEntry.addAttribute("vendorName", vendorName);
    }

    final String vendorVersion = config.getVendorVersion();
    if (vendorVersion != null)
    {
      rootDSEEntry.addAttribute("vendorVersion", vendorVersion);
    }

    rootDSEEntry.addAttribute(new Attribute("subschemaSubentry",
         DistinguishedNameMatchingRule.getInstance(),
         subschemaSubentryDN.toString()));
    rootDSEEntry.addAttribute(new Attribute("entryDN",
         DistinguishedNameMatchingRule.getInstance(), ""));
    rootDSEEntry.addAttribute("entryUUID", UUID.randomUUID().toString());

    rootDSEEntry.addAttribute("supportedFeatures",
         "1.3.6.1.4.1.4203.1.5.1",  // All operational attributes
         "1.3.6.1.4.1.4203.1.5.2",  // Request attributes by object class
         "1.3.6.1.4.1.4203.1.5.3",  // LDAP absolute true and false filters
         "1.3.6.1.1.14");           // Increment modification type

    final TreeSet<String> ctlSet = new TreeSet<>();

    ctlSet.add(AssertionRequestControl.ASSERTION_REQUEST_OID);
    ctlSet.add(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID);
    ctlSet.add(DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID);
    ctlSet.add(ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID);
    ctlSet.add(DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    ctlSet.add(DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID);
    ctlSet.add(PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID);
    ctlSet.add(PostReadRequestControl.POST_READ_REQUEST_OID);
    ctlSet.add(PreReadRequestControl.PRE_READ_REQUEST_OID);
    ctlSet.add(ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID);
    ctlSet.add(ProxiedAuthorizationV2RequestControl.
         PROXIED_AUTHORIZATION_V2_REQUEST_OID);
    ctlSet.add(RFC3672SubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    ctlSet.add(ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID);
    ctlSet.add(SimplePagedResultsControl.PAGED_RESULTS_OID);
    ctlSet.add(SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID);
    ctlSet.add(TransactionSpecificationRequestControl.
         TRANSACTION_SPECIFICATION_REQUEST_OID);
    ctlSet.add(VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID);
    ctlSet.add(IgnoreNoUserModificationRequestControl.
         IGNORE_NO_USER_MODIFICATION_REQUEST_OID);

    final String[] controlOIDs = new String[ctlSet.size()];
    rootDSEEntry.addAttribute("supportedControl", ctlSet.toArray(controlOIDs));


    if (! extendedRequestHandlers.isEmpty())
    {
      final String[] oidArray = new String[extendedRequestHandlers.size()];
      rootDSEEntry.addAttribute("supportedExtension",
           extendedRequestHandlers.keySet().toArray(oidArray));

      for (final InMemoryListenerConfig c : config.getListenerConfigs())
      {
        if (c.getStartTLSSocketFactory() != null)
        {
          rootDSEEntry.addAttribute("supportedExtension",
               StartTLSExtendedRequest.STARTTLS_REQUEST_OID);
          break;
        }
      }
    }

    if (! saslBindHandlers.isEmpty())
    {
      final String[] mechanismArray = new String[saslBindHandlers.size()];
      rootDSEEntry.addAttribute("supportedSASLMechanisms",
           saslBindHandlers.keySet().toArray(mechanismArray));
    }

    int pos = 0;
    final String[] baseDNStrings = new String[baseDNs.size()];
    for (final DN baseDN : baseDNs)
    {
      baseDNStrings[pos++] = baseDN.toString();
    }
    rootDSEEntry.addAttribute(new Attribute("namingContexts",
         DistinguishedNameMatchingRule.getInstance(), baseDNStrings));

    if (maxChangelogEntries > 0)
    {
      rootDSEEntry.addAttribute(new Attribute("changeLog",
           DistinguishedNameMatchingRule.getInstance(),
           changeLogBaseDN.toString()));
      rootDSEEntry.addAttribute(new Attribute("firstChangeNumber",
           IntegerMatchingRule.getInstance(), firstChangeNumber.toString()));
      rootDSEEntry.addAttribute(new Attribute("lastChangeNumber",
           IntegerMatchingRule.getInstance(), lastChangeNumber.toString()));
    }

    for (final Attribute customAttribute : config.getCustomRootDSEAttributes())
    {
      rootDSEEntry.setAttribute(customAttribute);
    }

    return new ReadOnlyEntry(rootDSEEntry);
  }



  /**
   * Generates a subschema subentry from the provided schema object.
   *
   * @param  schema  The schema to use to generate the subschema subentry.  It
   *                 may be {@code null} if a minimal default entry should be
   *                 generated.
   *
   * @return  The generated subschema subentry.
   */
  @NotNull()
  private static ReadOnlyEntry generateSubschemaSubentry(
                                    @Nullable final Schema schema)
  {
    final Entry e;

    if (schema == null)
    {
      e = new Entry("cn=schema", schema);

      e.addAttribute("objectClass", "namedObject", "ldapSubEntry",
           "subschema");
      e.addAttribute("cn", "schema");
    }
    else
    {
      e = schema.getSchemaEntry().duplicate();
    }

    try
    {
      e.addAttribute("entryDN", DN.normalize(e.getDN(), schema));
    }
    catch (final LDAPException le)
    {
      // This should never happen.
      Debug.debugException(le);
      e.setAttribute("entryDN", StaticUtils.toLowerCase(e.getDN()));
    }


    e.addAttribute("entryUUID", UUID.randomUUID().toString());
    return new ReadOnlyEntry(e);
  }



  /**
   * Performs the necessary processing to determine whether the given entry
   * should be returned as a search result entry or reference, or if it should
   * not be returned at all.
   *
   * @param  entry                 The entry to be processed.
   * @param  includeSubEntries     Indicates whether LDAP subentries should be
   *                               returned to the client.
   * @param  includeNonSubEntries  Indicates whether non-LDAP subentries should
   *                               be returned to the client.
   * @param  includeChangeLog      Indicates whether entries within the
   *                               changelog should be returned to the client.
   * @param  hasManageDsaIT        Indicates whether the request includes the
   *                               ManageDsaIT control, which can change how
   *                               smart referrals should be handled.
   * @param  entryList             The list to which the entry should be added
   *                               if it should be returned to the client as a
   *                               search result entry.
   * @param  referenceList         The list that should be updated if the
   *                               provided entry represents a smart referral
   *                               that should be returned as a search result
   *                               reference.
   */
  private void processSearchEntry(@NotNull final Entry entry,
                    final boolean includeSubEntries,
                    final boolean includeNonSubEntries,
                    final boolean includeChangeLog,
                    final boolean hasManageDsaIT,
                    @NotNull final List<Entry> entryList,
                    @NotNull final List<SearchResultReference> referenceList)
  {
    // Check to see if the entry should be suppressed based on whether it's an
    // LDAP subentry.
    if (entry.hasObjectClass("ldapSubEntry") ||
        entry.hasObjectClass("inheritableLDAPSubEntry"))
    {
      if (! includeSubEntries)
      {
        return;
      }
    }
    else if (! includeNonSubEntries)
    {
      return;
    }

    // See if the entry should be suppressed as a changelog entry.
    try
    {
      if ((! includeChangeLog) &&
           (entry.getParsedDN().isDescendantOf(changeLogBaseDN, true)))
      {
        return;
      }
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
    }

    // See if the entry is a referral and should result in a reference rather
    // than an entry.
    if ((! hasManageDsaIT) && entry.hasObjectClass("referral") &&
        entry.hasAttribute("ref"))
    {
      referenceList.add(new SearchResultReference(
           entry.getAttributeValues("ref"), NO_CONTROLS));
      return;
    }

    entryList.add(entry);
  }



  /**
   * Retrieves the DN of the existing entry which is the closest hierarchical
   * match to the provided DN.
   *
   * @param  dn  The DN for which to retrieve the appropriate matched DN.
   *
   * @return  The appropriate matched DN value, or {@code null} if there is
   *          none.
   */
  @Nullable()
  private String getMatchedDNString(@NotNull final DN dn)
  {
    DN parentDN = dn.getParent();
    while (parentDN != null)
    {
      if (entryMap.containsKey(parentDN))
      {
        return parentDN.toString();
      }

      parentDN = parentDN.getParent();
    }

    return null;
  }



  /**
   * Converts the provided string list to an array.
   *
   * @param  l  The possibly null list to be converted.
   *
   * @return  The string array with the same elements as the given list in the
   *          same order, or {@code null} if the given list was null.
   */
  @Nullable()
  private static String[] stringListToArray(@Nullable final List<String> l)
  {
    if (l == null)
    {
      return null;
    }
    else
    {
      final String[] a = new String[l.size()];
      return l.toArray(a);
    }
  }



  /**
   * Creates a changelog entry from the information in the provided add request
   * and adds it to the server changelog.
   *
   * @param  addRequest  The add request to use to construct the changelog
   *                     entry.
   * @param  authzDN     The authorization DN for the change.
   */
  private void addChangeLogEntry(@NotNull final AddRequestProtocolOp addRequest,
                                 @NotNull final DN authzDN)
  {
    // If the changelog is disabled, then don't do anything.
    if (maxChangelogEntries <= 0)
    {
      return;
    }

    final long changeNumber = lastChangeNumber.incrementAndGet();
    final LDIFAddChangeRecord changeRecord = new LDIFAddChangeRecord(
         addRequest.getDN(), addRequest.getAttributes());
    try
    {
      addChangeLogEntry(
           ChangeLogEntry.constructChangeLogEntry(changeNumber, changeRecord),
           authzDN);
    }
    catch (final LDAPException le)
    {
      // This should not happen.
      Debug.debugException(le);
    }
  }



  /**
   * Creates a changelog entry from the information in the provided delete
   * request and adds it to the server changelog.
   *
   * @param  e        The entry to be deleted.
   * @param  authzDN  The authorization DN for the change.
   */
  private void addDeleteChangeLogEntry(@NotNull final Entry e,
                                       @NotNull final DN authzDN)
  {
    // If the changelog is disabled, then don't do anything.
    if (maxChangelogEntries <= 0)
    {
      return;
    }

    final long changeNumber = lastChangeNumber.incrementAndGet();
    final LDIFDeleteChangeRecord changeRecord =
         new LDIFDeleteChangeRecord(e.getDN());

    // Create the changelog entry.
    try
    {
      final ChangeLogEntry cle = ChangeLogEntry.constructChangeLogEntry(
           changeNumber, changeRecord);

      // Add a set of deleted entry attributes, which is simply an LDIF-encoded
      // representation of the entry, excluding the first line since it contains
      // the DN.
      final StringBuilder deletedEntryAttrsBuffer = new StringBuilder();
      final String[] ldifLines = e.toLDIF(0);
      for (int i=1; i < ldifLines.length; i++)
      {
        deletedEntryAttrsBuffer.append(ldifLines[i]);
        deletedEntryAttrsBuffer.append(StaticUtils.EOL);
      }

      final Entry copy = cle.duplicate();
      copy.addAttribute(ChangeLogEntry.ATTR_DELETED_ENTRY_ATTRS,
           deletedEntryAttrsBuffer.toString());
      addChangeLogEntry(new ChangeLogEntry(copy), authzDN);
    }
    catch (final LDAPException le)
    {
      // This should never happen.
      Debug.debugException(le);
    }
  }



  /**
   * Creates a changelog entry from the information in the provided modify
   * request and adds it to the server changelog.
   *
   * @param  modifyRequest  The modify request to use to construct the changelog
   *                        entry.
   * @param  authzDN        The authorization DN for the change.
   */
  private void addChangeLogEntry(
                    @NotNull final ModifyRequestProtocolOp modifyRequest,
                    @NotNull final DN authzDN)
  {
    // If the changelog is disabled, then don't do anything.
    if (maxChangelogEntries <= 0)
    {
      return;
    }

    final long changeNumber = lastChangeNumber.incrementAndGet();
    final LDIFModifyChangeRecord changeRecord =
         new LDIFModifyChangeRecord(modifyRequest.getDN(),
              modifyRequest.getModifications());
    try
    {
      addChangeLogEntry(
           ChangeLogEntry.constructChangeLogEntry(changeNumber, changeRecord),
           authzDN);
    }
    catch (final LDAPException le)
    {
      // This should not happen.
      Debug.debugException(le);
    }
  }



  /**
   * Creates a changelog entry from the information in the provided modify DN
   * request and adds it to the server changelog.
   *
   * @param  modifyDNRequest  The modify DN request to use to construct the
   *                          changelog entry.
   * @param  authzDN          The authorization DN for the change.
   */
  private void addChangeLogEntry(
                    @NotNull final ModifyDNRequestProtocolOp modifyDNRequest,
                    @NotNull final DN authzDN)
  {
    // If the changelog is disabled, then don't do anything.
    if (maxChangelogEntries <= 0)
    {
      return;
    }

    final long changeNumber = lastChangeNumber.incrementAndGet();
    final LDIFModifyDNChangeRecord changeRecord =
         new LDIFModifyDNChangeRecord(modifyDNRequest.getDN(),
              modifyDNRequest.getNewRDN(), modifyDNRequest.deleteOldRDN(),
              modifyDNRequest.getNewSuperiorDN());
    try
    {
      addChangeLogEntry(
           ChangeLogEntry.constructChangeLogEntry(changeNumber, changeRecord),
           authzDN);
    }
    catch (final LDAPException le)
    {
      // This should not happen.
      Debug.debugException(le);
    }
  }



  /**
   * Adds the provided changelog entry to the data set, removing an old entry if
   * necessary to remain within the maximum allowed number of changes.  This
   * must only be called from a synchronized method, and the change number for
   * the changelog entry must have been obtained by calling
   * {@code lastChangeNumber.incrementAndGet()}.
   *
   * @param  e        The changelog entry to add to the data set.
   * @param  authzDN  The authorization DN for the change.
   */
  private void addChangeLogEntry(@NotNull final ChangeLogEntry e,
                                 @NotNull final DN authzDN)
  {
    // Construct the DN object to use for the entry and put it in the map.
    final long changeNumber = e.getChangeNumber();
    final Schema schema = schemaRef.get();
    final DN dn = new DN(
         new RDN("changeNumber", String.valueOf(changeNumber), schema),
         changeLogBaseDN);

    final Entry entry = e.duplicate();
    if (generateOperationalAttributes)
    {
      final Date d = new Date();
      entry.addAttribute(new Attribute("entryDN",
           DistinguishedNameMatchingRule.getInstance(),
           dn.toNormalizedString()));
      entry.addAttribute(new Attribute("entryUUID",
           UUID.randomUUID().toString()));
      entry.addAttribute(new Attribute("subschemaSubentry",
           DistinguishedNameMatchingRule.getInstance(),
           subschemaSubentryDN.toString()));
      entry.addAttribute(new Attribute("creatorsName",
           DistinguishedNameMatchingRule.getInstance(),
           authzDN.toString()));
      entry.addAttribute(new Attribute("createTimestamp",
           GeneralizedTimeMatchingRule.getInstance(),
           StaticUtils.encodeGeneralizedTime(d)));
      entry.addAttribute(new Attribute("modifiersName",
           DistinguishedNameMatchingRule.getInstance(),
           authzDN.toString()));
      entry.addAttribute(new Attribute("modifyTimestamp",
           GeneralizedTimeMatchingRule.getInstance(),
           StaticUtils.encodeGeneralizedTime(d)));
    }

    entryMap.put(dn, new ReadOnlyEntry(entry));
    indexAdd(entry);

    // Update the first change number and/or trim the changelog if necessary.
    final long firstNumber = firstChangeNumber.get();
    if (changeNumber == 1L)
    {
      // It's the first change, so we need to set the first change number.
      firstChangeNumber.set(1);
    }
    else
    {
      // See if we need to trim an entry.
      final long numChangeLogEntries = changeNumber - firstNumber + 1;
      if (numChangeLogEntries > maxChangelogEntries)
      {
        // We need to delete the first changelog entry and increment the
        // first change number.
        firstChangeNumber.incrementAndGet();
        final Entry deletedEntry = entryMap.remove(new DN(
             new RDN("changeNumber", String.valueOf(firstNumber), schema),
             changeLogBaseDN));
        indexDelete(deletedEntry);
      }
    }
  }



  /**
   * Checks to see if the provided control map includes a proxied authorization
   * control (v1 or v2) and if so then attempts to determine the appropriate
   * authorization identity to use for the operation.
   *
   * @param  m  The map of request controls, indexed by OID.
   *
   * @return  The DN of the authorized user, or the current authentication DN
   *          if the control map does not include a proxied authorization
   *          request control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         determine the authorization DN.
   */
  @NotNull()
  private DN handleProxiedAuthControl(@NotNull final Map<String,Control> m)
          throws LDAPException
  {
    final ProxiedAuthorizationV1RequestControl p1 =
         (ProxiedAuthorizationV1RequestControl) m.get(
              ProxiedAuthorizationV1RequestControl.
                   PROXIED_AUTHORIZATION_V1_REQUEST_OID);
    if (p1 != null)
    {
      final DN authzDN = new DN(p1.getProxyDN(), schemaRef.get());
      if (authzDN.isNullDN() ||
          entryMap.containsKey(authzDN) ||
          additionalBindCredentials.containsKey(authzDN))
      {
        return authzDN;
      }
      else
      {
        throw new LDAPException(ResultCode.AUTHORIZATION_DENIED,
             ERR_MEM_HANDLER_NO_SUCH_IDENTITY.get("dn:" + authzDN.toString()));
      }
    }

    final ProxiedAuthorizationV2RequestControl p2 =
         (ProxiedAuthorizationV2RequestControl) m.get(
              ProxiedAuthorizationV2RequestControl.
                   PROXIED_AUTHORIZATION_V2_REQUEST_OID);
    if (p2 != null)
    {
      return getDNForAuthzID(p2.getAuthorizationID());
    }

    return authenticatedDN;
  }



  /**
   * Attempts to identify the DN of the user referenced by the provided
   * authorization ID string.  It may be "dn:" followed by the target DN, or
   * "u:" followed by the value of the uid attribute in the entry.  If it uses
   * the "dn:" form, then it may reference the DN of a regular entry or a DN
   * in the configured set of additional bind credentials.
   *
   * @param  authzID  The authorization ID to resolve to a user DN.
   *
   * @return  The DN identified for the provided authorization ID.
   *
   * @throws  LDAPException  If a problem prevents resolving the authorization
   *                         ID to a user DN.
   */
  @NotNull()
  public DN getDNForAuthzID(@NotNull final String authzID)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final String lowerAuthzID = StaticUtils.toLowerCase(authzID);
      if (lowerAuthzID.startsWith("dn:"))
      {
        if (lowerAuthzID.equals("dn:"))
        {
          return DN.NULL_DN;
        }
        else
        {
          final DN dn = new DN(authzID.substring(3), schemaRef.get());
          if (entryMap.containsKey(dn) ||
               additionalBindCredentials.containsKey(dn))
          {
            return dn;
          }
          else
          {
            throw new LDAPException(ResultCode.AUTHORIZATION_DENIED,
                 ERR_MEM_HANDLER_NO_SUCH_IDENTITY.get(authzID));
          }
        }
      }
      else if (lowerAuthzID.startsWith("u:"))
      {
        final Filter f =
             Filter.createEqualityFilter("uid", authzID.substring(2));
        final List<ReadOnlyEntry> entryList = search("", SearchScope.SUB, f);
        if (entryList.size() == 1)
        {
          return entryList.get(0).getParsedDN();
        }
        else
        {
          throw new LDAPException(ResultCode.AUTHORIZATION_DENIED,
               ERR_MEM_HANDLER_NO_SUCH_IDENTITY.get(authzID));
        }
      }
      else
      {
        throw new LDAPException(ResultCode.AUTHORIZATION_DENIED,
             ERR_MEM_HANDLER_NO_SUCH_IDENTITY.get(authzID));
      }
    }
  }



  /**
   * Checks to see if the provided control map includes an assertion request
   * control, and if so then checks to see whether the provided entry satisfies
   * the filter in that control.
   *
   * @param  m  The map of request controls, indexed by OID.
   * @param  e  The entry to examine against the assertion filter.
   *
   * @throws  LDAPException  If the control map includes an assertion request
   *                         control and the provided entry does not match the
   *                         filter contained in that control.
   */
  private static void handleAssertionRequestControl(
                           @NotNull final Map<String,Control> m,
                           @NotNull final Entry e)
          throws LDAPException
  {
    final AssertionRequestControl c = (AssertionRequestControl)
         m.get(AssertionRequestControl.ASSERTION_REQUEST_OID);
    if (c == null)
    {
      return;
    }

    try
    {
      if (c.getFilter().matchesEntry(e))
      {
        return;
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
    }

    // If we've gotten here, then the filter doesn't match.
    throw new LDAPException(ResultCode.ASSERTION_FAILED,
         ERR_MEM_HANDLER_ASSERTION_CONTROL_NOT_SATISFIED.get());
  }



  /**
   * Checks to see if the provided control map includes a pre-read request
   * control, and if so then generates the appropriate response control that
   * should be returned to the client.
   *
   * @param  m  The map of request controls, indexed by OID.
   * @param  e  The entry as it appeared before the operation.
   *
   * @return  The pre-read response control that should be returned to the
   *          client, or {@code null} if there is none.
   */
  @Nullable()
  private PreReadResponseControl handlePreReadControl(
               @NotNull final Map<String,Control> m, @NotNull final Entry e)
  {
    final PreReadRequestControl c = (PreReadRequestControl)
         m.get(PreReadRequestControl.PRE_READ_REQUEST_OID);
    if (c == null)
    {
      return null;
    }

    final SearchEntryParer parer = new SearchEntryParer(
         Arrays.asList(c.getAttributes()), schemaRef.get());
    final Entry trimmedEntry = parer.pareEntry(e);
    return new PreReadResponseControl(new ReadOnlyEntry(trimmedEntry));
  }



  /**
   * Checks to see if the provided control map includes a post-read request
   * control, and if so then generates the appropriate response control that
   * should be returned to the client.
   *
   * @param  m  The map of request controls, indexed by OID.
   * @param  e  The entry as it appeared before the operation.
   *
   * @return  The post-read response control that should be returned to the
   *          client, or {@code null} if there is none.
   */
  @Nullable()
  private PostReadResponseControl handlePostReadControl(
               @NotNull final Map<String,Control> m, @NotNull final Entry e)
  {
    final PostReadRequestControl c = (PostReadRequestControl)
         m.get(PostReadRequestControl.POST_READ_REQUEST_OID);
    if (c == null)
    {
      return null;
    }

    final SearchEntryParer parer = new SearchEntryParer(
         Arrays.asList(c.getAttributes()), schemaRef.get());
    final Entry trimmedEntry = parer.pareEntry(e);
    return new PostReadResponseControl(new ReadOnlyEntry(trimmedEntry));
  }



  /**
   * Finds the smart referral entry which is hierarchically nearest the entry
   * with the given DN.
   *
   * @param  dn  The DN for which to find the hierarchically nearest smart
   *             referral entry.
   *
   * @return  The hierarchically nearest smart referral entry for the provided
   *          DN, or {@code null} if there are no smart referral entries with
   *          the provided DN or any of its ancestors.
   */
  @Nullable()
  private Entry findNearestReferral(@NotNull final DN dn)
  {
    DN d = dn;
    while (true)
    {
      final Entry e = entryMap.get(d);
      if (e == null)
      {
        d = d.getParent();
        if (d == null)
        {
          return null;
        }
      }
      else if (e.hasObjectClass("referral"))
      {
        return e;
      }
      else
      {
        return null;
      }
    }
  }



  /**
   * Retrieves the referral URLs that should be used for the provided target DN
   * based on the given referral entry.
   *
   * @param  targetDN       The target DN from the associated operation.
   * @param  referralEntry  The entry containing the smart referral.
   *
   * @return  The referral URLs that should be returned.
   */
  @Nullable()
  private static List<String> getReferralURLs(@NotNull final DN targetDN,
                                   @NotNull final Entry referralEntry)
  {
    final String[] refs = referralEntry.getAttributeValues("ref");
    if (refs == null)
    {
      return null;
    }

    final RDN[] retainRDNs;
    try
    {
      // If the target DN equals the referral entry DN, or if it's not
      // subordinate to the referral entry, then the URLs should be returned
      // as-is.
      final DN parsedEntryDN = referralEntry.getParsedDN();
      if (targetDN.equals(parsedEntryDN) ||
          (! targetDN.isDescendantOf(parsedEntryDN, true)))
      {
        return Arrays.asList(refs);
      }

      final RDN[] targetRDNs   = targetDN.getRDNs();
      final RDN[] refEntryRDNs = referralEntry.getParsedDN().getRDNs();
      retainRDNs = new RDN[targetRDNs.length - refEntryRDNs.length];
      System.arraycopy(targetRDNs, 0, retainRDNs, 0, retainRDNs.length);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return Arrays.asList(refs);
    }

    final List<String> refList = new ArrayList<>(refs.length);
    for (final String ref : refs)
    {
      try
      {
        final LDAPURL url = new LDAPURL(ref);
        final RDN[] refRDNs = url.getBaseDN().getRDNs();
        final RDN[] newRefRDNs = new RDN[retainRDNs.length + refRDNs.length];
        System.arraycopy(retainRDNs, 0, newRefRDNs, 0, retainRDNs.length);
        System.arraycopy(refRDNs, 0, newRefRDNs, retainRDNs.length,
             refRDNs.length);
        final DN newBaseDN = new DN(newRefRDNs);

        final LDAPURL newURL = new LDAPURL(url.getScheme(), url.getHost(),
             url.getPort(), newBaseDN, null, null, null);
        refList.add(newURL.toString());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        refList.add(ref);
      }
    }

    return refList;
  }



  /**
   * Indicates whether the specified entry exists in the server.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @return  {@code true} if the entry exists, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final String dn)
         throws LDAPException
  {
    return (getEntry(dn) != null);
  }



  /**
   * Indicates whether the specified entry exists in the server and matches the
   * given filter.
   *
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  The filter the entry is expected to match.
   *
   * @return  {@code true} if the entry exists and matches the specified filter,
   *          or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final String dn,
                             @NotNull final String filter)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        return false;
      }

      final Filter f = Filter.create(filter);
      try
      {
        return f.matchesEntry(e, schemaRef.get());
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return false;
      }
    }
  }



  /**
   * Indicates whether the specified entry exists in the server.  This will
   * return {@code true} only if the target entry exists and contains all values
   * for all attributes of the provided entry.  The entry will be allowed to
   * have attribute values not included in the provided entry.
   *
   * @param  entry  The entry to compare against the directory server.
   *
   * @return  {@code true} if the entry exists in the server and is a superset
   *          of the provided entry, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final Entry entry)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(entry.getDN());
      if (e == null)
      {
        return false;
      }

      for (final Attribute a : entry.getAttributes())
      {
        for (final byte[] value : a.getValueByteArrays())
        {
          if (! e.hasAttributeValue(a.getName(), value))
          {
            return false;
          }
        }
      }

      return true;
    }
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist.
   */
  public void assertEntryExists(@NotNull final String dn)
         throws LDAPException, AssertionError
  {
    final Entry e = getEntry(dn);
    if (e == null)
    {
      throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
    }
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  A filter that the target entry must match.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public void assertEntryExists(@NotNull final String dn,
                                @NotNull final String filter)
         throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }

      final Filter f = Filter.create(filter);
      try
      {
        if (! f.matchesEntry(e, schemaRef.get()))
        {
          throw new AssertionError(
               ERR_MEM_HANDLER_TEST_ENTRY_DOES_NOT_MATCH_FILTER.get(dn,
                    filter));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new AssertionError(
             ERR_MEM_HANDLER_TEST_ENTRY_DOES_NOT_MATCH_FILTER.get(dn, filter));
      }
    }
  }



  /**
   * Ensures that an entry exists in the directory with the same DN and all
   * attribute values contained in the provided entry.  The server entry may
   * contain additional attributes and/or attribute values not included in the
   * provided entry.
   *
   * @param  entry  The entry expected to be present in the directory server.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public void assertEntryExists(@NotNull final Entry entry)
         throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(entry.getDN());
      if (e == null)
      {
        throw new AssertionError(
             ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(entry.getDN()));
      }


      final Collection<Attribute> attrs = entry.getAttributes();
      final List<String> messages = new ArrayList<>(attrs.size());

      final Schema schema = schemaRef.get();
      for (final Attribute a : entry.getAttributes())
      {
        final Filter presFilter = Filter.createPresenceFilter(a.getName());
        if (! presFilter.matchesEntry(e, schema))
        {
          messages.add(ERR_MEM_HANDLER_TEST_ATTR_MISSING.get(entry.getDN(),
               a.getName()));
          continue;
        }

        for (final byte[] value : a.getValueByteArrays())
        {
          final Filter eqFilter = Filter.createEqualityFilter(a.getName(),
               value);
          if (! eqFilter.matchesEntry(e, schema))
          {
            messages.add(ERR_MEM_HANDLER_TEST_VALUE_MISSING.get(entry.getDN(),
                 a.getName(), StaticUtils.toUTF8String(value)));
          }
        }
      }

      if (! messages.isEmpty())
      {
        throw new AssertionError(StaticUtils.concatenateStrings(messages));
      }
    }
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  dns  The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  public List<String> getMissingEntryDNs(@NotNull final Collection<String> dns)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final List<String> missingDNs = new ArrayList<>(dns.size());
      for (final String dn : dns)
      {
        final Entry e = getEntry(dn);
        if (e == null)
        {
          missingDNs.add(dn);
        }
      }

      return missingDNs;
    }
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  dns  The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public void assertEntriesExist(@NotNull final Collection<String> dns)
         throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final List<String> missingDNs = getMissingEntryDNs(dns);
      if (missingDNs.isEmpty())
      {
        return;
      }

      final List<String> messages = new ArrayList<>(missingDNs.size());
      for (final String dn : missingDNs)
      {
        messages.add(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }

      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeNames(@NotNull final String dn,
                           @NotNull final Collection<String> attributeNames)
         throws LDAPException
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        return null;
      }

      final Schema schema = schemaRef.get();
      final List<String> missingAttrs =
           new ArrayList<>(attributeNames.size());
      for (final String attr : attributeNames)
      {
        final Filter f = Filter.createPresenceFilter(attr);
        if (! f.matchesEntry(e, schema))
        {
          missingAttrs.add(attr);
        }
      }

      return missingAttrs;
    }
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  public void assertAttributeExists(@NotNull final String dn,
                   @NotNull final Collection<String> attributeNames)
        throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final List<String> missingAttrs =
           getMissingAttributeNames(dn, attributeNames);
      if (missingAttrs == null)
      {
        throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }
      else if (missingAttrs.isEmpty())
      {
        return;
      }

      final List<String> messages = new ArrayList<>(missingAttrs.size());
      for (final String attr : missingAttrs)
      {
        messages.add(ERR_MEM_HANDLER_TEST_ATTR_MISSING.get(dn, attr));
      }

      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.  The target attribute may or may not contain
   * additional values.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeValues(@NotNull final String dn,
                           @NotNull final String attributeName,
                           @NotNull final Collection<String> attributeValues)
       throws LDAPException
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        return null;
      }

      final Schema schema = schemaRef.get();
      final List<String> missingValues =
           new ArrayList<>(attributeValues.size());
      for (final String value : attributeValues)
      {
        final Filter f = Filter.createEqualityFilter(attributeName, value);
        if (! f.matchesEntry(e, schema))
        {
          missingValues.add(value);
        }
      }

      return missingValues;
    }
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  public void assertValueExists(@NotNull final String dn,
                   @NotNull final String attributeName,
                   @NotNull final Collection<String> attributeValues)
        throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final List<String> missingValues =
           getMissingAttributeValues(dn, attributeName, attributeValues);
      if (missingValues == null)
      {
        throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }
      else if (missingValues.isEmpty())
      {
        return;
      }

      // See if the attribute exists at all in the entry.
      final Entry e = getEntry(dn);
      final Filter f = Filter.createPresenceFilter(attributeName);
      if (! f.matchesEntry(e,  schemaRef.get()))
      {
        throw new AssertionError(
             ERR_MEM_HANDLER_TEST_ATTR_MISSING.get(dn, attributeName));
      }

      final List<String> messages = new ArrayList<>(missingValues.size());
      for (final String value : missingValues)
      {
        messages.add(ERR_MEM_HANDLER_TEST_VALUE_MISSING.get(dn, attributeName,
             value));
      }

      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Ensures that the specified entry does not exist in the directory.
   *
   * @param  dn  The DN of the entry expected to be missing.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is found in the server.
   */
  public void assertEntryMissing(@NotNull final String dn)
         throws LDAPException, AssertionError
  {
    final Entry e = getEntry(dn);
    if (e != null)
    {
      throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_EXISTS.get(dn));
    }
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   *
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  public void assertAttributeMissing(@NotNull final String dn,
                   @NotNull final Collection<String> attributeNames)
         throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }

      final Schema schema = schemaRef.get();
      final List<String> messages = new ArrayList<>(attributeNames.size());
      for (final String name : attributeNames)
      {
        final Filter f = Filter.createPresenceFilter(name);
        if (f.matchesEntry(e, schema))
        {
          messages.add(ERR_MEM_HANDLER_TEST_ATTR_EXISTS.get(dn, name));
        }
      }

      if (! messages.isEmpty())
      {
        throw new AssertionError(StaticUtils.concatenateStrings(messages));
      }
    }
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   *
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  public void assertValueMissing(@NotNull final String dn,
                   @NotNull final String attributeName,
                   @NotNull final Collection<String> attributeValues)
         throws LDAPException, AssertionError
  {
    synchronized (entryMap)
    {
      final Entry e = getEntry(dn);
      if (e == null)
      {
        throw new AssertionError(ERR_MEM_HANDLER_TEST_ENTRY_MISSING.get(dn));
      }

      final Schema schema = schemaRef.get();
      final List<String> messages = new ArrayList<>(attributeValues.size());
      for (final String value : attributeValues)
      {
        final Filter f = Filter.createEqualityFilter(attributeName, value);
        if (f.matchesEntry(e, schema))
        {
          messages.add(ERR_MEM_HANDLER_TEST_VALUE_EXISTS.get(dn, attributeName,
               value));
        }
      }

      if (! messages.isEmpty())
      {
        throw new AssertionError(StaticUtils.concatenateStrings(messages));
      }
    }
  }
}
