/*
 * Copyright 2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011 UnboundID Corp.
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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

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
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.matchingrules.GeneralizedTimeMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.EntryValidator;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
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
 * At present, it does not provide any level of support for SASL authentication
 * or extended operations, and it does not support any controls.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryRequestHandler
       extends LDAPListenerRequestHandler
{
  // TODO -- Add support for pluggable SASL authentication.
  // TODO -- Add support for pluggable extended operations.
  // TODO -- Add support for controls.
  // TODO -- Add support for smart referrals.
  // TODO -- Add support for LDAP subentries.
  // TODO -- Add support for prohibiting object class modifications.
  // TODO -- Use schema when applying modifications.
  // TODO -- Add support for schema modifications.
  // TODO -- Add the ability to generate a changelog.



  // The DN of the currently-authenticated user for the associated connection.
  private DN authenticatedDN;

  // The DN of the subschema subentry.
  private final DN subschemaSubentryDN;

  // The entry validator that will be used for schema checking, if
  // appropriate.
  private final EntryValidator entryValidator;

  // The client connection for this request handler instance.
  private final LDAPListenerClientConnection connection;

  // An additional set of credentials that may be used for bind operations.
  private final Map<DN,byte[]> additionalBindCredentials;

  // The entry to use as the root DSE.
  private final ReadOnlyEntry rootDSE;

  // The entry to use as the subschema subentry.
  private final ReadOnlyEntry subschemaSubentry;

  // The schema that will be used for this request handler.  It may be null.
  private final Schema schema;

  // The set of base DNs for the server.
  private final Set<DN> baseDNs;

  // The map of entries currently held in the server.
  private final TreeMap<DN,Entry> entryMap;



  /**
   * Creates a new instance of this request handler with an initially-empty
   * data set.
   *
   * @param  schema   The schema that should be used.  It may be {@code null} if
   *                  no schema checking should be performed.
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty, and the null DN must not be one
   *                  of the defined base DNs.
   *
   * @throws  LDAPException  If there is a problem with the provided set of
   *                         base DNs.
   */
  public InMemoryRequestHandler(final Schema schema, final String... baseDNs)
         throws LDAPException
  {
    this(schema, parseDNs(baseDNs));
  }



  /**
   * Creates a new instance of this request handler with an initially-empty
   * data set.
   *
   * @param  schema   The schema that should be used.  It may be {@code null} if
   *                  no schema checking should be performed.
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty, and the null DN must not be one
   *                  of the defined base DNs.
   *
   * @throws  LDAPException  If there is a problem with the provided set of
   *                         base DNs.
   */
  public InMemoryRequestHandler(final Schema schema, final DN... baseDNs)
         throws LDAPException
  {
    this.schema = schema;

    if (schema == null)
    {
      entryValidator = null;
    }
    else
    {
      entryValidator = new EntryValidator(schema);
    }

    if ((baseDNs == null) || (baseDNs.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_NO_BASE_DNS.get());
    }

    entryMap = new TreeMap<DN,Entry>();

    final LinkedHashSet<DN> baseSet =
         new LinkedHashSet<DN>(Arrays.asList(baseDNs));
    this.baseDNs = Collections.unmodifiableSet(baseSet);
    if (this.baseDNs.contains(DN.NULL_DN))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_NULL_BASE_DN.get());
    }

    additionalBindCredentials = new LinkedHashMap<DN,byte[]>(0);
    authenticatedDN           = DN.NULL_DN;
    connection                = null;
    subschemaSubentry         = generateSubschemaSubentry(schema);
    subschemaSubentryDN       = subschemaSubentry.getParsedDN();
    rootDSE                   = generateRootDSE();

    if (this.baseDNs.contains(subschemaSubentryDN))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_HANDLER_SCHEMA_BASE_DN.get());
    }
  }



  /**
   * Creates a new instance of this request handler that will use the provided
   * entry map object.
   *
   * @param  parent      The parent request handler instance.
   * @param  connection  The client connection for this instance.
   */
  private InMemoryRequestHandler(final InMemoryRequestHandler parent,
               final LDAPListenerClientConnection connection)
  {
    this.connection = connection;

    authenticatedDN = DN.NULL_DN;

    additionalBindCredentials = parent.additionalBindCredentials;
    baseDNs                   = parent.baseDNs;
    entryMap                  = parent.entryMap;
    entryValidator            = parent.entryValidator;
    rootDSE                   = parent.rootDSE;
    schema                    = parent.schema;
    subschemaSubentry         = parent.subschemaSubentry;
    subschemaSubentryDN       = parent.subschemaSubentryDN;
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
  public InMemoryRequestHandler newInstance(
              final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new InMemoryRequestHandler(this, connection);
  }



  /**
   * Retrieves the schema that will be used by the server, if any.
   *
   * @return  The schema that will be used by the server, or {@code null} if
   *          none has been configured.
   */
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * Retrieves a list of the base DNs configured for use by the server.
   *
   * @return  A list of the base DNs configured for use by the server.
   */
  public List<DN> getBaseDNs()
  {
    return Collections.unmodifiableList(new ArrayList<DN>(baseDNs));
  }



  /**
   * Attempts to add an entry to the in-memory data set.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
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
  public synchronized LDAPMessage processAddRequest(final int messageID,
                                       final AddRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // See if the entry includes an ignore NO-USER-MODIFICATION control.
    boolean ignoreNoUserModification = false;
    final ArrayList<Control> newControls =
         new ArrayList<Control>(controls.size());
    for (final Control c : controls)
    {
      if (c.getOID().equals("1.3.6.1.4.1.30221.2.5.5"))
      {
        ignoreNoUserModification = true;
      }
      else
      {
        newControls.add(c);
      }
    }


    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(newControls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new AddResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the entry to be added.  If a schema was provided, then make sure the
    // attributes are created with the appropriate matching rules.
    final Entry entry;
    if (schema == null)
    {
      entry = new Entry(request.getDN(), request.getAttributes());
    }
    else
    {
      final List<Attribute> providedAttrs = request.getAttributes();
      final List<Attribute> newAttrs =
           new ArrayList<Attribute>(providedAttrs.size());
      for (final Attribute a : providedAttrs)
      {
        final String baseName = a.getBaseName();
        final MatchingRule matchingRule =
             MatchingRule.selectEqualityMatchingRule(baseName, schema);
        newAttrs.add(new Attribute(a.getName(), matchingRule,
             a.getRawValues()));
      }

      entry = new Entry(request.getDN(), newAttrs);
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

    // See if the DN is the null DN or the schema entry DN.
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
        final ArrayList<String> ocNames =
             new ArrayList<String>(objectClasses.length);
        final LinkedHashSet<ObjectClassDefinition> ocSet =
             new LinkedHashSet<ObjectClassDefinition>(objectClasses.length);
        for (final String ocName : objectClasses)
        {
          ocNames.add(ocName);
          final ObjectClassDefinition oc = schema.getObjectClass(ocName);
          if (oc != null)
          {
            ocSet.add(oc);
            for (final ObjectClassDefinition supClass :
                 oc.getSuperiorClasses(schema, true))
            {
              if (! ocSet.contains(supClass))
              {
                ocSet.add(supClass);
                ocNames.add(supClass.getNameOrOID());
              }
            }
          }
        }

        final String[] newObjectClasses = new String[ocNames.size()];
        ocNames.toArray(newObjectClasses);
        entry.setAttribute("objectClass", newObjectClasses);
      }
    }

    // If a schema was provided, then make sure the entry complies with it.
    // Also make sure that there are no attributes marked with
    // NO-USER-MODIFICATION.
    if (entryValidator != null)
    {
      final ArrayList<String> invalidReasons =
           new ArrayList<String>(1);
      if (! entryValidator.entryIsValid(entry, invalidReasons))
      {
        return new LDAPMessage(messageID, new AddResponseProtocolOp(
             ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE, null,
             ERR_MEM_HANDLER_ADD_VIOLATES_SCHEMA.get(request.getDN(),
                  StaticUtils.concatenateStrings(invalidReasons)), null));
      }

      if (! ignoreNoUserModification)
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

    // Add a number of operational attributes to the entry.
    entry.addAttribute(new Attribute("entryDN",
         DistinguishedNameMatchingRule.getInstance(), dn.toNormalizedString()));
    entry.addAttribute(new Attribute("entryUUID",
         UUID.randomUUID().toString()));
    entry.addAttribute(new Attribute("subschemaSubentry",
         DistinguishedNameMatchingRule.getInstance(),
         subschemaSubentryDN.toString()));
    entry.addAttribute(new Attribute("creatorsName",
         DistinguishedNameMatchingRule.getInstance(),
         authenticatedDN.toString()));
    entry.addAttribute(new Attribute("createTimestamp",
         GeneralizedTimeMatchingRule.getInstance(),
         StaticUtils.encodeGeneralizedTime(new Date())));

    // See if the entry DN is one of the defined base DNs.  If so, then we can
    // add the entry.
    if (baseDNs.contains(dn))
    {
      entryMap.put(dn, entry);
      return new LDAPMessage(messageID, new AddResponseProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null));
    }

    // See if the parent entry exists.  If so, then we can add the entry.
    final DN parentDN = dn.getParent();
    if ((parentDN != null) && entryMap.containsKey(parentDN))
    {
      entryMap.put(dn, entry);
      return new LDAPMessage(messageID, new AddResponseProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null));
    }

    // The add attempt must fail.
    return new LDAPMessage(messageID, new AddResponseProtocolOp(
         ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
         ERR_MEM_HANDLER_ADD_MISSING_PARENT.get(request.getDN(),
              dn.getParentString()),
         null));
  }



  /**
   * Attempts to process the provided bind request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
   *   <LI>The bind request is not a simple bind request.</LI>
   *   <LI>The bind request contains a malformed bind DN.</LI>
   *   <LI>The bind DN is not the null DN and is not the DN of any entry in the
   *       data set.</LI>
   *   <LI>The bind password is empty and the bind DN is not the null DN.</LI>
   *   <LI>The target user does not have a userPassword value that matches the
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
  public synchronized LDAPMessage processBindRequest(final int messageID,
                                       final BindRequestProtocolOp request,
                                       final List<Control> controls)
  {
    authenticatedDN = DN.NULL_DN;

    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null,
           null));
    }

    // If the bind request is not for a simple bind, then reject it.
    if (request.getCredentialsType() != BindRequestProtocolOp.CRED_TYPE_SIMPLE)
    {
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.AUTH_METHOD_NOT_SUPPORTED_INT_VALUE, null,
           ERR_MEM_HANDLER_BIND_ONLY_SIMPLE_AUTH_SUPPORTED.get(), null, null));
    }

    // Get the parsed bind DN.
    final DN bindDN;
    try
    {
      bindDN = new DN(request.getBindDN());
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

    // If the bind DN is the null DN, then the bind will be considered
    // successful as long as the password is also empty.
    final ASN1OctetString bindPassword = request.getSimplePassword();
    if (bindDN.isNullDN())
    {
      if (bindPassword.getValueLength() == 0)
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.SUCCESS_INT_VALUE, null, null, null, null));
      }
      else
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.INVALID_CREDENTIALS_INT_VALUE,
             getMatchedDNString(bindDN),
             ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()), null,
             null));
      }
    }

    // If the bind DN is not null and the password is empty, then reject the
    // request.
    if ((! bindDN.isNullDN()) && (bindPassword.getValueLength() == 0))
    {
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
           ERR_MEM_HANDLER_BIND_SIMPLE_DN_WITHOUT_PASSWORD.get(), null, null));
    }

    // See if the bind DN is in the set of additional bind credentials.  If so,
    // then use the password there.
    final byte[] additionalCreds = additionalBindCredentials.get(bindDN);
    if (additionalCreds != null)
    {
      if (Arrays.equals(additionalCreds, bindPassword.getValue()))
      {
        authenticatedDN = bindDN;
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.SUCCESS_INT_VALUE, null, null, null, null));
      }
      else
      {
        return new LDAPMessage(messageID, new BindResponseProtocolOp(
             ResultCode.INVALID_CREDENTIALS_INT_VALUE,
             getMatchedDNString(bindDN),
             ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()), null,
             null));
      }
    }

    // If the target user doesn't exist, then reject the request.
    final Entry userEntry = entryMap.get(bindDN);
    if (userEntry == null)
    {
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.INVALID_CREDENTIALS_INT_VALUE, getMatchedDNString(bindDN),
           ERR_MEM_HANDLER_BIND_NO_SUCH_USER.get(request.getBindDN()), null,
           null));
    }

    // If the user entry has a userPassword value that matches the provided
    // password, then the bind will be successful.  Otherwise, it will fail.
    if (userEntry.hasAttributeValue("userPassword", bindPassword.getValue(),
             OctetStringMatchingRule.getInstance()))
    {
      authenticatedDN = bindDN;
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null, null));
    }
    else
    {
      return new LDAPMessage(messageID, new BindResponseProtocolOp(
           ResultCode.INVALID_CREDENTIALS_INT_VALUE, getMatchedDNString(bindDN),
           ERR_MEM_HANDLER_BIND_WRONG_PASSWORD.get(request.getBindDN()), null,
           null));
    }
  }



  /**
   * Attempts to process the provided compare request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
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
  public synchronized LDAPMessage processCompareRequest(final int messageID,
                                       final CompareRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new CompareResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the parsed target DN.
    final DN dn;
    try
    {
      dn = new DN(request.getDN());
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

    // Get the target entry (optionally checking for the root DSE or subschema
    // subentry).  If it does not exist, then fail.
    final Entry entry;
    if (dn.isNullDN())
    {
      entry = rootDSE;
    }
    else if (dn.equals(subschemaSubentryDN))
    {
      entry = subschemaSubentry;
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
    return new LDAPMessage(messageID, new CompareResponseProtocolOp(
         resultCode, null, null, null));
  }



  /**
   * Attempts to process the provided delete request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
   *   <LI>The delete request contains a malformed target DN.</LI>
   *   <LI>The target entry is the root DSE.</LI>
   *   <LI>The target entry is the subschema subentry.</LI>
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
  public synchronized LDAPMessage processDeleteRequest(final int messageID,
                                       final DeleteRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the parsed target DN.
    final DN dn;
    try
    {
      dn = new DN(request.getDN());
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

    // See if the entry has any children.
    for (final DN mapEntryDN : entryMap.keySet())
    {
      if (mapEntryDN.isDescendantOf(dn, false))
      {
        return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
             ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE, null,
             ERR_MEM_HANDLER_DELETE_HAS_SUBORDINATES.get(request.getDN()),
             null));
      }
    }

    // Attempt to remove the target entry.  If it does not exist, then fail.
    final Entry removedEntry = entryMap.remove(dn);
    if (removedEntry == null)
    {
      return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
           ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
           ERR_MEM_HANDLER_DELETE_NO_SUCH_ENTRY.get(request.getDN()), null));
    }
    else
    {
      return new LDAPMessage(messageID, new DeleteResponseProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null));
    }
  }



  /**
   * Attempts to process the provided extended request.  At present, no
   * extended operation types are supported, so all requests will be rejected.
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
  public LDAPMessage processExtendedRequest(final int messageID,
                          final ExtendedRequestProtocolOp request,
                          final List<Control> controls)
  {
    return new LDAPMessage(messageID, new ExtendedResponseProtocolOp(
         ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
         ERR_MEM_HANDLER_EXTENDED_OP_NOT_SUPPORTED.get(), null, null, null));
  }



  /**
   * Attempts to process the provided modify request.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
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
  public synchronized LDAPMessage processModifyRequest(final int messageID,
                                       final ModifyRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the parsed target DN.
    final DN dn;
    try
    {
      dn = new DN(request.getDN());
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

    // See if the target entry is the root DSE or the subschema subentry.
    if (dn.isNullDN())
    {
      return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
           ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
           ERR_MEM_HANDLER_MOD_ROOT_DSE.get(), null));
    }
    else if (dn.equals(subschemaSubentryDN))
    {
      return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
           ResultCode.UNWILLING_TO_PERFORM_INT_VALUE, null,
           ERR_MEM_HANDLER_MOD_SCHEMA.get(subschemaSubentryDN.toString()),
           null));
    }

    // Get the target entry.  If it does not exist, then fail.
    final Entry entry = entryMap.get(dn);
    if (entry == null)
    {
      return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
           ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(dn),
           ERR_MEM_HANDLER_MOD_NO_SUCH_ENTRY.get(request.getDN()), null));
    }


    // Attempt to apply the modifications to the entry.  If successful, then a
    // copy of the entry will be returned with the modifications applied.
    final Entry modifiedEntry;
    try
    {
      modifiedEntry = Entry.applyModifications(entry, false,
           request.getModifications());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
           le.getResultCode().intValue(), null,
           ERR_MEM_HANDLER_MOD_FAILED.get(request.getDN(), le.getMessage()),
           null));
    }

    // If a schema was provided, use it to validate the resulting entry.  Also,
    // ensure that no NO-USER-MODIFICATION attributes were targeted.
    if (entryValidator != null)
    {
      final ArrayList<String> invalidReasons = new ArrayList<String>(1);
      if (! entryValidator.entryIsValid(modifiedEntry, invalidReasons))
      {
        return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
             ResultCode.OBJECT_CLASS_VIOLATION_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_VIOLATES_SCHEMA.get(request.getDN(),
                  StaticUtils.concatenateStrings(invalidReasons)),
             null));
      }

      for (final Modification m : request.getModifications())
      {
        final Attribute a = m.getAttribute();
        final String baseName = a.getBaseName();
        final AttributeTypeDefinition at = schema.getAttributeType(baseName);
        if ((at != null) && at.isNoUserModification())
        {
          return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
               ResultCode.CONSTRAINT_VIOLATION_INT_VALUE, null,
               ERR_MEM_HANDLER_MOD_NO_USER_MOD.get(request.getDN(),
                    a.getName()), null));
        }
      }
    }

    // Update modifiersName and modifyTimestamp.
    modifiedEntry.setAttribute(new Attribute("modifiersName",
         DistinguishedNameMatchingRule.getInstance(),
         authenticatedDN.toString()));
    modifiedEntry.setAttribute(new Attribute("modifyTimestamp",
         GeneralizedTimeMatchingRule.getInstance(),
         StaticUtils.encodeGeneralizedTime(new Date())));


    // Replace the entry in the map and return a success result.
    entryMap.put(dn, modifiedEntry);
    return new LDAPMessage(messageID, new ModifyResponseProtocolOp(
         ResultCode.SUCCESS_INT_VALUE, null, null, null));
  }



  /**
   * Attempts to process the provided modify DN request.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
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
  public synchronized LDAPMessage processModifyDNRequest(final int messageID,
                                       final ModifyDNRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the parsed target DN, new RDN, and new superior DN values.
    final DN dn;
    try
    {
      dn = new DN(request.getDN());
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
      newRDN = new RDN(request.getNewRDN());
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
        newSuperiorDN = new DN(newSuperiorString);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
             ResultCode.INVALID_DN_SYNTAX_INT_VALUE, null,
             ERR_MEM_HANDLER_MOD_DN_MALFORMED_NEW_SUPERIOR.get(request.getDN(),
                  request.getNewSuperiorDN(), le.getMessage()),
             null));
      }
    }

    // See if the target is the root DSE or subschema subentry.
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
                subschemaSubentryDN.toString()),
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

    // If the new DN is not a base DN and its parent does not exist, then fail.
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
    if (request.deleteOldRDN() && (! newRDN.equals(originalRDN)))
    {
      final String[] oldRDNNames  = originalRDN.getAttributeNames();
      final byte[][] oldRDNValues = originalRDN.getByteArrayAttributeValues();
      for (int i=0; i < oldRDNNames.length; i++)
      {
        updatedEntry.removeAttributeValue(oldRDNNames[i], oldRDNValues[i]);
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
    }

    // If a schema was provided, then make sure the updated entry conforms to
    // the schema.  Also, reject the attempt if any of the new RDN attributes
    // is marked with NO-USER-MODIFICATION.
    if (entryValidator != null)
    {
      final ArrayList<String> invalidReasons = new ArrayList<String>(1);
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
        if ((at != null) && at.isNoUserModification())
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

      final String[] newRDNNames = newRDN.getAttributeNames();
      for (int i=0; i < newRDNNames.length; i++)
      {
        final String name = newRDNNames[i];
        final AttributeTypeDefinition at = schema.getAttributeType(name);
        if ((at != null) && at.isNoUserModification())
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

    // Update the modifiersName, modifyTimestamp, and entryDN operational
    // attributes.
    updatedEntry.setAttribute(new Attribute("modifiersName",
         DistinguishedNameMatchingRule.getInstance(),
         authenticatedDN.toString()));
    updatedEntry.setAttribute(new Attribute("modifyTimestamp",
         GeneralizedTimeMatchingRule.getInstance(),
         StaticUtils.encodeGeneralizedTime(new Date())));
    updatedEntry.setAttribute(new Attribute("entryDN",
         DistinguishedNameMatchingRule.getInstance(),
         newDN.toNormalizedString()));

    // Remove the old entry and add the new one.
    entryMap.remove(dn);
    entryMap.put(newDN, updatedEntry);

    // If the target entry had any subordinates, then rename them as well.
    final RDN[] oldDNComps = dn.getRDNs();
    final RDN[] newDNComps = newDN.getRDNs();
    final Set<DN> dnSet = new LinkedHashSet<DN>(entryMap.keySet());
    for (final DN mapEntryDN : dnSet)
    {
      if (mapEntryDN.isDescendantOf(dn, false))
      {
        final Entry e = entryMap.remove(mapEntryDN);

        final RDN[] oldMapEntryComps = mapEntryDN.getRDNs();
        final int compsToSave = oldMapEntryComps.length - oldDNComps.length ;

        final RDN[] newMapEntryComps = new RDN[compsToSave + newDNComps.length];
        System.arraycopy(oldMapEntryComps, 0, newMapEntryComps, 0,
             compsToSave);
        System.arraycopy(newDNComps, 0, newMapEntryComps, compsToSave,
             newDNComps.length);

        final DN newMapEntryDN = new DN(newMapEntryComps);
        e.setDN(newMapEntryDN);
        e.setAttribute(new Attribute("entryDN",
             DistinguishedNameMatchingRule.getInstance(),
             newMapEntryDN.toNormalizedString()));
        entryMap.put(newMapEntryDN, e);
      }
    }

    return new LDAPMessage(messageID, new ModifyDNResponseProtocolOp(
         ResultCode.SUCCESS_INT_VALUE, null, null, null));
  }



  /**
   * Attempts to process the provided search request.  The attempt will fail
   * if any of the following conditions is true:
   * <UL>
   *   <LI>The request contains any unsupported critical controls.</LI>
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
  public synchronized LDAPMessage processSearchRequest(final int messageID,
                                       final SearchRequestProtocolOp request,
                                       final List<Control> controls)
  {
    // Reject the request if it contains any critical controls.
    final Control c = getFirstCriticalControl(controls);
    if (c != null)
    {
      return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION_INT_VALUE, null,
           ERR_MEM_HANDLER_UNSUPPORTED_CRITICAL_CONTROL.get(c.getOID()), null));
    }

    // Get the parsed base DN.
    final DN baseDN;
    try
    {
      baseDN = new DN(request.getBaseDN());
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

    // Make sure that the base entry exists.  It may be the root DSE or
    // subschema subentry.
    final Entry baseEntry;
    if (baseDN.isNullDN())
    {
      baseEntry = rootDSE;
    }
    else if (baseDN.equals(subschemaSubentryDN))
    {
      baseEntry = subschemaSubentry;
    }
    else
    {
      baseEntry = entryMap.get(baseDN);
    }

    if (baseEntry == null)
    {
      return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
           ResultCode.NO_SUCH_OBJECT_INT_VALUE, getMatchedDNString(baseDN),
           ERR_MEM_HANDLER_SEARCH_BASE_DOES_NOT_EXIST.get(request.getBaseDN()),
           null));
    }

    // Process the set of requested attributes.
    final AtomicBoolean allUserAttrs = new AtomicBoolean(false);
    final AtomicBoolean allOpAttrs = new AtomicBoolean(false);
    final Map<String,List<List<String>>> returnAttrs =
         processRequestedAttributes(request, allUserAttrs, allOpAttrs);

    // Check the scope.  If it is a base-level search, then we only need to
    // examine the base entry.  Otherwise, we'll have to scan the entire entry
    // map.
    final Filter filter = request.getFilter();
    final SearchScope scope = request.getScope();
    final AtomicInteger entriesSent = new AtomicInteger(0);
    if (scope == SearchScope.BASE)
    {
      try
      {
        if (filter.matchesEntry(baseEntry, schema))
        {
          try
          {
            returnEntry(messageID, baseEntry, allUserAttrs.get(),
                 allOpAttrs.get(), returnAttrs, entriesSent,
                 request.getSizeLimit());
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);

            return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
                 le.getResultCode().intValue(), le.getMatchedDN(),
                 le.getMessage(), null));
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null));
    }

    // If the search uses a single-level scope and the base DN is the root DSE,
    // then we will only examine the defined base entries for the data set.
    if ((scope == SearchScope.ONE) && baseDN.isNullDN())
    {
      for (final DN dn : baseDNs)
      {
        final Entry e = entryMap.get(dn);
        if (e != null)
        {
          try
          {
            if (filter.matchesEntry(e))
            {
              try
              {
                returnEntry(messageID, e, allUserAttrs.get(), allOpAttrs.get(),
                     returnAttrs, entriesSent, request.getSizeLimit());
              }
              catch (final LDAPException le)
              {
                Debug.debugException(le);

                return new LDAPMessage(messageID,
                     new SearchResultDoneProtocolOp(
                          le.getResultCode().intValue(), le.getMatchedDN(),
                          le.getMessage(), null));
              }
            }
          }
          catch (final Exception ex)
          {
            Debug.debugException(ex);
          }
        }
      }

      return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
           ResultCode.SUCCESS_INT_VALUE, null, null, null));
    }

    // Iterate through the map to find and return entries matching the criteria.
    // It is not necessary to consider the root DSE for non-base scopes.
    for (final Map.Entry<DN,Entry> me : entryMap.entrySet())
    {
      final DN dn = me.getKey();
      final Entry entry = me.getValue();
      try
      {
        if (dn.matchesBaseAndScope(baseDN, scope) &&
            filter.matchesEntry(entry))
        {
          try
          {
            returnEntry(messageID, entry, allUserAttrs.get(), allOpAttrs.get(),
                 returnAttrs, entriesSent, request.getSizeLimit());
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);

            return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
                 le.getResultCode().intValue(), le.getMatchedDN(),
                 le.getMessage(), null));
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return new LDAPMessage(messageID, new SearchResultDoneProtocolOp(
         ResultCode.SUCCESS_INT_VALUE, null, null, null));
  }



  /**
   * Retrieves the number of entries currently held in the server.
   *
   * @return  The number of entries currently held in the server.
   */
  public synchronized int countEntries()
  {
    return entryMap.size();
  }



  /**
   * Removes all entries currently held in the server.
   */
  public synchronized void clear()
  {
    entryMap.clear();
  }



  /**
   * Adds all entries obtained from the provided LDIF reader to the server.   If
   * an error is encountered during processing, then the contents of the server
   * will be the same as they were before this method was called.
   *
   * @param  clear       Indicates whether to clear the contents of the server
   *                     prior to adding all entries read from LDIF.
   * @param  ldifReader  The LDIF reader from which to read the entries to use
   *                     to populate the server.  It must not be {@code null}.
   *                     It will be closed by this method.
   *
   * @return  The number of entries read from LDIF.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         populate the server with entries from the specified
   *                         LDIF file.
   */
  public synchronized int initializeFromLDIF(final boolean clear,
                                             final LDIFReader ldifReader)
         throws LDAPException
  {
    final HashMap<DN,Entry> originalEntryMap = new HashMap<DN,Entry>(entryMap);
    boolean restoreOriginalEntryMap = true;

    try
    {
      if (clear)
      {
        entryMap.clear();
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
            restoreOriginalEntryMap = false;
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

      if (restoreOriginalEntryMap)
      {
        entryMap.clear();
        entryMap.putAll(originalEntryMap);
      }
    }
  }



  /**
   * Writes all entries contained in the server to LDIF using the provided
   * writer.
   *
   * @param  ldifWriter   The LDIF writer to use when writing the entries.  It
   *                      must not be {@code null}.
   * @param  closeWriter  Indicates whether the LDIF writer should be closed
   *                      after all entries have been written.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         write an entry to LDIF.
   */
  public synchronized int writeToLDIF(final LDIFWriter ldifWriter,
                                      final boolean closeWriter)
         throws LDAPException
  {
    boolean exceptionThrown = false;

    try
    {
      int entriesWritten = 0;

      for (final Entry entry : entryMap.values())
      {
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
  public void addEntry(final Entry entry,
                       final boolean ignoreNoUserModification)
         throws LDAPException
  {
    final List<Control> controls;
    if (ignoreNoUserModification)
    {
      controls = new ArrayList<Control>(1);
      controls.add(new Control("1.3.6.1.4.1.30221.2.5.5", false));
    }
    else
    {
      controls = Collections.emptyList();
    }

    final AddRequestProtocolOp addRequest = new AddRequestProtocolOp(
         entry.getDN(), new ArrayList<Attribute>(entry.getAttributes()));

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
  public synchronized void addEntries(final List<? extends Entry> entries)
         throws LDAPException
  {
    final HashMap<DN,Entry> originalEntryMap = new HashMap<DN,Entry>(entryMap);
    boolean restoreOriginalEntryMap = true;

    try
    {
      for (final Entry e : entries)
      {
        addEntry(e, false);
      }
      restoreOriginalEntryMap = false;
    }
    finally
    {
      if (restoreOriginalEntryMap)
      {
        entryMap.clear();
        entryMap.putAll(originalEntryMap);
      }
    }
  }



  /**
   * Attempts to delete the specified entry.  The attempt will fail if
   * any of the following conditions is true:
   * <UL>
   *   <LI>The provided entry DN is malformed.</LI>
   *   <LI>The target entry is the root DSE.</LI>
   *   <LI>The target entry is the subschema subentry.</LI>
   *   <LI>The target entry does not exist.</LI>
   *   <LI>The target entry has one or more subordinate entries.</LI>
   * </UL>
   *
   * @param  dn  The DN of the entry to remove.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to delete the
   *                         specified entry.
   */
  public void deleteEntry(final String dn)
         throws LDAPException
  {
    final DeleteRequestProtocolOp deleteRequest =
         new DeleteRequestProtocolOp(dn);

    final LDAPMessage resultMessage = processDeleteRequest(-1, deleteRequest,
         Collections.<Control>emptyList());

    final DeleteResponseProtocolOp deleteResponse =
         resultMessage.getDeleteResponseProtocolOp();
    if (deleteResponse.getResultCode() != ResultCode.SUCCESS_INT_VALUE)
    {
      throw new LDAPException(
           ResultCode.valueOf(deleteResponse.getResultCode()),
           deleteResponse.getDiagnosticMessage(), deleteResponse.getMatchedDN(),
           stringListToArray(deleteResponse.getReferralURLs()));
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
  public synchronized int deleteSubtree(final String baseDN)
         throws LDAPException
  {
    final DN dn = new DN(baseDN);
    if (dn.isNullDN())
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_MEM_HANDLER_DELETE_ROOT_DSE.get());
    }

    int numDeleted = 0;

    final Iterator<Map.Entry<DN,Entry>> iterator =
         entryMap.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<DN,Entry> e = iterator.next();
      if (e.getKey().isDescendantOf(dn, true))
      {
        iterator.remove();
        numDeleted++;
      }
    }

    return numDeleted;
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
  public void modifyEntry(final String dn, final List<Modification> mods)
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
  public synchronized ReadOnlyEntry getEntry(final String dn)
         throws LDAPException
  {
    final DN parsedDN = new DN(dn);
    if (parsedDN.isNullDN())
    {
      return rootDSE;
    }
    else if (parsedDN.equals(subschemaSubentryDN))
    {
      return subschemaSubentry;
    }
    else
    {
      final Entry e = entryMap.get(parsedDN);
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
  public synchronized List<ReadOnlyEntry> search(final String baseDN,
                                                 final SearchScope scope,
                                                 final Filter filter)
         throws LDAPException
  {
    final DN parsedDN;
    try
    {
      parsedDN = new DN(baseDN);
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
      baseEntry = rootDSE;
    }
    else if (parsedDN.equals(subschemaSubentryDN))
    {
      baseEntry = subschemaSubentry;
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
      final List<ReadOnlyEntry> entryList = new ArrayList<ReadOnlyEntry>(1);

      try
      {
        if (filter.matchesEntry(baseEntry))
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
           new ArrayList<ReadOnlyEntry>(baseDNs.size());

      try
      {
        for (final DN dn : baseDNs)
        {
          final Entry e = entryMap.get(dn);
          if ((e != null) && filter.matchesEntry(e))
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

    final List<ReadOnlyEntry> entryList = new ArrayList<ReadOnlyEntry>(10);
    for (final Map.Entry<DN,Entry> me : entryMap.entrySet())
    {
      final DN dn = me.getKey();
      if (dn.matchesBaseAndScope(parsedDN, scope))
      {
        try
        {
          final Entry entry = me.getValue();
          if (filter.matchesEntry(entry))
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



  /**
   * Replaces the set of additional bind credentials with the credentials in the
   * provided map.
   *
   * @param  credentials  A map containing bind DNs and passwords that may be
   *                      used authenticate even if no corresponding entry
   *                      exists in the server.  If it is {@code null} or empty
   *                      then no additional bind credentials will be used.
   */
  public synchronized void setAdditionalBindCredentials(
                                final Map<DN,byte[]> credentials)
  {
    additionalBindCredentials.clear();
    if (credentials != null)
    {
      additionalBindCredentials.putAll(credentials);
    }
  }



  /**
   * Parses the provided set of strings as DNs.
   *
   * @param  dnStrings  The array of strings to be parsed as DNs.
   *
   * @return  The array of parsed DNs.
   *
   * @throws  LDAPException  If any of the provided strings cannot be parsed as
   *                         DNs.
   */
  static DN[] parseDNs(final String... dnStrings)
         throws LDAPException
  {
    if (dnStrings == null)
    {
      return null;
    }

    final DN[] dns = new DN[dnStrings.length];
    for (int i=0; i < dns.length; i++)
    {
      dns[i] = new DN(dnStrings[i]);
    }
    return dns;
  }



  /**
   * Generates an entry to use as the server root DSE.
   *
   * @return  The generated root DSE entry.
   */
  private ReadOnlyEntry generateRootDSE()
  {
    final Entry rootDSEEntry = new Entry(DN.NULL_DN);
    rootDSEEntry.addAttribute("objectClass", "top", "ds-root-dse");
    rootDSEEntry.addAttribute("supportedLDAPVersion", "3");
    rootDSEEntry.addAttribute("vendorName", "UnboundID Corp.");
    rootDSEEntry.addAttribute("vendorVersion", Version.FULL_VERSION_STRING);
    rootDSEEntry.addAttribute("subschemaSubentry",
         subschemaSubentryDN.toString());
    rootDSEEntry.addAttribute("entryDN", "");
    rootDSEEntry.addAttribute("entryUUID", UUID.randomUUID().toString());

    rootDSEEntry.addAttribute("supportedFeatures",
         "1.3.6.1.4.1.4203.1.5.1",  // All operational attributes
         "1.3.6.1.4.1.4203.1.5.2",  // Request attributes by object class
         "1.3.6.1.4.1.4203.1.5.3",  // LDAP absolute true and false filters
         "1.3.6.1.1.14");           // Increment modification type

    int pos = 0;
    final String[] baseDNStrings = new String[baseDNs.size()];
    for (final DN baseDN : baseDNs)
    {
      baseDNStrings[pos++] = baseDN.toString();
    }
    rootDSEEntry.addAttribute("namingContexts", baseDNStrings);

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
  private static ReadOnlyEntry generateSubschemaSubentry(final Schema schema)
  {
    final Entry e;

    if (schema == null)
    {
      e = new Entry("cn=schema");

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
      e.addAttribute("entryDN", DN.normalize(e.getDN()));
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
   * Processes the set of requested attributes from the given search request.
   *
   * @param  request       The search request to examine.
   * @param  allUserAttrs  Indicates whether to return all user attributes.  It
   *                       should have an initial value of {@code false}.
   * @param  allOpAttrs    Indicates whether to return all operational
   *                       attributes.  It should have an initial value of
   *                       {@code false}.
   *
   * @return  A map of specific attribute types to be returned.  The keys of the
   *          map will be the lowercase OID and names of the attribute types,
   *          and the values will be a list of option sets for the associated
   *          attribute type.
   */
  private Map<String,List<List<String>>> processRequestedAttributes(
               final SearchRequestProtocolOp request,
               final AtomicBoolean allUserAttrs, final AtomicBoolean allOpAttrs)
  {
    final List<String> attrList = request.getAttributes();
    if (attrList.isEmpty())
    {
      allUserAttrs.set(true);
      return Collections.emptyMap();
    }

    final HashMap<String,List<List<String>>> m =
         new HashMap<String,List<List<String>>>(attrList.size() * 2);
    for (final String s : attrList)
    {
      if (s.equals("*"))
      {
        // All user attributes.
        allUserAttrs.set(true);
      }
      else if (s.equals("+"))
      {
        // All operational attributes.
        allOpAttrs.set(true);
      }
      else if (s.startsWith("@"))
      {
        // Return attributes by object class.  This can only be supported if a
        // schema has been defined.
        if (schema != null)
        {
          final String ocName = s.substring(1);
          final ObjectClassDefinition oc = schema.getObjectClass(ocName);
          if (oc != null)
          {
            for (final AttributeTypeDefinition at :
                 oc.getRequiredAttributes(schema, true))
            {
              addAttributeOIDAndNames(at, m, Collections.<String>emptyList());
            }
            for (final AttributeTypeDefinition at :
                 oc.getOptionalAttributes(schema, true))
            {
              addAttributeOIDAndNames(at, m, Collections.<String>emptyList());
            }
          }
        }
      }
      else
      {
        final ObjectPair<String,List<String>> nameWithOptions =
             getNameWithOptions(s);
        if (nameWithOptions == null)
        {
          continue;
        }

        final String name = nameWithOptions.getFirst();
        final List<String> options = nameWithOptions.getSecond();

        if (schema == null)
        {
          // Just use the name as provided.
          List<List<String>> optionLists = m.get(name);
          if (optionLists == null)
          {
            optionLists = new ArrayList<List<String>>(1);
            m.put(name, optionLists);
          }
          optionLists.add(options);
        }
        else
        {
          // If the attribute type is defined in the schema, then use it to get
          // all names and the OID.  Otherwise, just use the name as provided.
          final AttributeTypeDefinition at = schema.getAttributeType(name);
          if (at == null)
          {
            List<List<String>> optionLists = m.get(name);
            if (optionLists == null)
            {
              optionLists = new ArrayList<List<String>>(1);
              m.put(name, optionLists);
            }
            optionLists.add(options);
          }
          else
          {
            addAttributeOIDAndNames(at, m, options);
          }
        }
      }
    }

    return m;
  }



  /**
   * Parses the provided string into an attribute type and set of options.
   *
   * @param  s  The string to be parsed.
   *
   * @return  An {@code ObjectPair} in which the first element is the attribute
   *          type name and the second is the list of options (or an empty
   *          list if there are no options).  Alternately, a value of
   *          {@code null} may be returned if the provided string does not
   *          represent a valid attribute type description.
   */
  private static ObjectPair<String,List<String>> getNameWithOptions(
                                                      final String s)
  {
    if (! Attribute.nameIsValid(s, true))
    {
      return null;
    }

    final String l = StaticUtils.toLowerCase(s);

    int semicolonPos = l.indexOf(';');
    if (semicolonPos < 0)
    {
      return new ObjectPair<String,List<String>>(l,
           Collections.<String>emptyList());
    }

    final String name = l.substring(0, semicolonPos);
    final ArrayList<String> optionList = new ArrayList<String>(1);
    while (true)
    {
      final int nextSemicolonPos = l.indexOf(';', semicolonPos+1);
      if (nextSemicolonPos < 0)
      {
        optionList.add(l.substring(semicolonPos+1));
        break;
      }
      else
      {
        optionList.add(l.substring(semicolonPos+1, nextSemicolonPos));
        semicolonPos = nextSemicolonPos;
      }
    }

    return new ObjectPair<String,List<String>>(name, optionList);
  }



  /**
   * Adds all-lowercase versions of the OID and all names for the provided
   * attribute type definition to the given map with the given options.
   *
   * @param  d  The attribute type definition to process.
   * @param  m  The map to which the OID and names should be added.
   * @param  o  The array of attribute options to use in the map.  It should be
   *            empty if no options are needed, and must not be {@code null}.
   */
  private void addAttributeOIDAndNames(final AttributeTypeDefinition d,
                                       final Map<String,List<List<String>>> m,
                                       final List<String> o)
  {
    if (d == null)
    {
      return;
    }

    final String lowerOID = StaticUtils.toLowerCase(d.getOID());
    if (lowerOID != null)
    {
      List<List<String>> l = m.get(lowerOID);
      if (l == null)
      {
        l = new ArrayList<List<String>>(1);
        m.put(lowerOID, l);
      }

      l.add(o);
    }

    for (final String name : d.getNames())
    {
      final String lowerName = StaticUtils.toLowerCase(name);
      List<List<String>> l = m.get(lowerName);
      if (l == null)
      {
        l = new ArrayList<List<String>>(1);
        m.put(lowerName, l);
      }

      l.add(o);
    }

    // If a schema is available, then see if the attribute type has any
    // subordinate types.  If so, then add them.
    if (schema != null)
    {
      for (final AttributeTypeDefinition subordinateType :
           schema.getSubordinateAttributeTypes(d))
      {
        addAttributeOIDAndNames(subordinateType, m, o);
      }
    }
  }



  /**
   * Returns the provided entry to the client, paring it down as necessary
   * based on the requested attributes.
   *
   * @param  messageID     The message ID for the search operation.
   * @param  entry         The entry to be returned.
   * @param  allUserAttrs  Indicates whether to return all user attributes.
   * @param  allOpAttrs    Indicates whether to return all operational
   *                       attributes.
   * @param  returnAttrs   A map with information about the specific attribute
   *                       types to return.
   * @param  entriesSent   The number of entries returned so far for the
   *                       associated search.
   * @param  sizeLimit     The size limit for the search.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         return the entry.
   */
  private void returnEntry(final int messageID, final Entry entry,
                           final boolean allUserAttrs, final boolean allOpAttrs,
                           final Map<String,List<List<String>>> returnAttrs,
                           final AtomicInteger entriesSent,
                           final int sizeLimit)
          throws LDAPException
  {
    // Check to see if we have hit the size limit.
    if ((sizeLimit > 0) && (entriesSent.get() >= sizeLimit))
    {
      throw new LDAPException(ResultCode.SIZE_LIMIT_EXCEEDED,
           ERR_MEM_HANDLER_SEARCH_SIZE_LIMIT_EXCEEDED.get());
    }


    // See if we can return the entry without paring it down.
    if (allUserAttrs)
    {
      if (allOpAttrs || (schema == null))
      {
        connection.sendSearchResultEntry(messageID, entry);
        entriesSent.incrementAndGet();
        return;
      }
    }


    // If we've gotten here, then we may only need to return a partial entry.
    final Entry copy = new Entry(entry.getDN());

    for (final Attribute a : entry.getAttributes())
    {
      final ObjectPair<String,List<String>> nameWithOptions =
           getNameWithOptions(a.getName());
      final String name = nameWithOptions.getFirst();
      final List<String> options = nameWithOptions.getSecond();

      // If there is a schema, then see if it is an operational attribute, since
      // that needs to be handled in a manner different from user attributes
      if (schema != null)
      {
        final AttributeTypeDefinition at = schema.getAttributeType(name);
        if ((at != null) && at.isOperational())
        {
          if (allOpAttrs)
          {
            copy.addAttribute(a);
            continue;
          }

          final List<List<String>> optionLists = returnAttrs.get(name);
          if (optionLists == null)
          {
            continue;
          }

          for (final List<String> optionList : optionLists)
          {
            boolean matchAll = true;
            for (final String option : optionList)
            {
              if (! options.contains(option))
              {
                matchAll = false;
                break;
              }
            }

            if (matchAll)
            {
              copy.addAttribute(a);
              break;
            }
          }
          continue;
        }
      }

      // We'll assume that it's a user attribute, and we'll look for an exact
      // match on the base name.
      if (allUserAttrs)
      {
        copy.addAttribute(a);
        continue;
      }

      final List<List<String>> optionLists = returnAttrs.get(name);
      if (optionLists == null)
      {
        continue;
      }

      for (final List<String> optionList : optionLists)
      {
        boolean matchAll = true;
        for (final String option : optionList)
        {
          if (! options.contains(option))
          {
            matchAll = false;
            break;
          }
        }

        if (matchAll)
        {
          copy.addAttribute(a);
          break;
        }
      }
    }

    connection.sendSearchResultEntry(messageID, copy);
    entriesSent.incrementAndGet();
  }



  /**
   * Retrieves the first critical control from the provided list.
   *
   * @param  controls  The set of controls to process.
   *
   * @return  The first critical control from the provided list, or {@code null}
   *          if it does not contain any critical controls.
   */
  private static Control getFirstCriticalControl(final List<Control> controls)
  {
    if (controls == null)
    {
      return null;
    }

    for (final Control c : controls)
    {
      if (c.isCritical())
      {
        return c;
      }
    }

    return null;
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
  private String getMatchedDNString(final DN dn)
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
  private static String[] stringListToArray(final List<String> l)
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
}
