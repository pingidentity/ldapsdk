/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



/**
 * This class provides an implementation of an LDAP search request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8521750809606744181L;



  // The typesOnly flag for this search request.
  private final boolean typesOnly;

  // The dereference policy for this search request.
  @NotNull private final DereferencePolicy derefPolicy;

  // The filter for this search request.
  @NotNull private final Filter filter;

  // The size limit for this search request.
  private final int sizeLimit;

  // The time limit for this search request.
  private final int timeLimit;

  // The set of attributes for this search request.
  @NotNull private final List<String> attributes;

  // The scope for this search request.
  @NotNull private final SearchScope scope;

  // The base DN for this search request.
  @NotNull private final String baseDN;



  /**
   * Creates a new search request protocol op with the provided information.
   *
   * @param  baseDN       The base DN for this search request.
   * @param  scope        The scope for this search request.
   * @param  derefPolicy  The policy to use for aliases encountered during the
   *                      search.
   * @param  sizeLimit    The maximum number of entries to return for the
   *                      search, or zero for no limit.
   * @param  timeLimit    The maximum length of time to spend processing the
   *                      search, or zero for no limit.
   * @param  typesOnly    Indicates whether to return only attribute types or
   *                      both types and values.
   * @param  filter       The filter for this search request.
   * @param  attributes   The names of attributes to include in matching
   *                      entries.
   */
  public SearchRequestProtocolOp(@NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly,
              @NotNull final Filter filter,
              @Nullable final List<String> attributes)
  {
    this.scope       = scope;
    this.derefPolicy = derefPolicy;
    this.typesOnly   = typesOnly;
    this.filter      = filter;

    if (baseDN == null)
    {
      this.baseDN = "";
    }
    else
    {
      this.baseDN = baseDN;
    }

    if (sizeLimit > 0)
    {
      this.sizeLimit = sizeLimit;
    }
    else
    {
      this.sizeLimit = 0;
    }

    if (timeLimit > 0)
    {
      this.timeLimit = timeLimit;
    }
    else
    {
      this.timeLimit = 0;
    }

    if (attributes == null)
    {
      this.attributes = Collections.emptyList();
    }
    else
    {
      this.attributes = Collections.unmodifiableList(attributes);
    }
  }



  /**
   * Creates a new search request protocol op from the provided search request
   * object.
   *
   * @param  request  The search request object to use to create this protocol
   *                  op.
   */
  public SearchRequestProtocolOp(@NotNull final SearchRequest request)
  {
    baseDN      = request.getBaseDN();
    scope       = request.getScope();
    derefPolicy = request.getDereferencePolicy();
    sizeLimit   = request.getSizeLimit();
    timeLimit   = request.getTimeLimitSeconds();
    typesOnly   = request.typesOnly();
    filter      = request.getFilter();
    attributes  = request.getAttributeList();
  }



  /**
   * Creates a new search request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the search
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         search request.
   */
  SearchRequestProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      baseDN      = reader.readString();
      scope       = SearchScope.valueOf(reader.readEnumerated());
      derefPolicy = DereferencePolicy.valueOf(reader.readEnumerated());
      sizeLimit   = reader.readInteger();
      timeLimit   = reader.readInteger();
      typesOnly   = reader.readBoolean();
      filter      = Filter.readFrom(reader);

      final ArrayList<String> attrs = new ArrayList<>(5);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrs.add(reader.readString());
      }

      attributes = Collections.unmodifiableList(attrs);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the base DN for this search request.
   *
   * @return  The base DN for this search request.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for this search request.
   *
   * @return  The scope for this search request.
   */
  @NotNull()
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves the policy to use for any aliases encountered during the search.
   *
   * @return  The policy to use for any aliases encountered during the search.
   */
  @NotNull()
  public DereferencePolicy getDerefPolicy()
  {
    return derefPolicy;
  }



  /**
   * Retrieves the maximum number of entries that the server should return for
   * the search.
   *
   * @return  The maximum number of entries that the server should return for
   *          the search, or zero if there is no limit.
   */
  public int getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * Retrieves the maximum length of time in seconds the server should spend
   * processing the search.
   *
   * @return  The maximum length of time in seconds the server should spend
   *          processing the search, or zero if there is no limit.
   */
  public int getTimeLimit()
  {
    return timeLimit;
  }



  /**
   * Indicates whether the server should return only attribute types or both
   * attribute types and values.
   *
   * @return  {@code true} if the server should return only attribute types, or
   *          {@code false} if both types and values should be returned.
   */
  public boolean typesOnly()
  {
    return typesOnly;
  }



  /**
   * Retrieves the filter for this search request.
   *
   * @return  The filter for this search request.
   */
  @NotNull()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Retrieves the set of requested attributes for this search request.
   *
   * @return  The set of requested attributes for this search request.
   */
  @NotNull()
  public List<String> getAttributes()
  {
    return attributes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<>(attributes.size());
    for (final String attribute : attributes)
    {
      attrElements.add(new ASN1OctetString(attribute));
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST,
         new ASN1OctetString(baseDN),
         new ASN1Enumerated(scope.intValue()),
         new ASN1Enumerated(derefPolicy.intValue()),
         new ASN1Integer(sizeLimit),
         new ASN1Integer(timeLimit),
         new ASN1Boolean(typesOnly),
         filter.encode(),
         new ASN1Sequence(attrElements));
  }



  /**
   * Decodes the provided ASN.1 element as a search request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded search request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a search request protocol op.
   */
  @NotNull()
  public static SearchRequestProtocolOp decodeProtocolOp(
                                             @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String baseDN =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      final SearchScope scope = SearchScope.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[1]).intValue());
      final DereferencePolicy derefPolicy = DereferencePolicy.valueOf(
           ASN1Enumerated.decodeAsEnumerated(elements[2]).intValue());
      final int sizeLimit = ASN1Integer.decodeAsInteger(elements[3]).intValue();
      final int timeLimit = ASN1Integer.decodeAsInteger(elements[4]).intValue();
      final boolean typesOnly =
           ASN1Boolean.decodeAsBoolean(elements[5]).booleanValue();
      final Filter filter = Filter.decode(elements[6]);

      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(elements[7]).elements();
      final ArrayList<String> attributes = new ArrayList<>(attrElements.length);
      for (final ASN1Element e : attrElements)
      {
        attributes.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }

      return new SearchRequestProtocolOp(baseDN, scope, derefPolicy, sizeLimit,
           timeLimit, typesOnly, filter, attributes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST);
    buffer.addOctetString(baseDN);
    buffer.addEnumerated(scope.intValue());
    buffer.addEnumerated(derefPolicy.intValue());
    buffer.addInteger(sizeLimit);
    buffer.addInteger(timeLimit);
    buffer.addBoolean(typesOnly);
    filter.writeTo(buffer);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final String s : attributes)
    {
      buffer.addOctetString(s);
    }
    attrSequence.end();
    opSequence.end();
  }



  /**
   * Creates a search request from this protocol op.
   *
   * @param  controls  The set of controls to include in the search request.
   *                   It may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The search request that was created.
   */
  @NotNull()
  public SearchRequest toSearchRequest(@Nullable final Control... controls)
  {
    final String[] attrArray = new String[attributes.size()];
    attributes.toArray(attrArray);

    return new SearchRequest(null, controls, baseDN, scope, derefPolicy,
         sizeLimit, timeLimit, typesOnly, filter, attrArray);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
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
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SearchRequestProtocolOp(baseDN='");
    buffer.append(baseDN);
    buffer.append("', scope='");
    buffer.append(scope.toString());
    buffer.append("', derefPolicy='");
    buffer.append(derefPolicy.toString());
    buffer.append("', sizeLimit=");
    buffer.append(sizeLimit);
    buffer.append(", timeLimit=");
    buffer.append(timeLimit);
    buffer.append(", typesOnly=");
    buffer.append(typesOnly);
    buffer.append(", filter='");
    filter.toString(buffer);
    buffer.append("', attributes={");

    final Iterator<String> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
