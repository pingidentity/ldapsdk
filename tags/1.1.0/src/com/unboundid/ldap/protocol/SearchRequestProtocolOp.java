/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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



import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



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
  private final DereferencePolicy derefPolicy;

  // The filter for this search request.
  private final Filter filter;

  // The size limit for this search request.
  private final int sizeLimit;

  // The time limit for this search request.
  private final int timeLimit;

  // The set of attributes for this search request.
  private final List<String> attributes;

  // The scope for this search request.
  private final SearchScope scope;

  // The base DN for this search request.
  private final String baseDN;



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
  public SearchRequestProtocolOp(final String baseDN, final SearchScope scope,
              final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly, final Filter filter,
              final List<String> attributes)
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
   * Creates a new search request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the search
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         search request.
   */
  SearchRequestProtocolOp(final ASN1StreamReader reader)
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

      final LinkedList<String> attrs = new LinkedList<String>();
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrs.add(reader.readString());
      }

      attributes = Collections.unmodifiableList(attrs);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SEARCH_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the base DN for this search request.
   *
   * @return  The base DN for this search request.
   */
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for this search request.
   *
   * @return  The scope for this search request.
   */
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves the policy to use for any aliases encountered during the search.
   *
   * @return  The policy to use for any aliases encountered during the search.
   */
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
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Retrieves the set of requested attributes for this search request.
   *
   * @return  The set of requested attributes for this search request.
   */
  public List<String> getAttributes()
  {
    return attributes;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
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
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  public void toString(final StringBuilder buffer)
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
