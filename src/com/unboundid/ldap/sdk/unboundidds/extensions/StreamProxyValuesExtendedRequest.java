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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the stream proxy values extended
 * request as used in the Ping Identity, UnboundID, Nokia/Alcatel-Lucent 8661
 * Directory Proxy Server.  It may be used to obtain all entry DNs and/or all
 * values for one or more attributes for a specified portion of the DIT.
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
 * This extended request has an OID of "1.3.6.1.4.1.30221.2.6.8" and the value
 * is encoded as follows:
 * <PRE>
 *   StreamProxyValuesRequest ::= SEQUENCE {
 *        baseDN                [0] LDAPDN,
 *        includeDNs            [1] DNSelection OPTIONAL,
 *        attributes            [2] SEQUENCE OF LDAPString OPTIONAL,
 *        valuesPerResponse     [3] INTEGER (1 .. 32767) OPTIONAL,
 *        backendSets           [4] SEQUENCE OF BackendSetConfig,
 *        ... }
 *
 *   DNSelection ::= SEQUENCE {
 *        scope        [0] ENUMERATED {
 *             baseObject             (0),
 *             singleLevel            (1),
 *             wholeSubtree           (2),
 *             subordinateSubtree     (3),
 *             ... }
 *        relative     [1] BOOLEAN DEFAULT TRUE,
 *        ..... }
 *
 *   BackendSetConfig ::= SEQUENCE {
 *        backendSetID       OCTET STRING,
 *        backendServers     SEQUENCE OF SEQUENCE {
 *             host     OCTET STRING,
 *             port     INTEGER (1 .. 65535) } }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StreamProxyValuesExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.8) for the get stream proxy values extended
   * request.
   */
  @NotNull public static final String STREAM_PROXY_VALUES_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.8";



  /**
   * The BER type for the baseDN element of the stream proxy values request
   * sequence.
   */
  private static final byte TYPE_BASE_DN = (byte) 0x80;



  /**
   * The BER type for the includeDNs element of the stream proxy values request
   * sequence.
   */
  private static final byte TYPE_INCLUDE_DNS = (byte) 0xA1;



  /**
   * The BER type for the attributes element of the stream proxy values request
   * sequence.
   */
  private static final byte TYPE_ATTRIBUTES = (byte) 0xA2;



  /**
   * The BER type for the valuesPerResponse element of the stream proxy values
   * request sequence.
   */
  private static final byte TYPE_VALUES_PER_RESPONSE = (byte) 0x83;



  /**
   * The BER type for the backendSets element of the stream proxy values request
   * sequence.
   */
  private static final byte TYPE_BACKEND_SETS = (byte) 0xA4;



  /**
   * The BER type for the scope element of the DNSelection sequence.
   */
  private static final byte TYPE_SCOPE = (byte) 0x80;



  /**
   * The BER type for the relative element of the DNSelection sequence.
   */
  private static final byte TYPE_RELATIVE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2528621021697410806L;



  // Indicates whether to return DN values that are relative to the base DN.
  private final boolean returnRelativeDNs;

  // The maximum number of values to include per response.
  private final int valuesPerResponse;

  // The list of backend sets defined in the Directory Proxy Server issuing the
  // request.
  @NotNull private final List<StreamProxyValuesBackendSet> backendSets;

  // The list of attribute values to be returned.
  @NotNull private final List<String> attributes;

  // The search scope to use if DN values are to be included.
  @Nullable private final SearchScope dnScope;

  // The base DN for this stream proxy values request.
  @NotNull private final String baseDN;



  /**
   * Creates a new stream proxy values extended request with the provided
   * information.
   *
   * @param  baseDN             The base DN which indicates the portion of the
   *                            DIT to target.  It must not be {@code null}.
   * @param  dnScope            The scope for which to return information about
   *                            entry DNs in the specified portion of the DIT.
   *                            This may be {@code null} if information about
   *                            entry DNs should not be returned.
   * @param  returnRelativeDNs  Indicates whether DNs returned should be
   *                            relative to the base DN rather than full DNs.
   * @param  attributes         The names of the attributes for which to
   *                            retrieve the values.  This may be {@code null}
   *                            or empty if only entry DNs should be retrieved.
   * @param  valuesPerResponse  The maximum number of values to include per
   *                            response.  A value less than or equal to zero
   *                            indicates that the server should choose an
   *                            appropriate value.
   * @param  backendSets        The list of backend sets defined in the
   *                            Directory Proxy Server issuing the request.  It
   *                            must not be {@code null} or empty.
   * @param  controls           The set of controls to include in the request.
   *                            It may be {@code null} or empty if no controls
   *                            should be included in the request.
   */
  public StreamProxyValuesExtendedRequest(@NotNull final String baseDN,
              @Nullable final SearchScope dnScope,
              final boolean returnRelativeDNs,
              @Nullable final List<String> attributes,
              final int valuesPerResponse,
              @NotNull final List<StreamProxyValuesBackendSet> backendSets,
              @Nullable final Control... controls)
  {
    super(STREAM_PROXY_VALUES_REQUEST_OID,
         encodeValue(baseDN, dnScope, returnRelativeDNs, attributes,
                     valuesPerResponse, backendSets),
         controls);

    this.baseDN            = baseDN;
    this.dnScope           = dnScope;
    this.returnRelativeDNs = returnRelativeDNs;
    this.backendSets       = Collections.unmodifiableList(backendSets);

    if (attributes == null)
    {
      this.attributes = Collections.emptyList();
    }
    else
    {
      this.attributes = Collections.unmodifiableList(attributes);
    }

    if (valuesPerResponse < 0)
    {
      this.valuesPerResponse = 0;
    }
    else
    {
      this.valuesPerResponse = valuesPerResponse;
    }
  }



  /**
   * Creates a new stream proxy values extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          stream proxy values extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StreamProxyValuesExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_STREAM_PROXY_VALUES_REQUEST_NO_VALUE.get());
    }

    boolean                 tmpRelative  = true;
    int                     tmpNumValues = 0;
    final ArrayList<String> tmpAttrs     = new ArrayList<>(10);
    SearchScope             tmpScope     = null;
    String                  tmpBaseDN    = null;

    final ArrayList<StreamProxyValuesBackendSet> tmpBackendSets =
         new ArrayList<>(10);

    try
    {
      final ASN1Element[] svElements =
           ASN1Element.decode(value.getValue()).decodeAsSequence().elements();
      for (final ASN1Element svElement : svElements)
      {
        switch (svElement.getType())
        {
          case TYPE_BASE_DN:
            tmpBaseDN = svElement.decodeAsOctetString().stringValue();
            break;

          case TYPE_INCLUDE_DNS:
            final ASN1Element[] idElements =
                 svElement.decodeAsSequence().elements();
            for (final ASN1Element idElement : idElements)
            {
              switch (idElement.getType())
              {
                case TYPE_SCOPE:
                  final int scopeValue =
                       idElement.decodeAsEnumerated().intValue();
                  tmpScope = SearchScope.definedValueOf(scopeValue);
                  if (tmpScope == null)
                  {
                    throw new LDAPException(ResultCode.DECODING_ERROR,
                         ERR_STREAM_PROXY_VALUES_REQUEST_INVALID_SCOPE.get(
                              scopeValue));
                  }
                  break;
                case TYPE_RELATIVE:
                  tmpRelative =
                       idElement.decodeAsBoolean().booleanValue();
                  break;
                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                  ERR_STREAM_PROXY_VALUES_REQUEST_INVALID_INCLUDE_DNS_TYPE.
                       get(StaticUtils.toHex(idElement.getType())));
              }
            }
            break;

          case TYPE_ATTRIBUTES:
            final ASN1Element[] attrElements =
                 svElement.decodeAsSequence().elements();
            for (final ASN1Element attrElement : attrElements)
            {
              tmpAttrs.add(attrElement.decodeAsOctetString().stringValue());
            }
            break;

          case TYPE_VALUES_PER_RESPONSE:
            tmpNumValues = svElement.decodeAsInteger().intValue();
            if (tmpNumValues < 0)
            {
              tmpNumValues = 0;
            }
            break;

          case TYPE_BACKEND_SETS:
            final ASN1Element[] backendSetElements =
                 svElement.decodeAsSequence().elements();
            for (final ASN1Element setElement : backendSetElements)
            {
              tmpBackendSets.add(
                   StreamProxyValuesBackendSet.decode(setElement));
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_STREAM_PROXY_VALUES_REQUEST_INVALID_SEQUENCE_TYPE.get(
                      StaticUtils.toHex(svElement.getType())));
        }
      }
    }
    catch (final LDAPException le)
    {
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_STREAM_PROXY_VALUES_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    if (tmpBaseDN == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_STREAM_PROXY_VALUES_REQUEST_NO_BASE_DN.get());
    }

    baseDN            = tmpBaseDN;
    dnScope           = tmpScope;
    returnRelativeDNs = tmpRelative;
    backendSets       = Collections.unmodifiableList(tmpBackendSets);
    attributes        = Collections.unmodifiableList(tmpAttrs);
    valuesPerResponse = tmpNumValues;
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this extended request.
   *
   * @param  baseDN             The base DN which indicates the portion of the
   *                            DIT to target.
   * @param  scope              The scope for which to return information about
   *                            entry DNs in the specified portion of the DIT.
   *                            This may be {@code null} if information about
   *                            entry DNs should not be returned.
   * @param  relativeDNs        Indicates whether DNs returned should be
   *                            relative to the base DN rather than full DNs.
   * @param  attributes         The names of the attributes for which to
   *                            retrieve the values.  This may be {@code null}
   *                            or empty if only entry DNs should be retrieved.
   * @param  valuesPerResponse  The maximum number of values to include per
   *                            response.  A value less than or equal to zero
   *                            indicates that the server should choose an
   *                            appropriate value.
   * @param  backendSets        The list of backend sets defined in the
   *                            Directory Proxy Server issuing the request.
   *
   * @return  The ASN.1 octet string containing the encoded value to use for
   *          this extended request.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String baseDN,
               @Nullable final SearchScope scope,
               final boolean relativeDNs,
               @Nullable final List<String> attributes,
               final int valuesPerResponse,
               @NotNull final List<StreamProxyValuesBackendSet> backendSets)
  {
    Validator.ensureNotNull(baseDN, backendSets);
    Validator.ensureFalse(backendSets.isEmpty());

    final ArrayList<ASN1Element> svElements = new ArrayList<>(4);
    svElements.add(new ASN1OctetString(TYPE_BASE_DN, baseDN));

    if (scope != null)
    {
      final ArrayList<ASN1Element> idElements = new ArrayList<>(2);
      idElements.add(new ASN1Enumerated(TYPE_SCOPE, scope.intValue()));

      if (! relativeDNs)
      {
        idElements.add(new ASN1Boolean(TYPE_RELATIVE, relativeDNs));
      }

      svElements.add(new ASN1Sequence(TYPE_INCLUDE_DNS, idElements));
    }

    if ((attributes != null) && (! attributes.isEmpty()))
    {
      final ArrayList<ASN1Element> attrElements =
           new ArrayList<>(attributes.size());
      for (final String s : attributes)
      {
        attrElements.add(new ASN1OctetString(s));
      }
      svElements.add(new ASN1Sequence(TYPE_ATTRIBUTES, attrElements));
    }

    if (valuesPerResponse > 0)
    {
      svElements.add(new ASN1Integer(TYPE_VALUES_PER_RESPONSE,
                                     valuesPerResponse));
    }

    final ASN1Element[] backendSetElements =
         new ASN1Element[backendSets.size()];
    for (int i=0; i < backendSetElements.length; i++)
    {
      backendSetElements[i] = backendSets.get(i).encode();
    }
    svElements.add(new ASN1Sequence(TYPE_BACKEND_SETS, backendSetElements));

    return new ASN1OctetString(new ASN1Sequence(svElements).encode());
  }



  /**
   * Retrieves the base DN for this request.
   *
   * @return  The base DN for this request.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for entry DNs to be included in intermediate responses.
   *
   * @return  The scope for entry DNs to be included in intermediate responses,
   *          or {@code null} if information about entry DNs should not be
   *          returned.
   */
  @Nullable()
  public SearchScope getDNScope()
  {
    return dnScope;
  }



  /**
   * Indicates whether entry DN values returned should be relative to the
   * provided base DN.
   *
   * @return  {@code true} if entry DN values returned should be relative to the
   *          provided base DN, or {@code false} if they should be complete DNs.
   */
  public boolean returnRelativeDNs()
  {
    return returnRelativeDNs;
  }



  /**
   * Retrieves the list of names of attributes whose values should be returned
   * to the client.
   *
   * @return  The list of names of attributes whose values should be returned to
   *          the client, or an empty list if only information about entry DNs
   *          should be returned.
   */
  @NotNull()
  public List<String> getAttributes()
  {
    return attributes;
  }



  /**
   * Retrieves the maximum number of values that should be included in each
   * stream proxy values intermediate response.
   *
   * @return  The maximum number of values that should be included in each
   *          stream proxy values intermediate response, or 0 if the server
   *          should choose the appropriate number of values per response.
   */
  public int getValuesPerResponse()
  {
    return valuesPerResponse;
  }



  /**
   * Retrieves the list of backend sets defined in the Directory Proxy Server
   * instance issuing the request.
   *
   * @return  The list of backend sets defined in the Directory Proxy Server
   *          instance issuing the request.
   */
  @NotNull()
  public List<StreamProxyValuesBackendSet> getBackendSets()
  {
    return backendSets;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StreamProxyValuesExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StreamProxyValuesExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final StreamProxyValuesExtendedRequest r =
         new StreamProxyValuesExtendedRequest(baseDN, dnScope,
              returnRelativeDNs, attributes, valuesPerResponse, backendSets,
              controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_STREAM_PROXY_VALUES.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StreamProxyValuesExtendedRequest(baseDN='");
    buffer.append(baseDN);
    buffer.append('\'');

    if (dnScope != null)
    {
      buffer.append(", scope='");
      buffer.append(dnScope.getName());
      buffer.append("', returnRelativeDNs=");
      buffer.append(returnRelativeDNs);
    }

    buffer.append(", attributes={");
    if (! attributes.isEmpty())
    {
      final Iterator<String> iterator = attributes.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }
    }
    buffer.append('}');

    if (valuesPerResponse > 0)
    {
      buffer.append(", valuesPerResponse=");
      buffer.append(valuesPerResponse);
    }

    buffer.append(", backendSets={");
    final Iterator<StreamProxyValuesBackendSet> setIterator =
         backendSets.iterator();
    while (setIterator.hasNext())
    {
      setIterator.next().toString(buffer);
      if (setIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
