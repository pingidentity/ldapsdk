/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to retrieve a version of the server configuration.  It may be the active
 * configuration, the baseline configuration, or any of the archived
 * configurations.  The set of available configurations that may be retrieved
 * can be obtained using the {@link ListConfigurationsExtendedRequest}.
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
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.28.  It must have
 * a value with the following encoding:
 * <PRE>
 *   GetConfigurationRequest ::= SEQUENCE {
 *        requestType     CHOICE {
 *             activeConfiguration       [0] NULL,
 *             baselineConfiguration     [1] OCTET STRING,
 *             archivedConfiguration     [2] OCTET STRING,
 *             ... },
 *        ... }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetConfigurationExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.28) for the get configuration extended
   * request.
   */
  @NotNull public static final String GET_CONFIG_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.28";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long   serialVersionUID       = 2953462215986675988L;



  // The type of configuration that should be retrieved.
  @NotNull private final GetConfigurationType configurationType;

  // The name of the configuration file that should be retrieved.
  @Nullable private final String fileName;



  /**
   * Creates a new get configuration extended request that has been decoded from
   * the provided generic extended request.
   *
   * @param  r  The generic extended request to decode as a get configuration
   *            extended request.
   *
   * @throws LDAPException  If the provided request cannot be decoded as a get
   *                         configuration extended request.
   */
  public GetConfigurationExtendedRequest(@NotNull final ExtendedRequest r)
       throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CONFIG_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      switch (elements[0].getType())
      {
        case GetConfigurationType.ACTIVE_BER_TYPE:
          configurationType = GetConfigurationType.ACTIVE;
          fileName = null;
          break;
        case GetConfigurationType.BASELINE_BER_TYPE:
          configurationType = GetConfigurationType.BASELINE;
          fileName =
               ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
          break;
        case GetConfigurationType.ARCHIVED_BER_TYPE:
          configurationType = GetConfigurationType.ARCHIVED;
          fileName =
               ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_CONFIG_REQUEST_UNEXPECTED_CONFIG_TYPE.get(
                    StaticUtils.toHex(elements[0].getType())));
      }
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
           ERR_GET_CONFIG_REQUEST_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new get configuration extended request with the provided
   * information.
   *
   * @param  configurationType  The type of configuration that should be
   *                            retrieved.
   * @param  fileName           The name of the configuration file that should
   *                            be retrieved, if appropriate.
   * @param  controls           An optional set of controls to include in the
   *                            request.  This may be {@code null} or empty if
   *                            no controls should be included in the request.
   */
  private GetConfigurationExtendedRequest(
               @NotNull final GetConfigurationType configurationType,
               @Nullable final String fileName,
               @Nullable final Control... controls)
  {
    super(GET_CONFIG_REQUEST_OID, encodeValue(configurationType, fileName),
         controls);

    this.configurationType = configurationType;
    this.fileName          = fileName;
  }



  /**
   * Encodes the provided information into a format suitable for use as the
   * value of this extended request.
   *
   * @param  configurationType  The type of configuration that should be
   *                            retrieved.
   * @param  fileName           The name of the configuration file that should
   *                            be retrieved, if appropriate.
   *
   * @return  The ASN.1 octet string containing the encoded representation of
   *          the provided information.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final GetConfigurationType configurationType,
                      @Nullable final String fileName)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(0);
    switch (configurationType)
    {
      case ACTIVE:
        elements.add(new ASN1Null(configurationType.getBERType()));
        break;

      case BASELINE:
      case ARCHIVED:
        elements.add(
             new ASN1OctetString(configurationType.getBERType(), fileName));
        break;

      default:
        // This should never happen.
        return null;
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new get configuration extended request that may be used to
   * retrieve the current active configuration.
   *
   * @param  controls  An optional set of controls to include in the request.
   *                   This may be {@code null} or empty if no controls should
   *                   be included in the request.
   *
   * @return  The get configuration extended request that has been created.
   */
  @NotNull()
  public static GetConfigurationExtendedRequest
                     createGetActiveConfigurationRequest(
                          @Nullable final Control... controls)
  {
    return new GetConfigurationExtendedRequest(GetConfigurationType.ACTIVE,
         null, controls);
  }



  /**
   * Creates a new get configuration extended request that may be used to
   * retrieve the baseline configuration for the current server version.
   *
   * @param  fileName  The name of the archived configuration file to retrieve.
   *                   This must not be {@code null}.
   * @param  controls  An optional set of controls to include in the request.
   *                   This may be {@code null} or empty if no controls should
   *                   be included in the request.
   *
   * @return  The get configuration extended request that has been created.
   */
  @NotNull()
  public static GetConfigurationExtendedRequest
                     createGetBaselineConfigurationRequest(
                          @NotNull final String fileName,
                          @Nullable final Control... controls)
  {
    Validator.ensureNotNull(fileName);

    return new GetConfigurationExtendedRequest(GetConfigurationType.BASELINE,
         fileName, controls);
  }



  /**
   * Creates a new get configuration extended request that may be used to
   * retrieve the baseline configuration for the current server version.
   *
   * @param  fileName  The name of the archived configuration file to retrieve.
   *                   This must not be {@code null}.
   * @param  controls  An optional set of controls to include in the request.
   *                   This may be {@code null} or empty if no controls should
   *                   be included in the request.
   *
   * @return  The get configuration extended request that has been created.
   */
  @NotNull()
  public static GetConfigurationExtendedRequest
                     createGetArchivedConfigurationRequest(
                          @NotNull final String fileName,
                          @Nullable final Control... controls)
  {
    Validator.ensureNotNull(fileName);

    return new GetConfigurationExtendedRequest(GetConfigurationType.ARCHIVED,
         fileName, controls);
  }



  /**
   * Retrieves the type of configuration file that should be requested.
   *
   * @return  The type of configuration file that should be requested.
   */
  @NotNull()
  public GetConfigurationType getConfigurationType()
  {
    return configurationType;
  }



  /**
   * Retrieves the name of the configuration file that should be requested, if
   * applicable.  This will only be available for requests that intend to
   * retrieve a baseline or archived configuration.
   *
   * @return  The name of the configuration file that should be requested, or
   *          {@code null} if this is not applicable.
   */
  @Nullable()
  public String getFileName()
  {
    return fileName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetConfigurationExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new GetConfigurationExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetConfigurationExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetConfigurationExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GetConfigurationExtendedRequest r =
         new GetConfigurationExtendedRequest(configurationType, fileName,
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
    return INFO_EXTENDED_REQUEST_NAME_GET_CONFIG.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetConfigurationsExtendedRequest(configType=");
    buffer.append(configurationType.name());

    if (fileName != null)
    {
      buffer.append(", fileName='");
      buffer.append(fileName);
      buffer.append('\'');
    }

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
