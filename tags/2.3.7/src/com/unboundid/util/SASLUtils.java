/*
 * Copyright 2011-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2014 UnboundID Corp.
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
package com.unboundid.util;



import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.ANONYMOUSBindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequestProperties;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequestProperties;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.ldap.sdk.SASLQualityOfProtection;

import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a utility that may be used to help process SASL bind
 * operations using the LDAP SDK.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLUtils
{
  /**
   * The name of the SASL option that specifies the authentication ID.  It may
   * be used in conjunction with the CRAM-MD5, DIGEST-MD5, GSSAPI, and PLAIN
   * mechanisms.
   */
  public static final String SASL_OPTION_AUTH_ID = "authID";



  /**
   * The name of the SASL option that specifies the authorization ID.  It may
   * be used in conjunction with the DIGEST-MD5, GSSAPI, and PLAIN mechanisms.
   */
  public static final String SASL_OPTION_AUTHZ_ID = "authzID";



  /**
   * The name of the SASL option that specifies the path to the JAAS config
   * file.  It may be used in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_CONFIG_FILE = "configFile";



  /**
   * The name of the SASL option that indicates whether debugging should be
   * enabled.  It may be used in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_DEBUG = "debug";



  /**
   * The name of the SASL option that specifies the KDC address.  It may be used
   * in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_KDC_ADDRESS = "kdcAddress";




  /**
   * The name of the SASL option that specifies the desired SASL mechanism to
   * use to authenticate to the server.
   */
  public static final String SASL_OPTION_MECHANISM = "mech";



  /**
   * The name of the SASL option that specifies the GSSAPI service principal
   * protocol.  It may be used in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_PROTOCOL = "protocol";



  /**
   * The name of the SASL option that specifies the quality of protection that
   * should be used for communication that occurs after the authentication has
   * completed.
   */
  public static final String SASL_OPTION_QOP = "qop";



  /**
   * The name of the SASL option that specifies the realm name.  It may be used
   * in conjunction with the DIGEST-MD5 and GSSAPI mechanisms.
   */
  public static final String SASL_OPTION_REALM = "realm";



  /**
   * The name of the SASL option that indicates whether to require an existing
   * Kerberos session from the ticket cache.  It may be used in conjunction with
   * the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_REQUIRE_CACHE = "requireCache";



  /**
   * The name of the SASL option that indicates whether to attempt to renew the
   * Kerberos TGT for an existing session.  It may be used in conjunction with
   * the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_RENEW_TGT = "renewTGT";



  /**
   * The name of the SASL option that specifies the path to the Kerberos ticket
   * cache to use.  It may be used in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_TICKET_CACHE_PATH = "ticketCache";



  /**
   * The name of the SASL option that specifies the trace string.  It may be
   * used in conjunction with the ANONYMOUS mechanism.
   */
  public static final String SASL_OPTION_TRACE = "trace";



  /**
   * The name of the SASL option that specifies whether to use a Kerberos ticket
   * cache.  It may be used in conjunction with the GSSAPI mechanism.
   */
  public static final String SASL_OPTION_USE_TICKET_CACHE = "useTicketCache";



  /**
   * A map with information about all supported SASL mechanisms, mapped from
   * lowercase mechanism name to an object with information about that
   * mechanism.
   */
  private static final Map<String,SASLMechanismInfo> SASL_MECHANISMS;



  static
  {
    final TreeMap<String,SASLMechanismInfo> m =
         new TreeMap<String,SASLMechanismInfo>();

    m.put(toLowerCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME),
         new SASLMechanismInfo(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME,
              INFO_SASL_ANONYMOUS_DESCRIPTION.get(), false, false,
              new SASLOption(SASL_OPTION_TRACE,
                   INFO_SASL_ANONYMOUS_OPTION_TRACE.get(), false, false)));

    m.put(toLowerCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME),
         new SASLMechanismInfo(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME,
              INFO_SASL_CRAM_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_CRAM_MD5_OPTION_AUTH_ID.get(), true, false)));

    m.put(toLowerCase(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME),
         new SASLMechanismInfo(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME,
              INFO_SASL_DIGEST_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_DIGEST_MD5_OPTION_REALM.get(), false, false),
              new SASLOption(SASL_OPTION_QOP,
                   INFO_SASL_DIGEST_MD5_OPTION_QOP.get(), false, false)));

    m.put(toLowerCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME),
         new SASLMechanismInfo(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME,
              INFO_SASL_EXTERNAL_DESCRIPTION.get(), false, false));

    m.put(toLowerCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME),
         new SASLMechanismInfo(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME,
              INFO_SASL_GSSAPI_DESCRIPTION.get(), true, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_CONFIG_FILE,
                   INFO_SASL_GSSAPI_OPTION_CONFIG_FILE.get(), false, false),
              new SASLOption(SASL_OPTION_DEBUG,
                   INFO_SASL_GSSAPI_OPTION_DEBUG.get(), false, false),
              new SASLOption(SASL_OPTION_KDC_ADDRESS,
                   INFO_SASL_GSSAPI_OPTION_KDC_ADDRESS.get(), false, false),
              new SASLOption(SASL_OPTION_PROTOCOL,
                   INFO_SASL_GSSAPI_OPTION_PROTOCOL.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_GSSAPI_OPTION_REALM.get(), false, false),
              new SASLOption(SASL_OPTION_QOP,
                   INFO_SASL_GSSAPI_OPTION_QOP.get(), false, false),
              new SASLOption(SASL_OPTION_RENEW_TGT,
                   INFO_SASL_GSSAPI_OPTION_RENEW_TGT.get(), false, false),
              new SASLOption(SASL_OPTION_REQUIRE_CACHE,
                   INFO_SASL_GSSAPI_OPTION_REQUIRE_TICKET_CACHE.get(), false,
                   false),
              new SASLOption(SASL_OPTION_TICKET_CACHE_PATH,
                   INFO_SASL_GSSAPI_OPTION_TICKET_CACHE.get(), false, false),
              new SASLOption(SASL_OPTION_USE_TICKET_CACHE,
                   INFO_SASL_GSSAPI_OPTION_USE_TICKET_CACHE.get(), false,
                   false)));

    m.put(toLowerCase(PLAINBindRequest.PLAIN_MECHANISM_NAME),
         new SASLMechanismInfo(PLAINBindRequest.PLAIN_MECHANISM_NAME,
              INFO_SASL_PLAIN_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_PLAIN_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_PLAIN_OPTION_AUTHZ_ID.get(), false, false)));


    // If Commercial Edition classes are available, then register support for
    // any additional SASL mechanisms that it provides.
    try
    {
      final Class<?> c =
           Class.forName("com.unboundid.ldap.sdk.unboundidds.SASLHelper");
      final Method addCESASLInfoMethod =
           c.getMethod("addCESASLInfo", Map.class);
      addCESASLInfoMethod.invoke(null, m);
    }
    catch (final Exception e)
    {
        // This is fine.  It simply means that the Commercial Edition classes
        // are not available.
      Debug.debugException(e);
    }

    SASL_MECHANISMS = Collections.unmodifiableMap(m);
  }



  /**
   * Prevent this utility class from being instantiated.
   */
  private SASLUtils()
  {
    // No implementation required.
  }



  /**
   * Retrieves information about the SASL mechanisms supported for use by this
   * class.
   *
   * @return  Information about the SASL mechanisms supported for use by this
   *          class.
   */
  public static List<SASLMechanismInfo> getSupportedSASLMechanisms()
  {
    return Collections.unmodifiableList(new ArrayList<SASLMechanismInfo>(
         SASL_MECHANISMS.values()));
  }



  /**
   * Retrieves information about the specified SASL mechanism.
   *
   * @param  mechanism  The name of the SASL mechanism for which to retrieve
   *                    information.  It will not be treated in a case-sensitive
   *                    manner.
   *
   * @return  Information about the requested SASL mechanism, or {@code null} if
   *          no information about the specified mechanism is available.
   */
  public static SASLMechanismInfo getSASLMechanismInfo(final String mechanism)
  {
    return SASL_MECHANISMS.get(toLowerCase(mechanism));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final String password,
                                                  final String mechanism,
                                                  final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null ? null : getBytes(password)), mechanism,
         StaticUtils.toList(options));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   * @param  controls   The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final String password,
                                                  final String mechanism,
                                                  final List<String> options,
                                                  final Control... controls)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null ? null : getBytes(password)), mechanism, options,
         controls);
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final byte[] password,
                                                  final String mechanism,
                                                  final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN, password, mechanism,
         StaticUtils.toList(options));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   * @param  controls   The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  public static SASLBindRequest createBindRequest(final String bindDN,
                                                  final byte[] password,
                                                  final String mechanism,
                                                  final List<String> options,
                                                  final Control... controls)
         throws LDAPException
  {
    // Parse the provided set of options to ensure that they are properly
    // formatted in name-value form, and extract the SASL mechanism.
    final String mech;
    final Map<String,String> optionsMap = parseOptions(options);
    final String mechOption =
         optionsMap.remove(toLowerCase(SASL_OPTION_MECHANISM));
    if (mechOption != null)
    {
      mech = mechOption;
      if ((mechanism != null) && (! mech.equalsIgnoreCase(mechanism)))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_CONFLICT.get(mechanism, mech));
      }
    }
    else
    {
      mech = mechanism;
    }

    if (mech == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_NO_MECH.get());
    }

    if (mech.equalsIgnoreCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME))
    {
      return createANONYMOUSBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME))
    {
      return createCRAMMD5BindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
                  DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME))
    {
      return createDIGESTMD5BindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME))
    {
      return createEXTERNALBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME))
    {
      return createGSSAPIBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(PLAINBindRequest.PLAIN_MECHANISM_NAME))
    {
      return createPLAINBindRequest(password, optionsMap, controls);
    }
    else
    {
      // If Commercial Edition classes are available, then see if the
      // authentication attempt is for one of the Commercial Edition mechanisms.
      try
      {
        final Class<?> c =
             Class.forName("com.unboundid.ldap.sdk.unboundidds.SASLHelper");
        final Method createBindRequestMethod = c.getMethod("createBindRequest",
             String.class, StaticUtils.NO_BYTES.getClass(), String.class,
             Map.class, StaticUtils.NO_CONTROLS.getClass());
        final Object bindRequestObject = createBindRequestMethod.invoke(null,
             bindDN, password, mech, optionsMap, controls);
        if (bindRequestObject != null)
        {
          return (SASLBindRequest) bindRequestObject;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        // This may mean that there was a problem with the provided arguments.
        // If it's an InvocationTargetException that wraps an LDAPException,
        // then throw that LDAPException.
        if (e instanceof InvocationTargetException)
        {
          final InvocationTargetException ite = (InvocationTargetException) e;
          final Throwable t = ite.getTargetException();
          if (t instanceof LDAPException)
          {
            throw (LDAPException) t;
          }
        }
      }

      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_UNSUPPORTED_MECH.get(mech));
    }
  }



  /**
   * Creates a SASL ANONYMOUS bind request using the provided set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL ANONYMOUS bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static ANONYMOUSBindRequest createANONYMOUSBindRequest(
                                           final byte[] password,
                                           final Map<String,String> options,
                                           final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME));
    }


    // The trace option is optional.
    final String trace = options.remove(toLowerCase(SASL_OPTION_TRACE));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME);

    return new ANONYMOUSBindRequest(trace, controls);
  }



  /**
   * Creates a SASL CRAM-MD5 bind request using the provided password and set of
   * options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL CRAM-MD5 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static CRAMMD5BindRequest createCRAMMD5BindRequest(
                                         final byte[] password,
                                         final Map<String,String> options,
                                         final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }


    // The authID option is required.
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }


    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME);

    return new CRAMMD5BindRequest(authID, password, controls);
  }



  /**
   * Creates a SASL DIGEST-MD5 bind request using the provided password and set
   * of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL DIGEST-MD5 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static DIGESTMD5BindRequest createDIGESTMD5BindRequest(
                                           final byte[] password,
                                           final Map<String,String> options,
                                           final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME));
    }

    // The authID option is required.
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }

    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties(authID, password);

    // The authzID option is optional.
    properties.setAuthorizationID(
         options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID)));

    // The realm option is optional.
    properties.setRealm(options.remove(toLowerCase(SASL_OPTION_REALM)));

    // The QoP option is optional, and may contain multiple values that need to
    // be parsed.
    final String qopString = options.remove(toLowerCase(SASL_OPTION_QOP));
    if (qopString != null)
    {
      properties.setAllowedQoP(
           SASLQualityOfProtection.decodeQoPList(qopString));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME);

    return new DIGESTMD5BindRequest(properties, controls);
  }



  /**
   * Creates a SASL EXTERNAL bind request using the provided set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL EXTERNAL bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static EXTERNALBindRequest createEXTERNALBindRequest(
                                          final byte[] password,
                                          final Map<String,String> options,
                                          final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME);

    return new EXTERNALBindRequest(controls);
  }



  /**
   * Creates a SASL GSSAPI bind request using the provided password and set of
   * options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL GSSAPI bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static GSSAPIBindRequest createGSSAPIBindRequest(
                                        final byte[] password,
                                        final Map<String,String> options,
                                        final Control[] controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                GSSAPIBindRequest.GSSAPI_MECHANISM_NAME));
    }
    final GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties(authID, password);

    // The authzID option is optional.
    gssapiProperties.setAuthorizationID(
         options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID)));

    // The configFile option is optional.
    gssapiProperties.setConfigFilePath(options.remove(toLowerCase(
         SASL_OPTION_CONFIG_FILE)));

    // The debug option is optional.
    gssapiProperties.setEnableGSSAPIDebugging(getBooleanValue(options,
         SASL_OPTION_DEBUG, false));

    // The kdcAddress option is optional.
    gssapiProperties.setKDCAddress(options.remove(
         toLowerCase(SASL_OPTION_KDC_ADDRESS)));

    // The protocol option is optional.
    final String protocol = options.remove(toLowerCase(SASL_OPTION_PROTOCOL));
    if (protocol != null)
    {
      gssapiProperties.setServicePrincipalProtocol(protocol);
    }

    // The realm option is optional.
    gssapiProperties.setRealm(options.remove(toLowerCase(SASL_OPTION_REALM)));

    // The QoP option is optional, and may contain multiple values that need to
    // be parsed.
    final String qopString = options.remove(toLowerCase(SASL_OPTION_QOP));
    if (qopString != null)
    {
      gssapiProperties.setAllowedQoP(
           SASLQualityOfProtection.decodeQoPList(qopString));
    }

    // The renewTGT option is optional.
    gssapiProperties.setRenewTGT(getBooleanValue(options, SASL_OPTION_RENEW_TGT,
         false));

    // The requireCache option is optional.
    gssapiProperties.setRequireCachedCredentials(getBooleanValue(options,
         SASL_OPTION_REQUIRE_CACHE, false));

    // The ticketCache option is optional.
    gssapiProperties.setTicketCachePath(options.remove(toLowerCase(
         SASL_OPTION_TICKET_CACHE_PATH)));

    // The useTicketCache option is optional.
    gssapiProperties.setUseTicketCache(getBooleanValue(options,
         SASL_OPTION_USE_TICKET_CACHE, true));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         GSSAPIBindRequest.GSSAPI_MECHANISM_NAME);

    // A password must have been provided unless useTicketCache=true and
    // requireTicketCache=true.
    if (password == null)
    {
      if (! (gssapiProperties.useTicketCache() &&
           gssapiProperties.requireCachedCredentials()))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_GSSAPI_PASSWORD_REQUIRED.get());
      }
    }

    return new GSSAPIBindRequest(gssapiProperties, controls);
  }



  /**
   * Creates a SASL PLAIN bind request using the provided password and set of
   * options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL PLAIN bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  private static PLAINBindRequest createPLAINBindRequest(
                                        final byte[] password,
                                        final Map<String,String> options,
                                        final Control[] controls)
          throws LDAPException
  {
    if (password == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                PLAINBindRequest.PLAIN_MECHANISM_NAME));
    }

    // The authID option is required.
    final String authID = options.remove(toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                PLAINBindRequest.PLAIN_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID = options.remove(toLowerCase(SASL_OPTION_AUTHZ_ID));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         PLAINBindRequest.PLAIN_MECHANISM_NAME);

    return new PLAINBindRequest(authID, authzID, password, controls);
  }



  /**
   * Parses the provided list of SASL options.
   *
   * @param  options  The list of options to be parsed.
   *
   * @return  A map with the parsed set of options.
   *
   * @throws  LDAPException  If a problem is encountered while parsing options.
   */
  private static Map<String,String>
                      parseOptions(final List<String> options)
          throws LDAPException
  {
    if (options == null)
    {
      return new HashMap<String,String>(0);
    }

    final HashMap<String,String> m = new HashMap<String,String>(options.size());
    for (final String s : options)
    {
      final int equalPos = s.indexOf('=');
      if (equalPos < 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MISSING_EQUAL.get(s));
      }
      else if (equalPos == 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_STARTS_WITH_EQUAL.get(s));
      }

      final String name = s.substring(0, equalPos);
      final String value = s.substring(equalPos + 1);
      if (m.put(toLowerCase(name), value) != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_NOT_MULTI_VALUED.get(name));
      }
    }

    return m;
  }



  /**
   * Ensures that the provided map is empty, and will throw an exception if it
   * isn't.  This method is intended for internal use only.
   *
   * @param  options    The map of options to ensure is empty.
   * @param  mechanism  The associated SASL mechanism.
   *
   * @throws  LDAPException  If the map of SASL options is not empty.
   */
  @InternalUseOnly()
  public static void ensureNoUnsupportedOptions(
                          final Map<String,String> options,
                          final String mechanism)
          throws LDAPException
  {
    if (! options.isEmpty())
    {
      for (final String s : options.keySet())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_UNSUPPORTED_FOR_MECH.get(s,mechanism));
      }
    }
  }



  /**
   * Retrieves the value of the specified option and parses it as a boolean.
   * Values of "true", "t", "yes", "y", "on", and "1" will be treated as
   * {@code true}.  Values of "false", "f", "no", "n", "off", and "0" will be
   * treated as {@code false}.
   *
   * @param  m  The map from which to retrieve the option.  It must not be
   *            {@code null}.
   * @param  o  The name of the option to examine.
   * @param  d  The default value to use if the given option was not provided.
   *
   * @return  The parsed boolean value.
   *
   * @throws  LDAPException  If the option value cannot be parsed as a boolean.
   */
  static boolean getBooleanValue(final Map<String,String> m, final String o,
                                 final boolean d)
         throws LDAPException
  {
    final String s = toLowerCase(m.remove(toLowerCase(o)));
    if (s == null)
    {
      return d;
    }
    else if (s.equals("true") ||
             s.equals("t") ||
             s.equals("yes") ||
             s.equals("y") ||
             s.equals("on") ||
             s.equals("1"))
    {
      return true;
    }
    else if (s.equals("false") ||
             s.equals("f") ||
             s.equals("no") ||
             s.equals("n") ||
             s.equals("off") ||
             s.equals("0"))
    {
      return false;
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MALFORMED_BOOLEAN_VALUE.get(o));
    }
  }
}
