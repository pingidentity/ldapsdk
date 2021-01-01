/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequestProperties;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequestProperties;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLQualityOfProtection;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a data structure and set of logic for interacting with
 * the authentication details portion of a JSON object provided to the
 * {@link LDAPConnectionDetailsJSONSpecification}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class AuthenticationDetails
      implements Serializable
{
  /**
   * The name of the field that may be used to specify the authentication ID.
   * This may be used in conjunction with the CRAM-MD5, DIGEST-MD5, GSSAPI, and
   * PLAIN authentication types.  It is required for use with those
   * authentication types, and its value must be a string that represents an
   * appropriate authentication ID for that authentication type.
   */
  @NotNull private static final String FIELD_AUTHENTICATION_ID =
       "authentication-id";



  /**
   * The name of the field that may be used to specify the type of
   * authentication to perform.  It is a required field, and its value must be a
   * string with one of the following values:  "none" (to indicate that no
   * authentication should be performed), "simple" (to indicate LDAP simple
   * authentication), "CRAM-MD5" (for the CRAM-MD5 SASL mechanism), "DIGEST-MD5"
   * (for the DIGEST-MD5 SASL mechanism), "EXTERNAL" (for the EXTERNAL SASL
   * mechanism), "GSSAPI" (for the GSSAPI SASL mechanism), or "PLAIN" (for the
   * PLAIN SASL mechanism).
   */
  @NotNull private static final String FIELD_AUTHENTICATION_TYPE =
       "authentication-type";



  /**
   * The name of the field that may be used to specify the authorization ID.
   * This may be used in conjunction with the DIGEST-MD5, EXTERNAL, GSSAPI, and
   * PLAIN authentication types, and is an optional field for those
   * authentication types.  If present, its value must be a string that
   * represents an appropriate authorization ID for that authentication type.
   */
  @NotNull private static final String FIELD_AUTHORIZATION_ID =
       "authorization-id";



  /**
   * The name of the field that may be used to specify the path to a JAAS
   * configuration file.  This is an optional field that may be used in
   * conjunction with the GSSAPI authentication type.  If present, its value
   * must be a path to a valid JAAS configuration file.  If it is not present,
   * then a temporary configuration file will be automatically created and used
   * for this purpose.
   */
  @NotNull private static final String FIELD_CONFIG_FILE_PATH =
       "config-file-path";



  /**
   * The name of the field that may be used to specify the bind DN.  This field
   * may be used in conjunction with the simple authentication type, and it is
   * required for use in conjunction with that authentication type.  Its value
   * must be the DN to use when performing simple authentication, or an empty
   * string to indicate anonymous authentication.
   */
  @NotNull private static final String FIELD_DN = "dn";



  /**
   * The name of the field that may be used to specify the address of the
   * Kerberos KDC.  This field may be used in conjunction with the GSSAPI
   * authentication type, and it is an optional field for that authentication
   * type.  If present, its value must be a string that represents a resolvable
   * name or IP address.  If absent, the LDAP SDK will attempt to automatically
   * determine the address of the Kerberos KDC from the underlying system.
   */
  @NotNull private static final String FIELD_KDC_ADDRESS = "kdc-address";



  /**
   * The name of the field that may be used to specify the password.  This field
   * may be used in conjunction with the simple, CRAM-MD5, DIGEST-MD5, GSSAPI,
   * and PLAIN authentication types.  It may not be used in conjunction with the
   * password-file field.  A password must be provided via either the password
   * or password-file field for the simple CRAM-MD5, DIGEST-MD5, and PLAIN
   * authentication types, and should be provided for the GSSAPI authentication
   * type unless require-cached-credentials is true.  If present, its value
   * should be a string containing the password to use, or an empty string to
   * indicate anonymous authentication.
   */
  @NotNull private static final String FIELD_PASSWORD = "password";



  /**
   * The name of the field that may be used to specify the path to a file
   * containing the password.  This field may be used in conjunction with the
   * simple, CRAM-MD5, DIGEST-MD5, GSSAPI, and PLAIN authentication types.  It
   * may not be used in conjunction with the password field.  A password must be
   * provided via either the password or password-file field for the simple
   * CRAM-MD5, DIGEST-MD5, and PLAIN authentication types, and should be
   * provided for the GSSAPI authentication type unless
   * require-cached-credentials is true.  If present, its value should be a
   * string containing the path to a file containing the password to use.  The
   * file should not be empty, so this field is not appropriate for anonymous
   * authentication.
   */
  @NotNull private static final String FIELD_PASSWORD_FILE = "password-file";



  /**
   * The name of the field that may be used to specify the allowed quality of
   * protection types.  This may be used in conjunction with the DIGEST-MD5 and
   * GSSAPI authentication types, and its value must be an array containing one
   * or more of the following strings:  "auth", "auth-int", and "auth-conf".
   * If this is not provided, then a single-element array containing only the
   * "auth" value will be used.
   */
  @NotNull private static final String FIELD_QOP = "qop";



  /**
   * The name of the field that may be used to specify the realm.  This field
   * may be used in conjunction with the DIGEST-MD5 and GSSAPI authentication
   * types, and it is optional for those types.  If present, its value must
   * be a string that indicates the realm to use for the authentication.  If
   * it is absent, no realm will be provided to the server during the
   * authentication process.
   */
  @NotNull private static final String FIELD_REALM = "realm";



  /**
   * The name of the field that may be used to indicate whether to attempt to
   * automatically renew the Kerberos ticket-granting ticket.  This field may be
   * used in conjunction with the GSSAPI authentication type, and it is optional
   * for use with that authentication type.  If present, its value must be a
   * boolean.  If this field is absent, then a default value of {@code false}
   * will be used.
   */
  @NotNull private static final String FIELD_RENEW_TGT = "renew-tgt";



  /**
   * The name of the field that may be used to indicate whether to require the
   * use of cached credentials for authentication.  This field may be used in
   * conjunction with the GSSAPI authentication type, and it is optional for use
   * with that authentication type.  If present, its value must be a boolean.
   * If this field is absent, then a default value of {@code false} will be
   * used.
   */
  @NotNull private static final String FIELD_REQUIRE_CACHED_CREDENTIALS =
       "require-cached-credentials";



  /**
   * The name of the field that may be used to specify the path to the Kerberos
   * ticket cache to use if appropriate.  This field may be used in conjunction
   * with the GSSAPI authentication type, and it is optional for use with that
   * authentication type.  If present, its value must be the path to the
   * Kerberos ticket cache.  if this field is absent, then JVM will attempt to
   * automatically determine the ticket cache path.
   */
  @NotNull private static final String FIELD_TICKET_CACHE_PATH =
       "ticket-cache-path";



  /**
   * The name of the field that may be used to indicate whether the client will
   * be required to use credentials within the current subject.  This field may
   * be used in conjunction with the GSSAPI authentication type, and it is
   * optional for use with that authentication type.  If present, its value must
   * be a boolean.  If it is not provided, then a default value of {@code true}
   * will be used.
   */
  @NotNull private static final String FIELD_USE_SUBJECT_CREDS_ONLY =
       "use-subject-credentials-only";



  /**
   * The name of the field that may be used to indicate whether to use the
   * Kerberos ticket cache.  This field may be used in conjunction with the
   * GSSAPI authentication type, and it is optional for use with that
   * authentication type.  If present, its value must be a boolean.  If it is
   * not provided, then a default value of {@code true} will be used.
   */
  @NotNull private static final String FIELD_USE_TICKET_CACHE =
       "use-ticket-cache";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2798778432389082274L;



  // The bind request created from the specification.
  @Nullable private final BindRequest bindRequest;



  /**
   * Creates a new set of authentication details from the information contained
   * in the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object containing the LDAP
   *                                  connection details specification.
   *
   * @throws LDAPException  If there is a problem with the authentication
   *                         details data in the provided JSON object.
   */
  AuthenticationDetails(@NotNull final JSONObject connectionDetailsObject)
       throws LDAPException
  {
    final JSONObject o = LDAPConnectionDetailsJSONSpecification.getObject(
         connectionDetailsObject,
         LDAPConnectionDetailsJSONSpecification.FIELD_AUTHENTICATION_DETAILS);
    if (o == null)
    {
      bindRequest = null;
      return;
    }

    final String authType =
         LDAPConnectionDetailsJSONSpecification.getString(o,
              FIELD_AUTHENTICATION_TYPE, null);
    final String loweAuthType = StaticUtils.toLowerCase(authType);
    if (loweAuthType == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD.get(
                LDAPConnectionDetailsJSONSpecification.
                     FIELD_AUTHENTICATION_DETAILS,
                FIELD_AUTHENTICATION_TYPE));
    }
    else if (loweAuthType.equals("none"))
    {
      LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o,
           LDAPConnectionDetailsJSONSpecification.FIELD_AUTHENTICATION_DETAILS,
           FIELD_AUTHENTICATION_TYPE);
      bindRequest = null;
    }
    else if (loweAuthType.equals("simple"))
    {
      validateAllowedFields(o, authType,
           FIELD_DN,
           FIELD_PASSWORD,
           FIELD_PASSWORD_FILE);

      final String dn = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_DN, null);
      if (dn == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD_FOR_AUTH_TYPE.get(
                  FIELD_DN, authType));
      }

      final String password = getPassword(o, authType, false);
      bindRequest = new SimpleBindRequest(dn, password);
    }
    else if (loweAuthType.equals("cram-md5") ||
             loweAuthType.equals("crammd5"))
    {
      validateAllowedFields(o, authType,
           FIELD_AUTHENTICATION_ID,
           FIELD_PASSWORD,
           FIELD_PASSWORD_FILE);

      final String authID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHENTICATION_ID, null);
      if (authID == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD_FOR_AUTH_TYPE.get(
                  FIELD_AUTHENTICATION_ID, authType));
      }

      final String password = getPassword(o, authType, false);
      bindRequest = new CRAMMD5BindRequest(authID, password);
    }
    else if (loweAuthType.equals("digest-md5") ||
             loweAuthType.equals("digestmd5"))
    {
      validateAllowedFields(o, authType,
           FIELD_AUTHENTICATION_ID,
           FIELD_AUTHORIZATION_ID,
           FIELD_PASSWORD,
           FIELD_PASSWORD_FILE,
           FIELD_QOP,
           FIELD_REALM);

      final String authID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHENTICATION_ID, null);
      if (authID == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD_FOR_AUTH_TYPE.get(
                  FIELD_AUTHENTICATION_ID, authType));
      }

      final String password = getPassword(o, authType, false);

      final DIGESTMD5BindRequestProperties properties =
           new DIGESTMD5BindRequestProperties(authID, password);
      properties.setAuthorizationID(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_AUTHORIZATION_ID, null));
      properties.setRealm(LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_REALM, null));
      properties.setAllowedQoP(getAllowedQoP(o));

      bindRequest = new DIGESTMD5BindRequest(properties);
    }
    else if (loweAuthType.equals("external"))
    {
      validateAllowedFields(o, authType,
           FIELD_AUTHORIZATION_ID);

      final String authzID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHORIZATION_ID, null);
      bindRequest = new EXTERNALBindRequest(authzID);
    }
    else if (loweAuthType.equals("gssapi") ||
             loweAuthType.equals("gss-api"))
    {
      validateAllowedFields(o, authType,
           FIELD_AUTHENTICATION_ID,
           FIELD_AUTHORIZATION_ID,
           FIELD_PASSWORD,
           FIELD_PASSWORD_FILE,
           FIELD_CONFIG_FILE_PATH,
           FIELD_KDC_ADDRESS,
           FIELD_QOP,
           FIELD_REALM,
           FIELD_RENEW_TGT,
           FIELD_REQUIRE_CACHED_CREDENTIALS,
           FIELD_TICKET_CACHE_PATH,
           FIELD_USE_SUBJECT_CREDS_ONLY,
           FIELD_USE_TICKET_CACHE);

      final String authID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHENTICATION_ID, null);
      if (authID == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD_FOR_AUTH_TYPE.get(
                  FIELD_AUTHENTICATION_ID, authType));
      }

      final String password = getPassword(o, authType, true);

      final GSSAPIBindRequestProperties properties =
           new GSSAPIBindRequestProperties(authID, password);
      properties.setAuthorizationID(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_AUTHORIZATION_ID, null));
      properties.setRealm(LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_REALM, null));
      properties.setAllowedQoP(getAllowedQoP(o));
      properties.setConfigFilePath(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_CONFIG_FILE_PATH, null));
      properties.setKDCAddress(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_KDC_ADDRESS, null));
      properties.setRenewTGT(
           LDAPConnectionDetailsJSONSpecification.getBoolean(o,
                FIELD_RENEW_TGT, false));
      properties.setRequireCachedCredentials(
           LDAPConnectionDetailsJSONSpecification.getBoolean(o,
                FIELD_REQUIRE_CACHED_CREDENTIALS, false));
      properties.setTicketCachePath(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_TICKET_CACHE_PATH, null));
      properties.setUseSubjectCredentialsOnly(
           LDAPConnectionDetailsJSONSpecification.getBoolean(o,
                FIELD_USE_SUBJECT_CREDS_ONLY, true));
      properties.setUseTicketCache(
           LDAPConnectionDetailsJSONSpecification.getBoolean(o,
                FIELD_USE_TICKET_CACHE, true));

      if ((password == null) && (! properties.requireCachedCredentials()))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_GSSAPI_PASSWORD.get(FIELD_PASSWORD,
                  FIELD_PASSWORD_FILE, authType,
                  FIELD_REQUIRE_CACHED_CREDENTIALS));
      }

      bindRequest = new GSSAPIBindRequest(properties);
    }
    else if (loweAuthType.equals("plain"))
    {
      validateAllowedFields(o, authType,
           FIELD_AUTHENTICATION_ID,
           FIELD_AUTHORIZATION_ID,
           FIELD_PASSWORD,
           FIELD_PASSWORD_FILE);

      final String authID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHENTICATION_ID, null);
      if (authID == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_MISSING_REQUIRED_FIELD_FOR_AUTH_TYPE.get(
                  FIELD_AUTHENTICATION_ID, authType));
      }

      final String authzID = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_AUTHORIZATION_ID, null);
      final String password = getPassword(o, authType, false);
      bindRequest = new PLAINBindRequest(authID, authzID, password);
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_AUTH_DETAILS_UNRECOGNIZED_TYPE.get(authType));
    }
  }



  /**
   * Retrieves the bind request created from the authentication details.
   *
   * @return  The bind request created from the authentication details.
   */
  @Nullable()
  BindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Validates that all of the provided fields are allowed for use in
   * conjunction with the specified authentication type.
   *
   * @param  o              The JSON object to process.
   * @param  authType       The name of the authentication type.
   * @param  allowedFields  The names of the fields allowed for use with the
   *                        specified authentication type.
   *
   * @throws  LDAPException  If the provided object contains any field not
   *                         permitted in conjunction with the specified
   *                         authentication type.
   */
  private static void validateAllowedFields(@NotNull final JSONObject o,
                           @NotNull final String authType,
                           @NotNull final String... allowedFields)
          throws LDAPException
  {
    final HashSet<String> s = new HashSet<>(Arrays.asList(allowedFields));
    for (final String fieldName : o.getFields().keySet())
    {
      if (fieldName.equals(FIELD_AUTHENTICATION_TYPE))
      {
        continue;
      }

      if (! s.contains(fieldName))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_FIELD_NOT_PERMITTED_FOR_AUTH_TYPE.get(fieldName,
                  authType));
      }
    }
  }



  /**
   * Retrieves a password from the provided JSON object.  The password must
   * either be directly contained in the object's password field, or it must be
   * in a file referenced by the object's password-file object.
   *
   * @param  o         The JSON object to process.
   * @param  authType  The authentication type.
   * @param  optional  Indicates whether the password should be optional for the
   *                   bind request.
   *
   * @return  The password, or {@code null} if no password was provided and the
   *          password is optional.
   *
   * @throws  LDAPException  If no password is available or a problem is
   *                         encountered while trying to read the password from
   *                         a file.
   */
  @Nullable()
  private static String getPassword(@NotNull final JSONObject o,
                                    @NotNull final String authType,
                                    final boolean optional)
          throws LDAPException
  {
    final String password = LDAPConnectionDetailsJSONSpecification.getString(o,
         FIELD_PASSWORD, null);
    if (password != null)
    {
      LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o,
           FIELD_PASSWORD, FIELD_PASSWORD_FILE);
      return password;
    }

    final String path = LDAPConnectionDetailsJSONSpecification.getString(o,
         FIELD_PASSWORD_FILE, null);
    if (path == null)
    {
      if (optional)
      {
        return null;
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_AUTH_DETAILS_NO_PASSWORD.get(FIELD_PASSWORD,
                  FIELD_PASSWORD_FILE, authType));
      }
    }

    return LDAPConnectionDetailsJSONSpecification.getStringFromFile(path,
         FIELD_PASSWORD_FILE);
  }



  /**
   * Retrieves the allowed quality of protection values from the provided JSON
   * object.
   *
   * @param  o  The JSON object to process.
   *
   * @return  A set containing the allowed quality of protection values.
   *
   * @throws  LDAPException  If no password is available or a problem is
   *                         encountered while trying to read the password from
   *                         a file.
   */
  @NotNull()
  private static List<SASLQualityOfProtection> getAllowedQoP(
                                                    @NotNull final JSONObject o)
          throws LDAPException
  {
    final JSONValue v = o.getField(FIELD_QOP);
    if (v == null)
    {
      return Collections.singletonList(SASLQualityOfProtection.AUTH);
    }

    if (v instanceof JSONString)
    {
      return SASLQualityOfProtection.decodeQoPList(
           ((JSONString) v).stringValue());
    }
    else if (v instanceof JSONArray)
    {
      final JSONArray a = (JSONArray) v;
      final ArrayList<SASLQualityOfProtection> qopList =
           new ArrayList<>(a.size());
      for (final JSONValue av : a.getValues())
      {
        if (av instanceof JSONString)
        {
          final SASLQualityOfProtection qop = SASLQualityOfProtection.forName(
               ((JSONString) av).stringValue());
          if (qop == null)
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_AUTH_DETAILS_INVALID_QOP.get(FIELD_QOP));
          }
          else
          {
            qopList.add(qop);
          }
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_AUTH_DETAILS_INVALID_QOP.get(FIELD_QOP));
        }
      }

      return qopList;
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_AUTH_DETAILS_INVALID_QOP.get(FIELD_QOP));
    }
  }
}
