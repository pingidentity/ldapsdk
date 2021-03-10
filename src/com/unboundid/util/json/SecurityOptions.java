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



import java.util.Arrays;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.PKCS11KeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a data structure and set of logic for interacting with
 * the set of security options in a JSON object provided to the
 * {@link LDAPConnectionDetailsJSONSpecification}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SecurityOptions
{
  /**
   * The name of the field that specifies the alias of the client certificate to
   * use.  If this field is present, then it must be a string that matches the
   * nickname of a client certificate in the configured key store.  If it is
   * absent, then a client certificate will be automatically selected if
   * necessary.
   */
  @NotNull private static final String FIELD_CLIENT_CERT_ALIAS =
       "client-certificate-alias";



  /**
   * The name of the field that specifies the path to the key store file.  If
   * this field is present, then it must be a string that represents a valid
   * path to a key store file in a supported format.  If it is absent, then no
   * key store file will be used.
   */
  @NotNull private static final String FIELD_KEY_STORE_FILE = "key-store-file";



  /**
   * The name of the field that specifies the PIN to use when accessing the key
   * store.  If it is present, then it must be a string containing the PIN.  If
   * it is absent, then the PIN may be read from the file specified in the
   * key-store-pin-file field, or no PIN will be used if that field is not
   * present.  The key-store-pin and key-store-pin-file fields must not both be
   * present, and neither field may be present unless the key-store-file field
   * is present or the key-store-type field is present with a value of "PKCS11".
   */
  @NotNull private static final String FIELD_KEY_STORE_PIN = "key-store-pin";



  /**
   * The name of the field that specifies the path to a file containing the PIN
   * to use when accessing the key store.  If it is present, then it must be a
   * string that represents the path to a file containing the PIN.  If it is
   * absent, then the PIN may obtained from the key-store-pin field, or no PIN
   * will be used if that field is not present.  The key-store-pin and
   * key-store-pin-file fields must not both be present, and neither field may
   * be present unless the key-store-file field is present or the key-store-type
   * field is present with a value of "PKCS11".
   */
  @NotNull private static final String FIELD_KEY_STORE_PIN_FILE =
       "key-store-pin-file";



  /**
   * The name of the field that specifies the type of key store to use.  If it
   * is present, then the value must be a string with a value of "JKS",
   * "PKCS12", or "PKCS11".  If the value is "JKS" or "PKCS12", then the
   * key-store-file field must have been provided.  If the value is "PKCS11",
   * then the key-store-field field must not have been provided.  If it is
   * absent, then a default key store type of "JKS" will be assumed if a
   * key-store-file field is present.
   */
  @NotNull private static final String FIELD_KEY_STORE_TYPE = "key-store-type";



  /**
   * The name of the field that specifies the type of security to use.  If
   * present, the value must be a string whose value is "none" (for no
   * security), either "SSL" or "TLS" (for entirely-encrypted communication via
   * the Transport-Layer Security protocol), or "StartTLS" (to use the StartTLS
   * extended operation to encrypt communication over an initially-unencrypted
   * connection.  If this is not present, a default value of "none" will be
   * used.  If the value of "none" is used (or assumed as the default value),
   * then none of the other fields may be present.
   */
  @NotNull private static final String FIELD_SECURITY_TYPE = "security-type";



  /**
   * The name of the field that indicates whether to blindly trust all
   * certificates that servers may present.  This is convenient for testing
   * purposes, but is not recommended for production use because it does not
   * provide any protection against man-in-the-middle attacks.  If present, the
   * value should be a boolean, and if the value is {@code true} then the
   * trust-jvm-default-issuers, trust-store-file, trust-store-pin,
   * trust-store-pin-file, and trust-store-type fields must not be provided.  If
   * it is absent, then a default of {@code false} will be used.
   */
  @NotNull private static final String FIELD_TRUST_ALL_CERTS =
       "trust-all-certificates";



  /**
   * The name of the field that indicates whether to trust certificates that are
   * outside their validity period, whether the current time is earlier than the
   * "notBefore" time or later than the "notAfter" time.  If present, the value
   * should be a boolean, and if the value is {@code true} then certificate
   * validity time violations will be overlooked if the certificate would have
   * otherwise been accepted.  If it is absent, then a default of {@code false}
   * will be used.  Note that unless this field is present with a value of
   * {@code true}, then certificates will not be trusted outside of their
   * validity window even if the trust-all-certificates field is present with a
   * value of true.
   */
  @NotNull private static final String FIELD_TRUST_EXPIRED_CERTS =
       "trust-expired-certificates";



  /**
   * The name of the field that indicates whether to trust any certificate
   * signed by one of the JVM's default trusted issuers.  If present, the value
   * should be a boolean.
   */
  @NotNull private static final String FIELD_USE_JVM_DEFAULT_TRUST_STORE =
       "use-jvm-default-trust-store";



  /**
   * The name of the field that specifies the path to the trust store file.  If
   * provided, this should be a string that represents a path to a valid trust
   * store file in a recognized format.  If this is absent, then no trust store
   * will be accessed and the JVM's default trust mechanism will be used.
   */
  @NotNull private static final String FIELD_TRUST_STORE_FILE =
       "trust-store-file";



  /**
   * The name of the field that specifies the PIN to use when accessing the
   * trust store.  If it is present, then it must be a string containing the
   * PIN.  If it is absent, then the PIN may be read from the file specified in
   * the trust-store-pin-file field, or no PIN will be used if that field is not
   * present.  The trust-store-pin and trust-store-pin-file fields must not both
   * be present, and neither field may be present unless the trust-store-file
   * field is present.
   */
  @NotNull private static final String FIELD_TRUST_STORE_PIN =
       "trust-store-pin";



  /**
   * The name of the field that specifies a file containing the PIN to use when
   * accessing the trust store.  If it is present, then it must be a string
   * containing the path to a file containing the PIN.  If it is absent, then
   * the PIN may be specified in the trust-store-pin field, or no PIN will be
   * used if that field is not present.  The trust-store-pin and
   * trust-store-pin-file fields must not both be present, and neither field may
   * be present unless the trust-store-file field is present.
   */
  @NotNull private static final String FIELD_TRUST_STORE_PIN_FILE =
       "trust-store-pin-file";



  /**
   * The name of the field that specifies the type of trust store to use.  If it
   * is present, then it must be a string with a value of either "JKS" or
   * "PKCS12".  If it is absent, then a default trust store type of "JKS" will
   * be used if the trust-store-file field is present.
   */
  @NotNull private static final String FIELD_TRUST_STORE_TYPE =
       "trust-store-type";



  /**
   * The name of the field that indicates whether to verify the address
   * contained in the certificate.  If present, the value of this field must be
   * a boolean, and a value of {@code true} indicates that either the address
   * used to connect to the server must match the value of the CN attribute
   * in the certificate subject, or address used to connect to the server must
   * be present in a dNSName, uniformResourceIdentifier, or iPAddress
   * subjectAltName extension in the certificate.  If it is not present, a
   * default value of {@code false} will be used.
   */
  @NotNull private static final String FIELD_VERIFY_ADDRESS =
       "verify-address-in-certificate";



  // Indicates whether to verify certificate addresses.
  private final boolean verifyAddressInCertificate;

  // The socket factory to use when creating connections.
  @NotNull private final SocketFactory socketFactory;

  // The post-connect processor to use if StartTLS-protected connections are to
  // be used in a connection pool.
  @Nullable private final StartTLSPostConnectProcessor postConnectProcessor;



  /**
   * Creates a new set of security options from the information contained in
   * the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object containing the LDAP
   *                                  connection details specification.
   *
   * @throws  LDAPException  If there is a problem with the security options
   *                         data in the provided JSON object.
   */
  SecurityOptions(@NotNull final JSONObject connectionDetailsObject)
       throws LDAPException
  {
    boolean useSSL = false;
    boolean useStartTLS = false;
    boolean trustAll = false;
    boolean trustExpired = false;
    boolean useJVMDefaultTrustStore = false;
    boolean verifyAddress = false;
    String  certAlias = null;
    String  keyStoreFile = null;
    String  keyStorePIN = null;
    String  keyStoreType = null;
    String  trustStoreFile = null;
    String  trustStorePIN = null;
    String  trustStoreType = null;

    final JSONObject o = LDAPConnectionDetailsJSONSpecification.getObject(
         connectionDetailsObject,
         LDAPConnectionDetailsJSONSpecification.FIELD_COMMUNICATION_SECURITY);
    if (o != null)
    {
      LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o,
           LDAPConnectionDetailsJSONSpecification.FIELD_COMMUNICATION_SECURITY,
           FIELD_CLIENT_CERT_ALIAS,
           FIELD_KEY_STORE_FILE,
           FIELD_KEY_STORE_PIN,
           FIELD_KEY_STORE_PIN_FILE,
           FIELD_KEY_STORE_TYPE,
           FIELD_SECURITY_TYPE,
           FIELD_TRUST_ALL_CERTS,
           FIELD_TRUST_EXPIRED_CERTS,
           FIELD_TRUST_STORE_FILE,
           FIELD_TRUST_STORE_PIN,
           FIELD_TRUST_STORE_PIN_FILE,
           FIELD_TRUST_STORE_TYPE,
           FIELD_USE_JVM_DEFAULT_TRUST_STORE,
           FIELD_VERIFY_ADDRESS);

      final String type = StaticUtils.toLowerCase(
           LDAPConnectionDetailsJSONSpecification.getString(o,
                FIELD_SECURITY_TYPE, null));
      if (type == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SECURITY_OPTIONS_MISSING_SECURITY_TYPE.get(
                  FIELD_SECURITY_TYPE));
      }
      else if (type.equals("none"))
      {
        if (o.getFields().size() > 1)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SECURITY_OPTIONS_INVALID_FIELD_WITH_NONE.get(
                    FIELD_SECURITY_TYPE));
        }
      }
      else if (type.equals("ssl") || type.equals("tls"))
      {
        useSSL = true;
      }
      else if (type.equals("starttls") || type.equals("start-tls"))
      {
        useStartTLS = true;
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SECURITY_OPTIONS_INVALID_TYPE.get(FIELD_SECURITY_TYPE));
      }

      trustExpired = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_TRUST_EXPIRED_CERTS, false);

      trustAll = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_TRUST_ALL_CERTS, false);
      if (trustAll)
      {
        LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o,
             FIELD_TRUST_ALL_CERTS,
             FIELD_TRUST_STORE_FILE,
             FIELD_TRUST_STORE_PIN,
             FIELD_TRUST_STORE_PIN_FILE,
             FIELD_TRUST_STORE_TYPE,
             FIELD_USE_JVM_DEFAULT_TRUST_STORE);
      }
      else
      {
        trustStoreFile = LDAPConnectionDetailsJSONSpecification.getString(o,
             FIELD_TRUST_STORE_FILE, null);
        if (trustStoreFile == null)
        {
          LDAPConnectionDetailsJSONSpecification.rejectUnresolvedDependency(o,
               FIELD_TRUST_STORE_FILE,
               FIELD_TRUST_STORE_PIN,
               FIELD_TRUST_STORE_PIN_FILE,
               FIELD_TRUST_STORE_TYPE);
        }
        else
        {
          trustStoreType = LDAPConnectionDetailsJSONSpecification.getString(o,
               FIELD_TRUST_STORE_TYPE,
               CryptoHelper.KEY_STORE_TYPE_JKS).toUpperCase();
          if (! (trustStoreType.equals(CryptoHelper.KEY_STORE_TYPE_JKS) ||
                 trustStoreType.equals(CryptoHelper.KEY_STORE_TYPE_PKCS_12)))
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_SECURITY_OPTIONS_INVALID_TS_TYPE.get(
                      FIELD_TRUST_STORE_TYPE, trustStoreType));
          }

          trustStorePIN = LDAPConnectionDetailsJSONSpecification.getString(o,
               FIELD_TRUST_STORE_PIN, null);
          if (trustStorePIN == null)
          {
            final String trustStorePINFile =
                 LDAPConnectionDetailsJSONSpecification.getString(o,
                      FIELD_TRUST_STORE_PIN_FILE, null);
            if (trustStorePINFile != null)
            {
              trustStorePIN =
                   LDAPConnectionDetailsJSONSpecification.getStringFromFile(
                        trustStorePINFile, FIELD_TRUST_STORE_PIN_FILE);
            }
          }
          else
          {
            LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o,
                 FIELD_TRUST_STORE_PIN,
                 FIELD_TRUST_STORE_PIN_FILE);
          }
        }

        useJVMDefaultTrustStore =
             LDAPConnectionDetailsJSONSpecification.getBoolean(o,
                  FIELD_USE_JVM_DEFAULT_TRUST_STORE, false);
      }

      verifyAddress = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_VERIFY_ADDRESS, verifyAddress);

      boolean useKeyStore = false;
      keyStoreFile = LDAPConnectionDetailsJSONSpecification.getString(o,
           FIELD_KEY_STORE_FILE, keyStoreFile);
      if (keyStoreFile != null)
      {
        useKeyStore = true;
        keyStoreType = LDAPConnectionDetailsJSONSpecification.getString(o,
             FIELD_KEY_STORE_TYPE,
             CryptoHelper.KEY_STORE_TYPE_JKS).toUpperCase();
        if (! (keyStoreType.equals(CryptoHelper.KEY_STORE_TYPE_JKS) ||
             keyStoreType.equals(CryptoHelper.KEY_STORE_TYPE_PKCS_12)))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SECURITY_OPTIONS_INVALID_KS_TYPE_WITH_FILE.get(
                    FIELD_KEY_STORE_TYPE, keyStoreType));

        }
      }
      else
      {
        keyStoreType = LDAPConnectionDetailsJSONSpecification.getString(o,
             FIELD_KEY_STORE_TYPE, null);
        if (keyStoreType != null)
        {
          useKeyStore = true;
          keyStoreType = keyStoreType.toUpperCase();
          if (! keyStoreType.equals("PKCS11"))
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_SECURITY_OPTIONS_INVALID_KS_TYPE_WITHOUT_FILE.get(
                      FIELD_KEY_STORE_TYPE, keyStoreType,
                      FIELD_KEY_STORE_FILE));
          }
        }
      }

      if (useKeyStore)
      {
        certAlias = LDAPConnectionDetailsJSONSpecification.getString(o,
             FIELD_CLIENT_CERT_ALIAS, null);

        keyStorePIN = LDAPConnectionDetailsJSONSpecification.getString(o,
             FIELD_KEY_STORE_PIN, null);
        if (keyStorePIN == null)
        {
          final String keyStorePINFile =
               LDAPConnectionDetailsJSONSpecification.getString(o,
                    FIELD_KEY_STORE_PIN_FILE, null);
          if (keyStorePINFile != null)
          {
            keyStorePIN =
                 LDAPConnectionDetailsJSONSpecification.getStringFromFile(
                      keyStorePINFile, FIELD_KEY_STORE_PIN_FILE);
          }
        }
        else
        {
          LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o,
               FIELD_KEY_STORE_PIN, FIELD_KEY_STORE_PIN_FILE);
        }
      }
      else
      {
        for (final String fieldName :
             Arrays.asList(FIELD_KEY_STORE_PIN, FIELD_KEY_STORE_PIN_FILE,
                  FIELD_CLIENT_CERT_ALIAS))
        {
          if (o.getField(fieldName) != null)
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_SECURITY_OPTIONS_INVALID_FIELD_WITHOUT_KS.get(fieldName));
          }
        }
      }
    }

    verifyAddressInCertificate = verifyAddress;

    if (useSSL || useStartTLS)
    {
      final TrustManager trustManager;
      try
      {
        if (trustAll)
        {
          trustManager = new TrustAllTrustManager(! trustExpired);
        }
        else
        {
          if (trustStoreFile == null)
          {
            if (useJVMDefaultTrustStore)
            {
              trustManager = JVMDefaultTrustManager.getInstance();
            }
            else
            {
              trustManager = null;
            }
          }
          else
          {
            final char[] trustStorePINArray;
            if (trustStorePIN == null)
            {
              trustStorePINArray = null;
            }
            else
            {
              trustStorePINArray = trustStorePIN.toCharArray();
            }

            final TrustStoreTrustManager trustStoreTrustManager =
                 new TrustStoreTrustManager(trustStoreFile, trustStorePINArray,
                      trustStoreType, ! trustExpired);
            if (useJVMDefaultTrustStore)
            {
              trustManager = new AggregateTrustManager(false,
                   trustStoreTrustManager,
                   JVMDefaultTrustManager.getInstance());
            }
            else
            {
              trustManager = trustStoreTrustManager;
            }
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SECURITY_OPTIONS_CANNOT_CREATE_TRUST_MANAGER.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      final KeyManager keyManager;
      try
      {
        final char[] keyStorePINArray;
        if (keyStorePIN == null)
        {
          keyStorePINArray = null;
        }
        else
        {
          keyStorePINArray = keyStorePIN.toCharArray();
        }

        if (keyStoreFile != null)
        {
          keyManager = new KeyStoreKeyManager(keyStoreFile, keyStorePINArray,
               keyStoreType, certAlias);
        }
        else if ((keyStoreType != null) && keyStoreType.equals("PKCS11"))
        {
          keyManager = new PKCS11KeyManager(keyStorePINArray, certAlias);
        }
        else
        {
          keyManager = null;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SECURITY_OPTIONS_CANNOT_CREATE_KEY_MANAGER.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      final SSLUtil sslUtil = new SSLUtil(keyManager, trustManager);
      if (useSSL)
      {
        try
        {
          socketFactory = sslUtil.createSSLSocketFactory();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SECURITY_OPTIONS_CANNOT_CREATE_SOCKET_FACTORY.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }

        postConnectProcessor = null;
      }
      else
      {
        socketFactory = SocketFactory.getDefault();

        try
        {
          postConnectProcessor = new StartTLSPostConnectProcessor(
               sslUtil.createSSLSocketFactory());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SECURITY_OPTIONS_CANNOT_CREATE_POST_CONNECT_PROCESSOR.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }
    else
    {
      socketFactory = SocketFactory.getDefault();
      postConnectProcessor = null;
    }
  }



  /**
   * Indicates whether to verify server addresses against certificates.
   *
   * @return  Whether to verify server addresses against certificates.
   */
  boolean verifyAddressInCertificate()
  {
    return verifyAddressInCertificate;
  }



  /**
   * Retrieves the socket factory to use when establishing connections.
   *
   * @return  The socket factory to use when establishing connections.
   */
  @NotNull()
  SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Retrieves the StartTLS post-connect processor to use with a connection
   * pool.
   *
   * @return  The StartTLS post-connect processor to use with a connection pool.
   */
  @Nullable()
  StartTLSPostConnectProcessor getPostConnectProcessor()
  {
    return postConnectProcessor;
  }
}
