/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.NameResolver;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.ManageCertificates;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a mechanism for generating a self-signed certificate for
 * use by a listener that supports SSL or StartTLS.
 */
@ThreadSafety(level= ThreadSafetyLevel.NOT_THREADSAFE)
public final class SelfSignedCertificateGenerator
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private SelfSignedCertificateGenerator()
  {
    // No implementation is required.
  }



  /**
   * Generates a temporary keystore containing a self-signed certificate for
   * use by a listener that supports SSL or StartTLS.
   *
   * @param  toolName      The name of the tool for which the certificate is to
   *                       be generated.
   * @param  keyStoreType  The key store type for the keystore to be created.
   *                       It must not be {@code null}.
   *
   * @return  An {@code ObjectPair} containing the path and PIN for the keystore
   *          that was generated.
   *
   * @throws  CertException  If a problem occurs while trying to generate the
   *                         temporary keystore containing the self-signed
   *                         certificate.
   */
  @NotNull()
  public static ObjectPair<File,char[]> generateTemporarySelfSignedCertificate(
                                             @NotNull final String toolName,
                                             @NotNull final String keyStoreType)
         throws CertException
  {
    final File keyStoreFile;
    try
    {
      keyStoreFile = File.createTempFile("temp-keystore-", ".jks");
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_SELF_SIGNED_CERT_GENERATOR_CANNOT_CREATE_FILE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    keyStoreFile.delete();

    final SecureRandom random = CryptoHelper.getSecureRandom();
    final byte[] randomBytes = new byte[50];
    random.nextBytes(randomBytes);
    final String keyStorePIN = Base64.encode(randomBytes);

    generateSelfSignedCertificate(toolName, keyStoreFile, keyStorePIN,
         keyStoreType, "server-cert");
    return new ObjectPair<>(keyStoreFile, keyStorePIN.toCharArray());
  }



  /**
   * Generates a self-signed certificate in the specified keystore.
   *
   * @param  toolName      The name of the tool for which the certificate is to
   *                       be generated.
   * @param  keyStoreFile  The path to the keystore file in which the
   *                       certificate is to be generated.  This must not be
   *                       {@code null}, and if the target file exists, then it
   *                       must be a JKS or PKCS #12 keystore.  If it does not
   *                       exist, then at least the parent directory must exist.
   * @param  keyStorePIN   The PIN needed to access the keystore.  It must not
   *                       be {@code null}.
   * @param  keyStoreType  The key store type for the keystore to be created, if
   *                       it does not already exist.  It must not be
   *                       {@code null}.
   * @param  alias         The alias to use for the certificate in the keystore.
   *                       It must not be {@code null}.
   *
   * @throws  CertException  If a problem occurs while trying to generate
   *                         self-signed certificate.
   */
  public static void generateSelfSignedCertificate(
                          @NotNull final String toolName,
                          @NotNull final File keyStoreFile,
                          @NotNull final String keyStorePIN,
                          @NotNull final String keyStoreType,
                          @NotNull final String alias)
         throws CertException
  {
    // Try to get a set of all addresses associated with the local system and
    // their corresponding canonical hostnames.
    final NameResolver nameResolver =
         LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
    Set<InetAddress> localAddresses =
         StaticUtils.getAllLocalAddresses(nameResolver, false);
    if (localAddresses.isEmpty())
    {
      localAddresses = StaticUtils.getAllLocalAddresses(nameResolver, true);

    }

    final Set<String> canonicalHostNames =
         StaticUtils.getAvailableCanonicalHostNames(nameResolver,
              localAddresses);


    // Construct a subject DN for the certificate.
    final DN subjectDN;
    if (localAddresses.isEmpty())
    {
      subjectDN = new DN(new RDN("CN", toolName));
    }
    else
    {
      subjectDN = new DN(
           new RDN("CN",
                nameResolver.getCanonicalHostName(
                     localAddresses.iterator().next())),
           new RDN("OU", toolName));
    }


    // Generate a timestamp that corresponds to one day ago.
    final long oneDayAgoTime = System.currentTimeMillis() - 86_400_000L;
    final Date oneDayAgoDate = new Date(oneDayAgoTime);
    final SimpleDateFormat dateFormatter =
         new SimpleDateFormat("yyyyMMddHHmmss");
    final String yesterdayTimeStamp = dateFormatter.format(oneDayAgoDate);


    // Build the list of arguments to provide to the manage-certificates tool.
    final ArrayList<String> argList = new ArrayList<>(30);
    argList.add("generate-self-signed-certificate");

    argList.add("--keystore");
    argList.add(keyStoreFile.getAbsolutePath());

    argList.add("--keystore-password");
    argList.add(keyStorePIN);

    argList.add("--keystore-type");
    argList.add(keyStoreType);

    argList.add("--alias");
    argList.add(alias);

    argList.add("--subject-dn");
    argList.add(subjectDN.toString());

    argList.add("--days-valid");
    argList.add("366");

    argList.add("--validityStartTime");
    argList.add(yesterdayTimeStamp);

    argList.add("--key-algorithm");
    argList.add("RSA");

    argList.add("--key-size-bits");
    argList.add("2048");

    argList.add("--signature-algorithm");
    argList.add("SHA256withRSA");

    for (final String hostName : canonicalHostNames)
    {
      argList.add("--subject-alternative-name-dns");
      argList.add(hostName);
    }

    for (final InetAddress address : localAddresses)
    {
      argList.add("--subject-alternative-name-ip-address");
      argList.add(StaticUtils.trimInterfaceNameFromHostAddress(
           address.getHostAddress()));
    }

    argList.add("--key-usage");
    argList.add("digitalSignature");
    argList.add("--key-usage");
    argList.add("keyEncipherment");

    argList.add("--extended-key-usage");
    argList.add("server-auth");
    argList.add("--extended-key-usage");
    argList.add("client-auth");

    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    final ResultCode resultCode = ManageCertificates.main(null, output, output,
         argList.toArray(StaticUtils.NO_STRINGS));
    if (resultCode != ResultCode.SUCCESS)
    {
      throw new CertException(
           ERR_SELF_SIGNED_CERT_GENERATOR_ERROR_GENERATING_CERT.get(
                StaticUtils.toUTF8String(output.toByteArray())));
    }
  }
}
