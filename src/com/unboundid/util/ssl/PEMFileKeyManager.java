/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import javax.net.ssl.X509KeyManager;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.PKCS8PEMFileReader;
import com.unboundid.util.ssl.cert.PKCS8PrivateKey;
import com.unboundid.util.ssl.cert.X509PEMFileReader;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an implementation of an X.509 key manager that can obtain
 * a certificate chain and private key from PEM files.  This key manager will
 * only support a single entry, and the alias for that entry will be a SHA-256
 * fingerprint for the certificate.  However, the certificate can be retrieved
 * with any (or no) alias.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PEMFileKeyManager
       implements X509KeyManager, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final   long serialVersionUID = 1973401278035832777L;



  /**
   * The name of the digest algorithm that will be used to generate a
   * certificate fingerprint for use as the alias.
   */
  @NotNull private static final String ALIAS_FINGERPRINT_ALGORITHM = "SHA-256";



  // The certificate chain read from PEM files.
  @NotNull private final X509Certificate[] certificateChain;

  // The private key read from a PEM file.
  @NotNull private final PrivateKey privateKey;

  // The alias that will be used for the certificate chain.
  @NotNull private final String alias;



  /**
   * Creates a new instance of this key manager with the provided PEM files.
   *
   * @param  certificateChainPEMFile  The file containing the PEM-formatted
   *                                  X.509 representations of the certificates
   *                                  in the certificate chain.  This must not
   *                                  be {@code null}, the file must exist, and
   *                                  it must contain at least one certificate
   *                                  (the end entity certificate), but may
   *                                  contain additional certificates as needed
   *                                  for the complete certificate chain.
   *                                  Certificates should be ordered such that
   *                                  the first certificate must be the end
   *                                  entity certificate, and each subsequent
   *                                  certificate must be the issuer for the
   *                                  previous certificate.  The chain does not
   *                                  need to be complete as long as the peer
   *                                  may be expected to have prior knowledge of
   *                                  any missing issuer certificates.
   * @param  privateKeyPEMFile        The file containing the PEM-formatted
   *                                  PKCS #8 representation of the private key
   *                                  for the end entity certificate.  This must
   *                                  not be {@code null}, the file must exist,
   *                                  and it must contain exactly one
   *                                  PEM-encoded private key.
   *
   * @throws  KeyStoreException  If there is a problem with any of the provided
   *                             PEM files.
   */
  public PEMFileKeyManager(@NotNull final File certificateChainPEMFile,
                           @NotNull final File privateKeyPEMFile)
         throws KeyStoreException
  {
    this(Collections.singletonList(certificateChainPEMFile), privateKeyPEMFile);
  }



  /**
   * Creates a new instance of this key manager with the provided PEM files.
   *
   * @param  certificateChainPEMFiles  The files containing the PEM-formatted
   *                                   X.509 representations of the certificates
   *                                   in the certificate chain.  This must not
   *                                   be {@code null} or empty.  Each file must
   *                                   exist and must contain at least one
   *                                   certificate.  The files will be processed
   *                                   in the order in which they are provided.
   *                                   The first certificate in the first file
   *                                   must be the end entity certificate, and
   *                                   each subsequent certificate must be the
   *                                   issuer for the previous certificate.  The
   *                                   chain does not need to be complete as
   *                                   long as the peer may be expected to have
   *                                   prior knowledge of any missing issuer
   *                                   certificates.
   * @param  privateKeyPEMFile         The file containing the PEM-formatted
   *                                   PKCS #8 representation of the private key
   *                                   for the end entity certificate.  This
   *                                   must not be {@code null}, the file must
   *                                   exist, and it must contain exactly one
   *                                   PEM-encoded private key.
   *
   * @throws  KeyStoreException  If there is a problem with any of the provided
   *                             PEM files.
   */
  public PEMFileKeyManager(@NotNull final File[] certificateChainPEMFiles,
                           @NotNull final File privateKeyPEMFile)
         throws KeyStoreException
  {
    this(StaticUtils.toList(certificateChainPEMFiles), privateKeyPEMFile);
  }



  /**
   * Creates a new instance of this key manager with the provided PEM files.
   *
   * @param  certificateChainPEMFiles  The files containing the PEM-formatted
   *                                   X.509 representations of the certificates
   *                                   in the certificate chain.  This must not
   *                                   be {@code null} or empty.  Each file must
   *                                   exist and must contain at least one
   *                                   certificate.  The files will be processed
   *                                   in the order in which they are provided.
   *                                   The first certificate in the first file
   *                                   must be the end entity certificate, and
   *                                   each subsequent certificate must be the
   *                                   issuer for the previous certificate.  The
   *                                   chain does not need to be complete as
   *                                   long as the peer may be expected to have
   *                                   prior knowledge of any missing issuer
   *                                   certificates.
   * @param  privateKeyPEMFile         The file containing the PEM-formatted
   *                                   PKCS #8 representation of the private key
   *                                   for the end entity certificate.  This
   *                                   must not be {@code null}, the file must
   *                                   exist, and it must contain exactly one
   *                                   PEM-encoded private key.
   *
   * @throws  KeyStoreException  If there is a problem with any of the provided
   *                             PEM files.
   */
  public PEMFileKeyManager(@NotNull final List<File> certificateChainPEMFiles,
                           @NotNull final File privateKeyPEMFile)
         throws KeyStoreException
  {
    Validator.ensureNotNullWithMessage(certificateChainPEMFiles,
         "PEMFileKeyManager.certificateChainPEMFiles must not be null.");
    Validator.ensureFalse(certificateChainPEMFiles.isEmpty(),
         "PEMFileKeyManager.certificateChainPEMFiles must not be empty.");
    Validator.ensureNotNullWithMessage(privateKeyPEMFile,
         "PEMFileKeyManager.privateKeyPEMFile must not be null.");

    certificateChain = readCertificateChain(certificateChainPEMFiles);
    privateKey = readPrivateKey(privateKeyPEMFile);


    // Compute a SHA-256 fingerprint for the certificate to use as the alias.
    try
    {
      final MessageDigest sha256 =
           CryptoHelper.getMessageDigest(ALIAS_FINGERPRINT_ALGORITHM);
      final byte[] digestBytes =
           sha256.digest(certificateChain[0].getEncoded());
      alias = StaticUtils.toHex(digestBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_KEY_MANAGER_CANNOT_COMPUTE_ALIAS.get(
                ALIAS_FINGERPRINT_ALGORITHM,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads the certificate chain from the provided PEM files.
   *
   * @param  certificateChainPEMFiles  The files containing the PEM-formatted
   *                                   X.509 representations of the certificates
   *                                   in the certificate chain.  This must not
   *                                   be {@code null} or empty.  Each file must
   *                                   exist and must contain at least one
   *                                   certificate.  The files will be processed
   *                                   in the order in which they are provided.
   *                                   The first certificate in the first file
   *                                   must be the end entity certificate, and
   *                                   each subsequent certificate must be the
   *                                   issuer for the previous certificate.  The
   *                                   chain does not need to be complete as
   *                                   long as the peer may be expected to have
   *                                   prior knowledge of any missing issuer
   *                                   certificates.
   *
   * @return  The certificate chain that was read.
   *
   * @throws  KeyStoreException  If a problem is encountered while reading the
   *                             certificate chain.
   */
  @NotNull()
  private static X509Certificate[] readCertificateChain(
               @NotNull final List<File> certificateChainPEMFiles)
          throws KeyStoreException
  {
    com.unboundid.util.ssl.cert.X509Certificate lastCert = null;

    final List<X509Certificate> certList = new ArrayList<>();
    for (final File f : certificateChainPEMFiles)
    {
      if (! f.exists())
      {
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_NO_SUCH_CERT_FILE.get(
                  f.getAbsolutePath()));
      }

      boolean readCert = false;
      try (final X509PEMFileReader r = new X509PEMFileReader(f))
      {
        while  (true)
        {
          final com.unboundid.util.ssl.cert.X509Certificate c =
               r.readCertificate();
          if (c == null)
          {
            if (! readCert)
            {
              throw new KeyStoreException(
                   ERR_PEM_FILE_KEY_MANAGER_EMPTY_CERT_FILE.get(
                        f.getAbsolutePath()));
            }

            break;
          }

          readCert = true;
          if ((lastCert != null) && (! c.isIssuerFor(lastCert)))
          {
            throw new KeyStoreException(
                 ERR_PEM_FILE_KEY_MANAGER_SUBSEQUENT_CERT_NOT_ISSUER.get(
                      c.getSubjectDN().toString(), f.getAbsolutePath(),
                      lastCert.getSubjectDN().toString()));
          }

          try
          {
            certList.add((X509Certificate) c.toCertificate());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new KeyStoreException(
                 ERR_PEM_FILE_KEY_MANAGER_CANNOT_DECODE_CERT.get(
                      c.getSubjectDN().toString(), f.getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }

          lastCert = c;
        }
      }
      catch (final KeyStoreException e)
      {
        Debug.debugException(e);
        throw e;
      }
      catch (final IOException e)
      {
        Debug.debugException(e);
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_ERROR_READING_FROM_FILE.get(
                  f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
             e);
      }
      catch (final CertException e)
      {
        Debug.debugException(e);
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_ERROR_READING_CERT.get(
                  f.getAbsolutePath(), e.getMessage()),
             e);
      }
    }

    final X509Certificate[] chain = new X509Certificate[certList.size()];
    return certList.toArray(chain);
  }



  /**
   * Reads the private key from the provided PEM file.
   *
   *
   * @param  privateKeyPEMFile         The file containing the PEM-formatted
   *                                   PKCS #8 representation of the private key
   *                                   for the end entity certificate.  This
   *                                   must not be {@code null}, the file must
   *                                   exist, and it must contain exactly one
   *                                   PEM-encoded private key.
   *
   * @return  The private key that was read.
   *
   * @throws  KeyStoreException  If a problem is encountered while reading the
   *                             certificate chain.
   */
  @NotNull()
  private static PrivateKey readPrivateKey(
               @NotNull final File privateKeyPEMFile)
          throws KeyStoreException
  {
    if (! privateKeyPEMFile.exists())
    {
      throw new KeyStoreException(
           ERR_PEM_FILE_KEY_MANAGER_NO_SUCH_KEY_FILE.get(
                privateKeyPEMFile.getAbsolutePath()));
    }

    try (PKCS8PEMFileReader r = new PKCS8PEMFileReader(privateKeyPEMFile))
    {
      final PKCS8PrivateKey privateKey = r.readPrivateKey();
      if (privateKey == null)
      {
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_EMPTY_KEY_FILE.get(
                  privateKeyPEMFile.getAbsolutePath()));
      }

      if (r.readPrivateKey() != null)
      {
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_MULTIPLE_KEYS_IN_FILE.get(
                  privateKeyPEMFile.getAbsolutePath()));
      }

      try
      {
        return privateKey.toPrivateKey();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new KeyStoreException(
             ERR_PEM_FILE_KEY_MANAGER_CANNOT_DECODE_KEY.get(
                  privateKeyPEMFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    catch (final KeyStoreException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_KEY_MANAGER_ERROR_READING_FROM_FILE.get(
                privateKeyPEMFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_KEY_MANAGER_ERROR_READING_KEY.get(
                privateKeyPEMFile.getAbsolutePath(), e.getMessage()),
           e);
    }
  }



  /**
   * Retrieves the aliases that may be used for a client certificate chain with
   * the requested settings.
   *
   * @param  keyType  The key type for the alias to retrieve.  It may be
   *                  {@code null} if any key type may be used.
   * @param  issuers  The set of allowed issuers for the aliases to retrieve.
   *                  It may be {@code null} if any issuers should be allowed.
   *
   * @return  An array of the aliases that may be used for a client certificate
   *          chain with the requested settings, or {@code null} if the
   *          certificate chain does not match the requested criteria.
   */
  @Override()
  @Nullable()
  public String[] getClientAliases(@Nullable final String keyType,
                                   @Nullable final Principal[] issuers)
  {
    return getAliases(keyType, issuers);
  }



  /**
   * Retrieves the aliases that may be used for a server certificate chain with
   * the requested settings.
   *
   * @param  keyType  The key type for the alias to retrieve.  It may be
   *                  {@code null} if any key type may be used.
   * @param  issuers  The set of allowed issuers for the aliases to retrieve.
   *                  It may be {@code null} if any issuers should be allowed.
   *
   * @return  An array of the aliases that may be used for a server certificate
   *          chain with the requested settings, or {@code null} if the
   *          certificate chain does not match the requested criteria.
   */
  @Override()
  @Nullable()
  public String[] getServerAliases(@Nullable final String keyType,
                                   @Nullable final Principal[] issuers)
  {
    return getAliases(keyType, issuers);
  }



  /**
   * Retrieves the aliases that may be used for a certificate chain with the
   * requested settings.
   *
   * @param  keyType  The key type for the alias to retrieve.  It may be
   *                  {@code null} if any key type may be used.
   * @param  issuers  A list of acceptable CA issuer subject names.  It may be
   *                  {@code null} if any issuers may be used.
   *
   * @return  An array of the aliases that may be used for a certificate chain
   *          with the requested settings, or {@code null} if the certificate
   *          chain does not match the requested criteria.
   */
  @Nullable()
  private String[] getAliases(@Nullable final String keyType,
                              @Nullable final Principal[] issuers)
  {
    if (! hasKeyType(keyType))
    {
      Debug.debug(Level.WARNING, DebugType.OTHER,
           "PEMFileKeyManager.getAliases returning null because the " +
                "requested keyType is '" + keyType + "' but the private " +
                "key uses an algorithm of '" + privateKey.getAlgorithm() +
                "'.");
      return null;
    }

    if (! hasAnyIssuer(issuers))
    {
      Debug.debug(Level.WARNING, DebugType.OTHER,
           "PEMFileKeyManager.getAliases returning null because " +
                "certificate chain " + Arrays.toString(certificateChain) +
                " does not use any of the allowed issuers " +
                Arrays.toString(issuers));

      return null;
    }

    return new String[] { alias };
  }



  /**
   * Chooses the alias that should be used for the preferred client certificate
   * chain with the requested settings.
   *
   * @param  keyTypes  The set of allowed key types for the alias to retrieve.
   *                   It may be {@code null} if any key type may be used.
   * @param  issuers   The set of allowed issuers for the alias to retrieve.  It
   *                   may be {@code null} if any issuers should be allowed.
   * @param  socket    The socket with which the certificate chain will be used.
   *                   It may be {@code null} if no socket should be taken into
   *                   consideration.
   *
   * @return  The alias that should be used for the preferred client certificate
   *          chain with the requested settings, or {@code null} if there is no
   *          applicable alias.
   */
  @Override()
  @Nullable()
  public String chooseClientAlias(@Nullable final String[] keyTypes,
                                  @Nullable final Principal[] issuers,
                                  @Nullable final Socket socket)
  {
    return chooseAlias(keyTypes, issuers);
  }



  /**
   * Chooses the alias that should be used for the preferred server certificate
   * chain with the requested settings.
   *
   * @param  keyType  The key type for the alias to retrieve.  It may be
   *                  {@code null} if any key type may be u sed.
   * @param  issuers  The set of allowed issuers for the alias to retrieve.  It
   *                  may be {@code null} if any issuers should be allowed.
   * @param  socket   The socket with which the certificate chain will be used.
   *                  It may be {@code null} if no socket should be taken into
   *                  consideration.
   *
   * @return  The alias that should be used for the preferred server certificate
   *          chain with the requested settings, or {@code null} if there is no
   *          applicable alias.
   */
  @Override()
  @Nullable()
  public String chooseServerAlias(@Nullable final String keyType,
                                  @Nullable final Principal[] issuers,
                                  @Nullable final Socket socket)
  {
    if (keyType == null)
    {
      return chooseAlias(null, issuers);
    }
    else
    {
      return chooseAlias(new String[] { keyType }, issuers);
    }
  }



  /**
   * Chooses the alias that should be used for the preferred certificate chain
   * with the requested settings.
   *
   * @param  keyTypes  The set of allowed key types for the alias to retrieve.
   *                   It may be {@code null} if any key type may be used.
   * @param  issuers   The set of allowed issuers for the alias to retrieve.  It
   *                   may be {@code null} if any issuers should be allowed.
   *
   * @return  The alias that should be used for the preferred certificate chain
   *          with the requested settings, or {@code null} if there is no
   *          applicable alias.
   */
  @Nullable()
  public String chooseAlias(@Nullable final String[] keyTypes,
                            @Nullable final Principal[] issuers)
  {
    if ((keyTypes != null) && (keyTypes.length > 0))
    {
      boolean keyTypeFound = false;
      for (final String keyType : keyTypes)
      {
        if (hasKeyType(keyType))
        {
          keyTypeFound = true;
          break;
        }
      }

      if (! keyTypeFound)
      {
        Debug.debug(Level.WARNING, DebugType.OTHER,
             "PEMFileKeyManager.chooseAlias returning null because " +
                  "certificate chain " + Arrays.toString(certificateChain) +
                  " uses a key type of " + privateKey.getAlgorithm() +
                  ", which does not match any of the allowed key types of " +
                  Arrays.toString(keyTypes));

        return null;
      }
    }

    if (! hasAnyIssuer(issuers))
    {
      Debug.debug(Level.WARNING, DebugType.OTHER,
           "PEMFileKeyManager.chooseAlias returning null because " +
                "certificate chain " + Arrays.toString(certificateChain) +
                " does not use any of the allowed issuers " +
                Arrays.toString(issuers));

      return null;
    }

    return alias;
  }



  /**
   * Indicates whether the certificate chain has the specified key type.
   *
   * @param  keyType  The key type for which to make the determination.  It may
   *                  be {@code null} if the key type does not matter.
   *
   * @return  {@code true} if the certificate chain has the specified key type
   *          (or if the key type does not matter), or {@code false} if not.
   */
  private boolean hasKeyType(@Nullable final String keyType)
  {
    return ((keyType == null) ||
         privateKey.getAlgorithm().equalsIgnoreCase(keyType));
  }



  /**
   * Indicates whether the certificate chain has any of the issuers in the
   * provided array.
   *
   * @param  issuers  The array of acceptable issuers.  It may be
   *                  {@code null} if the set of issuers does not matter.
   *
   * @return  {@code true} if the certificate chain uses one of the accepted
   *          issuers (or if the issuers do not matter), or {@code false} if
   *          not.
   */
  private boolean hasAnyIssuer(@Nullable final Principal[] issuers)
  {
    if ((issuers == null) || (issuers.length == 0))
    {
      return true;
    }


    // Check all of the issuer certificates for the chain.
    for (final Principal acceptableIssuer : issuers)
    {
      final String acceptableIssuerString = acceptableIssuer.toString();
      for (final X509Certificate c : certificateChain)
      {
        final Principal certificateIssuer = c.getIssuerDN();
        final String certificateIssuerString = certificateIssuer.toString();
        try
        {
          if (DN.equals(certificateIssuerString, acceptableIssuerString))
          {
            return true;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }


    // Also check the subject DN for the first certificate in the chain.
    final Principal endEntitySubject = certificateChain[0].getSubjectDN();
    final String endEntitySubjectString = endEntitySubject.toString();
    for (final Principal acceptableIssuer : issuers)
    {
      final String acceptableIssuerString = acceptableIssuer.toString();
      try
      {
        if (DN.equals(endEntitySubjectString, acceptableIssuerString))
        {
          return true;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }


    return false;
  }



  /**
   * Retrieves the certificate chain with the specified alias.  Note that
   * because this key manager implementation can only use a single certificate
   * chain, it will always return the same chain for any alias, even if the
   * requested alias is {@code null}.
   *
   * @param  alias  The alias for the certificate chain to retrieve.
   *
   * @return  The certificate chain for this key manager.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getCertificateChain(@Nullable final String alias)
  {
    return Arrays.copyOf(certificateChain, certificateChain.length);
  }



  /**
   * Retrieves the private key for the certificate chain with the specified
   * alias.  Note that because this key manager implementation can only use a
   * single certificate chain, it will always return the same private key for
   * any alias, even if the requested alias is {@code null}.
   *
   * @param  alias  The alias for the private key to retrieve.
   *
   * @return  The private key for this key manager.
   */
  @Override()
  @NotNull()
  public PrivateKey getPrivateKey(@Nullable final String alias)
  {
    return privateKey;
  }
}
