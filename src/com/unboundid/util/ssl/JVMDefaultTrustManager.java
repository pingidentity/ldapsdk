/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.X509TrustManager;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.cert.AuthorityKeyIdentifierExtension;
import com.unboundid.util.ssl.cert.SubjectKeyIdentifierExtension;
import com.unboundid.util.ssl.cert.X509CertificateExtension;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an implementation of a trust manager that relies on the
 * JVM's default set of trusted issuers.
 * <BR><BR>
 * This implementation will first look for the trust store in the following
 * locations within the Java installation, in the following order:
 * <OL>
 *   <LI>{@code lib/security/jssecacerts}</LI>
 *   <LI>{@code jre/lib/security/jssecacerts}</LI>
 *   <LI>{@code lib/security/cacerts}</LI>
 *   <LI>{@code jre/lib/security/cacerts}</LI>
 * </OL>
 * If none of those files exist (or if they cannot be parsed as a JKS or PKCS
 * #12 key store), then we will search for a {@code jssecacerts} or
 * {@code cacerts} file below the Java home directory.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JVMDefaultTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A reference to the singleton instance of this class.
   */
  @NotNull private static final AtomicReference<JVMDefaultTrustManager>
       INSTANCE = new AtomicReference<>();



  /**
   * The name of the system property that specifies the path to the Java
   * installation for the currently-running JVM.
   */
  @NotNull private static final String PROPERTY_JAVA_HOME = "java.home";



  /**
   * A set of alternate file extensions that may be used by Java keystores.
   */
  @NotNull static final String[] FILE_EXTENSIONS  =
  {
    ".jks",
    ".p12",
    ".pkcs12",
    ".pfx",
  };



  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8587938729712485943L;



  // A certificate exception that should be thrown for any attempt to use this
  // trust store.
  @Nullable private final CertificateException certificateException;

  // The file from which they keystore was loaded.
  @Nullable private final File caCertsFile;

  // The keystore instance containing the JVM's default set of trusted issuers.
  @Nullable private final KeyStore keystore;

  // A map of the certificates in the keystore, indexed by signature.
  @NotNull private final Map<ASN1OctetString,X509Certificate>
       trustedCertsBySignature;

  // A map of the certificates in the keystore, indexed by key ID.
  @NotNull private final Map<ASN1OctetString,
       com.unboundid.util.ssl.cert.X509Certificate> trustedCertsByKeyID;



  /**
   * Creates an instance of this trust manager.
   *
   * @param  javaHomePropertyName  The name of the system property that should
   *                               specify the path to the Java installation.
   */
  JVMDefaultTrustManager(@NotNull final String javaHomePropertyName)
  {
    // Determine the path to the root of the Java installation.
    final String javaHomePath =
         StaticUtils.getSystemProperty(javaHomePropertyName);
    if (javaHomePath == null)
    {
      certificateException = new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_NO_JAVA_HOME.get(
                javaHomePropertyName));
      caCertsFile = null;
      keystore = null;
      trustedCertsBySignature = Collections.emptyMap();
      trustedCertsByKeyID = Collections.emptyMap();
      return;
    }

    final File javaHomeDirectory = new File(javaHomePath);
    if ((! javaHomeDirectory.exists()) || (! javaHomeDirectory.isDirectory()))
    {
      certificateException = new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_INVALID_JAVA_HOME.get(
                javaHomePropertyName, javaHomePath));
      caCertsFile = null;
      keystore = null;
      trustedCertsBySignature = Collections.emptyMap();
      trustedCertsByKeyID = Collections.emptyMap();
      return;
    }


    // Get a keystore instance that is loaded from the JVM's default set of
    // trusted issuers.
    final ObjectPair<KeyStore,File> keystorePair;
    try
    {
      keystorePair = getJVMDefaultKeyStore(javaHomeDirectory);
    }
    catch (final CertificateException ce)
    {
      Debug.debugException(ce);
      certificateException = ce;
      caCertsFile = null;
      keystore = null;
      trustedCertsBySignature = Collections.emptyMap();
      trustedCertsByKeyID = Collections.emptyMap();
      return;
    }

    keystore = keystorePair.getFirst();
    caCertsFile = keystorePair.getSecond();


    // Iterate through the certificates in the keystore and load them into a
    // map for faster and more reliable access.
    final LinkedHashMap<ASN1OctetString,X509Certificate> certsBySignature =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));
    final LinkedHashMap<ASN1OctetString,
         com.unboundid.util.ssl.cert.X509Certificate> certsByKeyID =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(50));
    try
    {
      final Enumeration<String> aliasEnumeration = keystore.aliases();
      while (aliasEnumeration.hasMoreElements())
      {
        final String alias = aliasEnumeration.nextElement();

        try
        {
          final X509Certificate certificate =
               (X509Certificate) keystore.getCertificate(alias);
          if (certificate != null)
          {
            certsBySignature.put(
                 new ASN1OctetString(certificate.getSignature()),
                 certificate);

            try
            {
              final com.unboundid.util.ssl.cert.X509Certificate c =
                   new com.unboundid.util.ssl.cert.X509Certificate(
                        certificate.getEncoded());
              for (final X509CertificateExtension e : c.getExtensions())
              {
                if (e instanceof SubjectKeyIdentifierExtension)
                {
                  final SubjectKeyIdentifierExtension skie =
                       (SubjectKeyIdentifierExtension) e;
                  certsByKeyID.put(
                       new ASN1OctetString(skie.getKeyIdentifier().getValue()),
                       c);
                }
              }
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
            }
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      certificateException = new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_ERROR_ITERATING_THROUGH_CACERTS.get(
                caCertsFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
      trustedCertsBySignature = Collections.emptyMap();
      trustedCertsByKeyID = Collections.emptyMap();
      return;
    }

    trustedCertsBySignature = Collections.unmodifiableMap(certsBySignature);
    trustedCertsByKeyID = Collections.unmodifiableMap(certsByKeyID);
    certificateException = null;
  }



  /**
   * Retrieves the singleton instance of this trust manager.
   *
   * @return  The singleton instance of this trust manager.
   */
  @NotNull()
  public static JVMDefaultTrustManager getInstance()
  {
    final JVMDefaultTrustManager existingInstance = INSTANCE.get();
    if (existingInstance != null)
    {
      return existingInstance;
    }

    final JVMDefaultTrustManager newInstance =
         new JVMDefaultTrustManager(PROPERTY_JAVA_HOME);
    if (INSTANCE.compareAndSet(null, newInstance))
    {
      return newInstance;
    }
    else
    {
      return INSTANCE.get();
    }
  }



  /**
   * Retrieves the keystore that backs this trust manager.
   *
   * @return  The keystore that backs this trust manager.
   *
   * @throws  CertificateException  If a problem was encountered while
   *                                initializing this trust manager.
   */
  @NotNull()
  KeyStore getKeyStore()
           throws CertificateException
  {
    if (certificateException != null)
    {
      throw certificateException;
    }

    return keystore;
  }



  /**
   * Retrieves the path to the the file containing the JVM's default set of
   * trusted issuers.
   *
   * @return  The path to the file containing the JVM's default set of
   *          trusted issuers.
   *
   * @throws  CertificateException  If a problem was encountered while
   *                                initializing this trust manager.
   */
  @NotNull()
  public File getCACertsFile()
         throws CertificateException
  {
    if (certificateException != null)
    {
      throw certificateException;
    }

    return caCertsFile;
  }



  /**
   * Retrieves the certificates included in this trust manager.
   *
   * @return  The certificates included in this trust manager.
   *
   * @throws  CertificateException  If a problem was encountered while
   *                                initializing this trust manager.
   */
  @NotNull()
  public Collection<X509Certificate> getTrustedIssuerCertificates()
         throws CertificateException
  {
    if (certificateException != null)
    {
      throw certificateException;
    }

    return trustedCertsBySignature.values();
  }



  /**
   * Checks to determine whether the provided client certificate chain should be
   * trusted.
   *
   * @param  chain     The client certificate chain for which to make the
   *                   determination.
   * @param  authType  The authentication type based on the client certificate.
   *
   * @throws  CertificateException  If the provided client certificate chain
   *                                should not be trusted.
   */
  @Override()
  public void checkClientTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    checkTrusted(chain);
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.
   * @param  authType  The key exchange algorithm used.
   *
   * @throws  CertificateException  If the provided server certificate chain
   *                                should not be trusted.
   */
  @Override()
  public void checkServerTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    checkTrusted(chain);
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.
   *
   * @return  The accepted issuer certificates for this trust manager, or an
   *          empty set of accepted issuers if a problem was encountered while
   *          initializing this trust manager.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getAcceptedIssuers()
  {
    if (certificateException != null)
    {
      return NO_CERTIFICATES;
    }

    final X509Certificate[] acceptedIssuers =
         new X509Certificate[trustedCertsBySignature.size()];
    return trustedCertsBySignature.values().toArray(acceptedIssuers);
  }



  /**
   * Retrieves a {@code KeyStore} that contains the JVM's default set of trusted
   * issuers.
   *
   * @param  javaHomeDirectory  The path to the JVM installation home directory.
   *
   * @return  An {@code ObjectPair} that includes the keystore and the file from
   *          which it was loaded.
   *
   * @throws  CertificateException  If the keystore could not be found or
   *                                loaded.
   */
  @NotNull()
  private static ObjectPair<KeyStore,File> getJVMDefaultKeyStore(
                      @NotNull final File javaHomeDirectory)
          throws CertificateException
  {
    final File libSecurityJSSECACerts = StaticUtils.constructPath(
         javaHomeDirectory, "lib", "security", "jssecacerts");
    final File jreLibSecurityJSSECACerts = StaticUtils.constructPath(
         javaHomeDirectory, "jre", "lib", "security", "jssecacerts");
    final File libSecurityCACerts = StaticUtils.constructPath(javaHomeDirectory,
         "lib", "security", "cacerts");
    final File jreLibSecurityCACerts = StaticUtils.constructPath(
         javaHomeDirectory, "jre", "lib", "security", "cacerts");

    final ArrayList<File> tryFirstFiles =
         new ArrayList<>(4 * FILE_EXTENSIONS.length + 2);
    tryFirstFiles.add(libSecurityCACerts);
    tryFirstFiles.add(jreLibSecurityCACerts);

    for (final String extension : FILE_EXTENSIONS)
    {
      tryFirstFiles.add(
           new File(libSecurityJSSECACerts.getAbsolutePath() + extension));
      tryFirstFiles.add(
           new File(jreLibSecurityJSSECACerts.getAbsolutePath() + extension));
      tryFirstFiles.add(
           new File(libSecurityCACerts.getAbsolutePath() + extension));
      tryFirstFiles.add(
           new File(jreLibSecurityCACerts.getAbsolutePath() + extension));
    }

    for (final File f : tryFirstFiles)
    {
      final KeyStore keyStore = loadKeyStore(f);
      if (keyStore != null)
      {
        return new ObjectPair<>(keyStore, f);
      }
    }


    // If we didn't find it with known paths, then try to find it with a
    // recursive filesystem search below the Java home directory.
    final LinkedHashMap<File,CertificateException> exceptions =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    final ObjectPair<KeyStore,File> keystorePair =
         searchForKeyStore(javaHomeDirectory, exceptions);
    if (keystorePair != null)
    {
      return keystorePair;
    }


    // If we've gotten here, then we couldn't find the keystore.  Construct a
    // message from the set of exceptions.
    if (exceptions.isEmpty())
    {
      throw new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_CACERTS_NOT_FOUND_NO_EXCEPTION.get());
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      buffer.append(
           ERR_JVM_DEFAULT_TRUST_MANAGER_CACERTS_NOT_FOUND_WITH_EXCEPTION.
                get());
      for (final Map.Entry<File,CertificateException> e : exceptions.entrySet())
      {
        if (buffer.charAt(buffer.length() - 1) != '.')
        {
          buffer.append('.');
        }

        buffer.append("  ");
        buffer.append(ERR_JVM_DEFAULT_TRUST_MANAGER_LOAD_ERROR.get(
             e.getKey().getAbsolutePath(),
             StaticUtils.getExceptionMessage(e.getValue())));
      }

      throw new CertificateException(buffer.toString());
    }
  }



  /**
   * Recursively searches for a valid keystore file below the specified portion
   * of the filesystem.  Any file named "cacerts", ignoring differences in
   * capitalization, and optionally ending with a number of different file
   * extensions, will be examined to see if it can be parsed as a Java keystore.
   * The first keystore that we find meeting that criteria will be returned.
   *
   * @param  directory   The directory in which to search.  It must not be
   *                     {@code null}.
   * @param  exceptions  A map that correlates file paths with exceptions
   *                     obtained while interacting with them.  If an exception
   *                     is encountered while interacting with this file, then
   *                     it will be added to this map.
   *
   * @return  The first valid keystore found that meets all the necessary
   *          criteria, or {@code null} if no such keystore could be found.
   */
  @Nullable()
  private static ObjectPair<KeyStore,File> searchForKeyStore(
                      @NotNull final File directory,
                      @NotNull final Map<File,CertificateException> exceptions)
  {
filesInDirectoryLoop:
    for (final File f : directory.listFiles())
    {
      if (f.isDirectory())
      {
        final ObjectPair<KeyStore,File> p = searchForKeyStore(f, exceptions);
        if (p != null)
        {
          return p;
        }
      }
      else
      {
        final String lowerName = StaticUtils.toLowerCase(f.getName());
        if (lowerName.equals("jssecacerts") || lowerName.equals("cacerts"))
        {
          try
          {
            final KeyStore keystore = loadKeyStore(f);
            return new ObjectPair<>(keystore, f);
          }
          catch (final CertificateException ce)
          {
            Debug.debugException(ce);
            exceptions.put(f, ce);
          }
        }
        else
        {
          for (final String extension : FILE_EXTENSIONS)
          {
            if (lowerName.equals("jssecacerts" + extension) ||
                 lowerName.equals("cacerts" + extension))
            {
              try
              {
                final KeyStore keystore = loadKeyStore(f);
                return new ObjectPair<>(keystore, f);
              }
              catch (final CertificateException ce)
              {
                Debug.debugException(ce);
                exceptions.put(f, ce);
                continue filesInDirectoryLoop;
              }
            }
          }
        }
      }
    }

    return null;
  }



  /**
   * Attempts to load the contents of the specified file as a Java keystore.
   *
   * @param  f  The file from which to load the keystore data.
   *
   * @return  The keystore that was loaded from the specified file.
   *
   * @throws  CertificateException  If a problem occurs while trying to load the
   *
   */
  @Nullable()
  private static KeyStore loadKeyStore(@NotNull final File f)
          throws CertificateException
  {
    if ((! f.exists()) || (! f.isFile()))
    {
      return null;
    }

    CertificateException firstGetInstanceException = null;
    CertificateException firstLoadException = null;
    for (final String keyStoreType : new String[] { "JKS", "PKCS12" })
    {
      final KeyStore keyStore;
      try
      {
        keyStore = CryptoHelper.getKeyStore(keyStoreType, null, true);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        if (firstGetInstanceException == null)
        {
          firstGetInstanceException = new CertificateException(
               ERR_JVM_DEFAULT_TRUST_MANAGER_CANNOT_INSTANTIATE_KEYSTORE.get(
                    keyStoreType, StaticUtils.getExceptionMessage(e)),
               e);
        }
        continue;
      }

      try (FileInputStream inputStream = new FileInputStream(f))
      {
        keyStore.load(inputStream, null);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        if (firstLoadException == null)
        {
          firstLoadException = new CertificateException(
               ERR_JVM_DEFAULT_TRUST_MANAGER_CANNOT_ERROR_LOADING_KEYSTORE.get(
                    f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
               e);
        }
        continue;
      }

      return keyStore;
    }

    if (firstLoadException != null)
    {
      throw firstLoadException;
    }

    throw firstGetInstanceException;
  }



  /**
   * Ensures that the provided certificate chain should be considered trusted.
   *
   * @param  chain  The certificate chain to validate.  It must not be
   *                {@code null}).
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be considered trusted.
   */
  void checkTrusted(@NotNull final X509Certificate[] chain)
       throws CertificateException
  {
    if (certificateException != null)
    {
      throw certificateException;
    }

    if ((chain == null) || (chain.length == 0))
    {
      throw new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_NO_CERTS_IN_CHAIN.get());
    }


    // It is possible that the chain could rely on cross-signed certificates,
    // and that we need to use a different path than the one presented in the
    // provided chain.  This requires us to potentially compute signatures using
    // each certificate in the JVM's default trust store, which can be
    // expensive.  To avoid that, we'll first only try it if the presented
    // chain has any certificates that are outside of their current validity
    // window.  If we get back a chain that is different from the one provided
    // to this method, then we shouldn't need to do any further validation.
    final X509Certificate[] chainToValidate = getChainToValidate(chain, true);
    if (! Arrays.equals(chainToValidate, chain))
    {
      return;
    }


    boolean foundIssuer = false;
    final Date currentTime = new Date();
    for (final X509Certificate cert : chainToValidate)
    {
      final ASN1OctetString signature =
           new ASN1OctetString(cert.getSignature());
      foundIssuer = (trustedCertsBySignature.get(signature) != null);
      if (foundIssuer)
      {
        break;
      }
    }

    if (! foundIssuer)
    {
      // It's possible that the server sent an incomplete chain.  Handle that
      // possibility.
      foundIssuer = checkIncompleteChain(chain);
    }

    if (! foundIssuer)
    {
      // We couldn't validate the presented chain, so see if we can find an
      // alternative chain using a cross-signed certificate.  In this case,
      // we'll perform the expensive check regardless of the validity dates in
      // the presented chain.  If the attempt to find an alternative chain
      // fails, then the getChainToValidate method will throw an exception.
      // However, if the alternative chain contains only a single certificate,
      // then that suggests the certificate is self-signed and not signed by
      // any trusted issuer.
      final X509Certificate[] alternativeChain =
           getChainToValidate(chain, false);
      if (Arrays.equals(alternativeChain, chain))
      {
        throw new CertificateException(
             ERR_JVM_DEFAULT_TRUST_MANGER_NO_TRUSTED_ISSUER_FOUND.get(
                  chainToString(chain)));
      }
    }
  }



  /**
   * Retrieves a list containing the certificates in the chain that should
   * actually be validated.  All certificates in the chain will have been
   * confirmed to be in their validity window.
   *
   * @param  chain                     The chain for which to obtain the path to
   *                                   validate.  It must not be {@code null} or
   *                                   empty.
   * @param  checkChainValidityWindow  Indicates whether to examine the validity
   *                                   of certificates in the presented chain
   *                                   when determining whether to examine
   *                                   certificates by signature.  If this is
   *                                   {@code true}, then the provided chain
   *                                   will be returned as long as all of the
   *                                   certificates in it are within their
   *                                   validity window.  If this is
   *                                   {@code false}, then an attempt to find a
   *                                   chain based on signatures will be used
   *                                   even if all of the certificates in the
   *                                   presented chain are considered valid.
   *
   * @return  The chain to be validated.  It may be the same as the provided
   *          chain, or an alternate chain if any certificate in the provided
   *          chain was outside of its validity window but an alternative trust
   *          path could be found.
   *
   * @throws  CertificateException  If the presented certificate chain included
   *                                a certificate that is outside of its
   *                                current validity window and no alternate
   *                                path could be found.
   */
  @NotNull()
  private X509Certificate[] getChainToValidate(
                                 @NotNull final X509Certificate[] chain,
                                 final boolean checkChainValidityWindow)
          throws CertificateException
  {
    final Date currentDate = new Date();

    // Check to see if any certificate in the provided chain is outside the
    // current validity window.  If not, then just use the provided chain.
    CertificateException firstException = null;
    if (checkChainValidityWindow)
    {
      for (int i=0; i < chain.length; i++)
      {
        final X509Certificate cert = chain[i];

        final Date notBefore = cert.getNotBefore();
        if (currentDate.before(notBefore))
        {
          if (firstException == null)
          {
            firstException = new CertificateNotYetValidException(
                 ERR_JVM_DEFAULT_TRUST_MANAGER_CERT_NOT_YET_VALID.get(
                      chainToString(chain), String.valueOf(cert.getSubjectDN()),
                      String.valueOf(notBefore)));
          }

          if (i == 0)
          {
            // If the peer certificate is not yet valid, then the entire chain
            // must be considered invalid.
            throw firstException;
          }
          else
          {
            break;
          }
        }

        final Date notAfter = cert.getNotAfter();
        if (currentDate.after(notAfter))
        {
          if (firstException == null)
          {
            firstException = new CertificateExpiredException(
                 ERR_JVM_DEFAULT_TRUST_MANAGER_CERT_EXPIRED.get(
                      chainToString(chain),
                      String.valueOf(cert.getSubjectDN()),
                      String.valueOf(notAfter)));
          }

          if (i == 0)
          {
            // If the peer certificate is expired, then the entire chain must be
            // considered invalid.
            throw firstException;
          }
          else
          {
            break;
          }
        }
      }


      // If all the certificates in the chain were within their validity window,
      // then just use the provided chain.
      if (firstException == null)
      {
        return chain;
      }
    }


    // If we've gotten here, then we should try to find an alternative chain.
    boolean foundAlternative = false;
    final List<X509Certificate> alternativeChain = new ArrayList<>();
chainLoop:
    for (final X509Certificate c : chain)
    {
      alternativeChain.add(c);
      try
      {
        final X509Certificate issuer = findIssuer(c, currentDate);
        if (issuer == null)
        {
          break;
        }
        else
        {
          foundAlternative = true;
          alternativeChain.add(issuer);

          X509Certificate prevIssuer = issuer;
          while (true)
          {
            try
            {
              final X509Certificate nextIssuer =
                   findIssuer(prevIssuer, currentDate);
              if (nextIssuer == null)
              {
                break chainLoop;
              }
              else
              {
                alternativeChain.add(nextIssuer);
                prevIssuer = nextIssuer;
              }
            }
            catch (final CertificateException e)
            {
              foundAlternative = false;
              break chainLoop;
            }
          }
        }
      }
      catch (final CertificateException e)
      {
        Debug.debugException(e);
      }
    }

    if (foundAlternative)
    {
      return alternativeChain.toArray(NO_CERTIFICATES);
    }
    else
    {
      if (firstException == null)
      {
        throw new CertificateException(
             ERR_JVM_DEFAULT_TRUST_MANGER_NO_TRUSTED_ISSUER_FOUND.get(
                  chainToString(chain)));
      }
      else
      {
        throw firstException;
      }
    }
  }



  /**
   * Finds the issuer for the provided certificate, if it is in the JVM-default
   * trust store.
   *
   * @param  cert         The certificate for which to find the issuer.  It must
   *                      have already been retrieved from the JVM-default trust
   *                      store.
   * @param  currentDate  The current date to use when verifying validity.
   *
   * @return  The issuer for the provided certificate, or {@code null} if the
   *          provided certificate is self-signed.
   *
   * @throws  CertificateException  If the provided certificate is not
   *                                self-signed but its issuer could not be
   *                                found, or if the issuer certificate is
   *                                not currently valid.
   */
  @Nullable()
  private X509Certificate findIssuer(@NotNull final X509Certificate cert,
                                     @NotNull final Date currentDate)
          throws CertificateException
  {
    try
    {
      // More fully decode the provided certificate so that we can better
      // examine it.
      final com.unboundid.util.ssl.cert.X509Certificate c =
           new com.unboundid.util.ssl.cert.X509Certificate(
                cert.getEncoded());

      // If the certificate is self-signed, then it doesn't have an issuer.
      if (c.isSelfSigned())
      {
        return null;
      }

      // See if the certificate has an authority key identifier extension.  If
      // so, then use it to try to find the issuer.
      for (final X509CertificateExtension e : c.getExtensions())
      {
        if (e instanceof AuthorityKeyIdentifierExtension)
        {
          final AuthorityKeyIdentifierExtension akie =
               (AuthorityKeyIdentifierExtension) e;
          final ASN1OctetString authorityKeyID =
               new ASN1OctetString(akie.getKeyIdentifier().getValue());
          final com.unboundid.util.ssl.cert.X509Certificate issuer =
               trustedCertsByKeyID.get(authorityKeyID);
          if ((issuer != null) && issuer.isWithinValidityWindow(currentDate))
          {
            c.verifySignature(issuer);
            return (X509Certificate) issuer.toCertificate();
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    throw new CertificateException(
         ERR_JVM_DEFAULT_TRUST_MANAGER_CANNOT_FIND_ISSUER.get(
              String.valueOf(cert.getSubjectDN())));
  }



  /**
   * Checks to determine whether the provided certificate chain may be
   * incomplete, and if so, whether we can find and trust the issuer of the last
   * certificate in the chain.
   *
   * @param  chain  The chain to validate.
   *
   * @return  {@code true} if the chain could be validated, or {@code false} if
   *          not.
   */
  private boolean checkIncompleteChain(@NotNull final X509Certificate[] chain)
  {
    try
    {
      // Get the last certificate in the chain and decode it as one that we can
      // more fully inspect.
      final com.unboundid.util.ssl.cert.X509Certificate c =
           new com.unboundid.util.ssl.cert.X509Certificate(
                chain[chain.length - 1].getEncoded());

      // If the certificate is self-signed, then it can't be trusted.
      if (c.isSelfSigned())
      {
        return false;
      }

      // See if the certificate has an authority key identifier extension.  If
      // so, then use it to try to find the issuer.
      for (final X509CertificateExtension e : c.getExtensions())
      {
        if (e instanceof AuthorityKeyIdentifierExtension)
        {
          final AuthorityKeyIdentifierExtension akie =
               (AuthorityKeyIdentifierExtension) e;
          final ASN1OctetString authorityKeyID =
               new ASN1OctetString(akie.getKeyIdentifier().getValue());
          final com.unboundid.util.ssl.cert.X509Certificate issuer =
               trustedCertsByKeyID.get(authorityKeyID);
          if ((issuer != null) && issuer.isWithinValidityWindow())
          {
            c.verifySignature(issuer);
            return true;
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return false;
  }



  /**
   * Constructs a string representation of the certificates in the provided
   * chain.  It will consist of a comma-delimited list of their subject DNs,
   * with each subject DN surrounded by single quotes.
   *
   * @param  chain  The chain for which to obtain the string representation.
   *
   * @return  A string representation of the provided certificate chain.
   */
  @NotNull()
  static String chainToString(@NotNull final X509Certificate[] chain)
  {
    final StringBuilder buffer = new StringBuilder();

    switch (chain.length)
    {
      case 0:
        break;
      case 1:
        buffer.append('\'');
        buffer.append(chain[0].getSubjectDN());
        buffer.append('\'');
        break;
      case 2:
        buffer.append('\'');
        buffer.append(chain[0].getSubjectDN());
        buffer.append("' and '");
        buffer.append(chain[1].getSubjectDN());
        buffer.append('\'');
        break;
      default:
        for (int i=0; i < chain.length; i++)
        {
          if (i > 0)
          {
            buffer.append(", ");
          }

          if (i == (chain.length - 1))
          {
            buffer.append("and ");
          }

          buffer.append('\'');
          buffer.append(chain[i].getSubjectDN());
          buffer.append('\'');
        }
    }

    return buffer.toString();
  }
}
