/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.X509TrustManager;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an implementation of a trust manager that relies on the
 * JVM's default set of trusted issuers.  This is generally found in the
 * {@code jre/lib/security/cacerts} or {@code lib/security/cacerts} file in the
 * Java installation (in both Sun/Oracle and IBM-based JVMs), but if neither of
 * those files exist (or if they cannot be parsed as a JKS or PKCS#12 keystore),
 * then we will search for the file below the Java home directory.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JVMDefaultTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A reference to the singleton instance of this class.
   */
  private static final AtomicReference<JVMDefaultTrustManager> INSTANCE =
       new AtomicReference<>();



  /**
   * The name of the system property that specifies the path to the Java
   * installation for the currently-running JVM.
   */
  private static final String PROPERTY_JAVA_HOME = "java.home";



  /**
   * A set of alternate file extensions that may be used by Java keystores.
   */
  static final String[] FILE_EXTENSIONS  =
  {
    ".jks",
    ".p12",
    ".pkcs12",
    ".pfx",
  };



  /**
   * A pre-allocated empty certificate array.
   */
  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8587938729712485943L;



  // A certificate exception that should be thrown for any attempt to use this
  // trust store.
  private final CertificateException certificateException;

  // The file from which they keystore was loaded.
  private final File caCertsFile;

  // The keystore instance containing the JVM's default set of trusted issuers.
  private final KeyStore keystore;

  // A map of the certificates in the keystore, indexed by signature.
  private final Map<ASN1OctetString,X509Certificate> trustedCertificateMap;



  /**
   * Creates an instance of this trust manager.
   *
   * @param  javaHomePropertyName  The name of the system property that should
   *                               specify the path to the Java installation.
   */
  JVMDefaultTrustManager(final String javaHomePropertyName)
  {
    // Determine the path to the root of the Java installation.
    final String javaHomePath = System.getProperty(javaHomePropertyName);
    if (javaHomePath == null)
    {
      certificateException = new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANAGER_NO_JAVA_HOME.get(
                javaHomePropertyName));
      caCertsFile = null;
      keystore = null;
      trustedCertificateMap = Collections.emptyMap();
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
      trustedCertificateMap = Collections.emptyMap();
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
      trustedCertificateMap = Collections.emptyMap();
      return;
    }

    keystore = keystorePair.getFirst();
    caCertsFile = keystorePair.getSecond();


    // Iterate through the certificates in the keystore and load them into a
    // map for faster and more reliable access.
    final LinkedHashMap<ASN1OctetString,X509Certificate> certificateMap =
         new LinkedHashMap<>(50);
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
            certificateMap.put(new ASN1OctetString(certificate.getSignature()),
                 certificate);
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
      trustedCertificateMap = Collections.emptyMap();
      return;
    }

    trustedCertificateMap = Collections.unmodifiableMap(certificateMap);
    certificateException = null;
  }



  /**
   * Retrieves the singleton instance of this trust manager.
   *
   * @return  The singleton instance of this trust manager.
   */
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
  public Collection<X509Certificate> getTrustedIssuerCertificates()
         throws CertificateException
  {
    if (certificateException != null)
    {
      throw certificateException;
    }

    return trustedCertificateMap.values();
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
  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
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
  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
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
  public X509Certificate[] getAcceptedIssuers()
  {
    if (certificateException != null)
    {
      return NO_CERTIFICATES;
    }

    final X509Certificate[] acceptedIssuers =
         new X509Certificate[trustedCertificateMap.size()];
    return trustedCertificateMap.values().toArray(acceptedIssuers);
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
  private static ObjectPair<KeyStore,File> getJVMDefaultKeyStore(
                                                final File javaHomeDirectory)
          throws CertificateException
  {
    final File libSecurityCACerts = StaticUtils.constructPath(javaHomeDirectory,
         "lib", "security", "cacerts");
    final File jreLibSecurityCACerts = StaticUtils.constructPath(
         javaHomeDirectory, "jre", "lib", "security", "cacerts");

    final ArrayList<File> tryFirstFiles =
         new ArrayList<>(2 * FILE_EXTENSIONS.length + 2);
    tryFirstFiles.add(libSecurityCACerts);
    tryFirstFiles.add(jreLibSecurityCACerts);

    for (final String extension : FILE_EXTENSIONS)
    {
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
         new LinkedHashMap<>(1);
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
  private static ObjectPair<KeyStore,File> searchForKeyStore(
                      final File directory,
                      final Map<File,CertificateException> exceptions)
  {
filesInDirectoryLoop:
    for (final File f : directory.listFiles())
    {
      if (f.isDirectory())
      {
        final ObjectPair<KeyStore,File> p =searchForKeyStore(f, exceptions);
        if (p != null)
        {
          return p;
        }
      }
      else
      {
        final String lowerName = StaticUtils.toLowerCase(f.getName());
        if (lowerName.equals("cacerts"))
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
            if (lowerName.equals("cacerts" + extension))
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
  private static KeyStore loadKeyStore(final File f)
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
        keyStore = KeyStore.getInstance(keyStoreType);
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
  void checkTrusted(final X509Certificate[] chain)
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

    boolean foundIssuer = false;
    final Date currentTime = new Date();
    for (final X509Certificate cert : chain)
    {
      // Make sure that the certificate is currently within its validity window.
      final Date notBefore = cert.getNotBefore();
      if (currentTime.before(notBefore))
      {
        throw new CertificateNotYetValidException(
             ERR_JVM_DEFAULT_TRUST_MANAGER_CERT_NOT_YET_VALID.get(
                  chainToString(chain), String.valueOf(cert.getSubjectDN()),
                  String.valueOf(notBefore)));
      }

      final Date notAfter = cert.getNotAfter();
      if (currentTime.after(notAfter))
      {
        throw new CertificateExpiredException(
             ERR_JVM_DEFAULT_TRUST_MANAGER_CERT_EXPIRED.get(
                  chainToString(chain),
                  String.valueOf(cert.getSubjectDN()),
                  String.valueOf(notAfter)));
      }

      final ASN1OctetString signature =
           new ASN1OctetString(cert.getSignature());
      foundIssuer |= (trustedCertificateMap.get(signature) != null);
    }

    if (! foundIssuer)
    {
      throw new CertificateException(
           ERR_JVM_DEFAULT_TRUST_MANGER_NO_TRUSTED_ISSUER_FOUND.get(
                chainToString(chain)));
    }
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
  static String chainToString(final X509Certificate[] chain)
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
