/*
 * Copyright 2021-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2023 Ping Identity Corporation
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
 * Copyright (C) 2021-2023 Ping Identity Corporation
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



import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.PasswordFileReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.PKCS8PEMFileReader;
import com.unboundid.util.ssl.cert.PKCS8PrivateKey;
import com.unboundid.util.ssl.cert.X509Certificate;
import com.unboundid.util.ssl.cert.X509PEMFileReader;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a {@link ReplaceCertificateKeyStoreContent}
 * implementation to indicate that the certificate chain and private key (in
 * either PEM or DER format) are provided directly in the extended request.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CertificateDataReplaceCertificateKeyStoreContent
       extends ReplaceCertificateKeyStoreContent
{
  /**
   * The BER type to use for the ASN.1 element containing an encoded
   * representation of this key store content object.
   */
  static final byte TYPE_KEY_STORE_CONTENT = (byte) 0xA2;



  /**
   * The BER type to use for the ASN.1 element that provides the new
   * certificate chain.
   */
  private static final byte TYPE_CERTIFICATE_CHAIN = (byte) 0xAE;



  /**
   * The BER type to use for the ASN.1 element that provides the private key for
   * the new certificate.
   */
  private static final byte TYPE_PRIVATE_KEY = (byte) 0xAF;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1771837307666073616L;



  // An encoded representation of the PKCS #8 private key.
  @Nullable private final byte[] privateKeyData;

  // An encoded representation of the X.509 certificates in the certificate
  // chain.
  @NotNull private final List<byte[]> certificateChainData;



  /**
   * Creates a new instance of this key store content object with the provided
   * information.
   *
   * @param  certificateChainData  A list containing the encoded representations
   *                               of the X.509 certificates in the new
   *                               certificate chain.  Each byte array must
   *                               contain the PEM or DER representation of a
   *                               single certificate in the chain, with the
   *                               first certificate being the end-entity
   *                               certificate, and each subsequent certificate
   *                               being the issuer for the previous
   *                               certificate.  This must not be {@code null}
   *                               or empty.
   * @param  privateKeyData        An array containing the encoded
   *                               representation of the PKCS #8 private key
   *                               for the end-entity certificate in the chain.
   *                               It may be encoded in either PEM or DER
   *                               format.  This may be {@code null} if the
   *                               new end-entity certificate uses the same
   *                               private key as the certificate currently in
   *                               use in the server.
   */
  public CertificateDataReplaceCertificateKeyStoreContent(
              @NotNull final List<byte[]> certificateChainData,
              @Nullable final byte[] privateKeyData)
  {
    Validator.ensureNotNullOrEmpty(certificateChainData,
         "CertificateDataReplaceCertificateKeyStoreContent." +
              "certificateChainData must not be null or empty.");

    this.certificateChainData = Collections.unmodifiableList(
         new ArrayList<>(certificateChainData));
    this.privateKeyData = privateKeyData;
  }



  /**
   * Creates a new instance of this key store content object with the provided
   * information.
   *
   * @param  certificateChainFiles  A list containing one or more files from
   *                                which to read the PEM or DER representations
   *                                of the X.509 certificates to include in
   *                                the new certificate chain.  The order of
   *                                the files, and the order of the certificates
   *                                in each file, should be arranged such that
   *                                the first certificate read is the end-entity
   *                                certificate and each subsequent certificate
   *                                is the issuer for the previous.  This must
   *                                not be {@code null} or empty.
   * @param  privateKeyFile         A file from which to read the PEM or DER
   *                                representation of the PKCS #8 private key
   *                                for the end-entity certificate in the chain.
   *                                This may be {@code null} if the new
   *                                end-entity certificate uses the same private
   *                                key as the certificate currently in use in
   *                                the server.  The private key must not be
   *                                encrypted.
   *
   * @throws  LDAPException  If a problem occurs while trying to read or parse
   *                         data contained in any of the provided files.
   */
  public CertificateDataReplaceCertificateKeyStoreContent(
              @NotNull final List<File> certificateChainFiles,
              @Nullable final File privateKeyFile)
         throws LDAPException
  {
    this(readCertificateChain(certificateChainFiles),
         ((privateKeyFile == null) ? null : readPrivateKey(privateKeyFile)));
  }



  /**
   * Creates a new instance of this key store content object with the provided
   * information.
   *
   * @param  certificateChainFiles
   *              A list containing one or more files from which to read the PEM
   *              or DER representations of the X.509 certificates to include in
   *              the new certificate chain.  The order of the files, and the
   *              order of the certificates in each file, should be arranged
   *              such that the first certificate read is the end-entity
   *              certificate and each subsequent certificate is the issuer for
   *              the previous.  This must not be {@code null} or empty.
   * @param  privateKeyFile
   *              A file from which to read the PEM or DER representation of the
   *              PKCS #8 private key for the end-entity certificate in the
   *              chain.  This may be {@code null} if the new end-entity
   *              certificate uses the same private key as the certificate
   *              currently in use in the server.
   * @param  privateKeyEncryptionPasswordFile
   *              A file that contains the password needed to decrypt the
   *              private key if it is encrypted.  This may be {@code null} if
   *              the private key is not encrypted.
   *
   * @throws  LDAPException  If a problem occurs while trying to read or parse
   *                         data contained in any of the provided files.
   */
  public CertificateDataReplaceCertificateKeyStoreContent(
              @NotNull final List<File> certificateChainFiles,
              @Nullable final File privateKeyFile,
              @Nullable final File privateKeyEncryptionPasswordFile)
         throws LDAPException
  {
    this(readCertificateChain(certificateChainFiles),
         ((privateKeyFile == null) ? null :
              readPrivateKey(privateKeyFile,
                   privateKeyEncryptionPasswordFile)));
  }



  /**
   * Reads a certificate chain from the given file or set of files.  Each file
   * must contain the PEM or DER representations of one or more X.509
   * certificates.  If a file contains multiple certificates, all certificates
   * in that file must be either all PEM-formatted or all DER-formatted.
   *
   * @param  files  The set of files from which the certificate chain should be
   *                read.  It must not be {@code null} or empty.
   *
   * @return  A list containing the encoded representation of the X.509
   *          certificates read from the file, with each byte array containing
   *          the encoded representation for one certificate.
   *
   * @throws  LDAPException  If a problem was encountered while attempting to
   *                         read from or parse the content of any of the files.
   */
  @NotNull()
  public static List<byte[]> readCertificateChain(@NotNull final File... files)
         throws LDAPException
  {
    return readCertificateChain(Arrays.asList(files));
  }



  /**
   * Reads a certificate chain from the given file or set of files.  Each file
   * must contain the PEM or DER representations of one or more X.509
   * certificates.  If a file contains multiple certificates, all certificates
   * in that file must be either all PEM-formatted or all DER-formatted.
   *
   * @param  files  The set of files from which the certificate chain should be
   *                read.  It must not be {@code null} or empty.
   *
   * @return  A list containing the encoded representation of the X.509
   *          certificates read from the file, with each byte array containing
   *          the encoded representation for one certificate.
   *
   * @throws  LDAPException  If a problem was encountered while attempting to
   *                         read from or parse the content of any of the files.
   */
  @NotNull()
  public static List<byte[]> readCertificateChain(
              @NotNull final List<File> files)
         throws LDAPException
  {
    Validator.ensureNotNullOrEmpty(files,
         "CertificateDataReplaceCertificateKeyStoreContent." +
              "readCertificateChain.files must not be null or empty.");

    final List<byte[]> encodedCerts = new ArrayList<>();
    for (final File f : files)
    {
      readCertificates(f, encodedCerts);
    }

    return Collections.unmodifiableList(encodedCerts);
  }



  /**
   * Reads one or more certificates from the specified file.  The certificates
   * may be in either PEM format or DER format, but if there are multiple
   * certificates in the file, they must all be in the same format.
   *
   * @param  file          The file to be read.  It must not be {@code null}.
   * @param  encodedCerts  A list that will be updated with the certificates
   *                       that are read.  This must not be {@code null} and
   *                       must be updatable.
   *
   * @throws  LDAPException  If a problem was encountered while attempting to
   *                         read from or parse the content of the specified
   *                         file.
   */
  private static void readCertificates(@NotNull final File file,
                                       @NotNull final List<byte[]> encodedCerts)
          throws LDAPException
  {
    // Open the file for reading.
    try (FileInputStream fis = new FileInputStream(file);
         BufferedInputStream bis = new BufferedInputStream(fis))
    {
      // Peek at the first byte of the file.
      bis.mark(1);
      final int firstByte = bis.read();
      bis.reset();


      // If the file is empty, then throw an exception.
      if (firstByte < 0x00)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_CD_KSC_DECODE_ERR_EMPTY_CERT_FILE.get(file.getAbsolutePath()));
      }


      // If the first byte is 0x30, then that indicates that it's the first byte
      // of a DER sequence.  Assume all the certificates in the file are in the
      // DER format.
      if (firstByte == 0x30)
      {
        readDERCertificates(file, bis, encodedCerts);
        return;
      }


      // If the file is PEM-formatted, then the first byte will probably be
      // 0x2D (which is the ASCII '-' character, which will appear at the start
      // of the "-----BEGIN CERTIFICATE-----" header).  However, we also support
      // blank lines and comment lines starting with '#', so we'll just fall
      // back to assuing that it's PEM.
      readPEMCertificates(file, bis, encodedCerts);
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_CD_KSC_DECODE_ERROR_READING_CERT_FILE.get(file.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads one or more DER-formatted X.509 certificates from the given input
   * stream.
   *
   * @param  file          The file with which the provided input stream is
   *                       associated.  It must not be {@code null}.
   * @param  inputStream   The input stream from which the certificates are to
   *                       be read.  It must not be {@code null}.
   * @param  encodedCerts  A list that will be updated with the certificates
   *                       that are read.  This must not be {@code null} and
   *                       must be updatable.
   *
   * @throws  LDAPException  If a problem occurs while trying to read from the
   *                         file or parse the data as ASN.1 DER elements.
   */
  private static void readDERCertificates(
               @NotNull final File file,
               @NotNull final InputStream inputStream,
               @NotNull final List<byte[]> encodedCerts)
          throws LDAPException
  {
    try (ASN1StreamReader asn1Reader = new ASN1StreamReader(inputStream))
    {
      while (true)
      {
        final ASN1Element element = asn1Reader.readElement();
        if (element == null)
        {
          return;
        }

        encodedCerts.add(element.encode());
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);

      // Even though it's possible that it's an I/O problem, it's actually much
      // more likely to be a decoding problem.
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_DER_CERT_ERROR.get(file.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads one or more PEM-formatted X.509 certificates from the given input
   * stream.
   *
   * @param  file          The file with which the provided input stream is
   *                       associated.  It must not be {@code null}.
   * @param  inputStream   The input stream from which the certificates are to
   *                       be read.  It must not be {@code null}.
   * @param  encodedCerts  A list that will be updated with the certificates
   *                       that are read.  This must not be {@code null} and
   *                       must be updatable.
   *
   * @throws  IOException  If a problem occurs while trying to read from the
   *                       file.
   *
   * @throws  LDAPException  If the contents of the file cannot be parsed as a
   *                         valid set of PEM-formatted certificates.
   */
  private static void readPEMCertificates(
               @NotNull final File file,
               @NotNull final InputStream inputStream,
               @NotNull final List<byte[]> encodedCerts)
          throws IOException, LDAPException
  {
    try (X509PEMFileReader pemReader = new X509PEMFileReader(inputStream))
    {
      while (true)
      {
        final X509Certificate cert = pemReader.readCertificate();
        if (cert == null)
        {
          return;
        }

        encodedCerts.add(cert.getX509CertificateBytes());
      }
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_PEM_CERT_ERROR.get(file.getAbsolutePath(),
                e.getMessage()),
           e);
    }
  }



  /**
   * Reads a PKCS #8 private key from the given file.  The file must contain the
   * PEM or DER representation of a single private key.
   *
   * @param  file  The file from which the private key should be read.  It must
   *               not be {@code null}.
   *
   * @return  The encoded representation of the PKCS #8 private key that was
   *          read.
   *
   * @throws  LDAPException  If a problem occurs while trying to read from
   *                         or parse the content of the specified file.
   */
  @NotNull()
  public static byte[] readPrivateKey(@NotNull final File file)
         throws LDAPException
  {
    return readPrivateKey(file, null);
  }



  /**
   * Reads a PKCS #8 private key from the given file.  The file must contain the
   * PEM or DER representation of a single private key.
   *
   * @param  file                    The file from which the private key should
   *                                 be read.  It must not be {@code null}.
   * @param  encryptionPasswordFile  The file containing the password needed to
   *                                 decrypt the private key if it is encrypted.
   *                                 It may be {@code null} if the private key
   *                                 is not encrypted.
   *
   * @return  The encoded representation of the PKCS #8 private key that was
   *          read.
   *
   * @throws  LDAPException  If a problem occurs while trying to read from
   *                         or parse the content of the specified file.
   */
  @NotNull()
  public static byte[] readPrivateKey(@NotNull final File file,
              @Nullable final File encryptionPasswordFile)
         throws LDAPException
  {
    Validator.ensureNotNull(file,
         "CertificateDataReplaceCertificateKeyStoreContent." +
              "readPrivateKey.file must not be null.");


    // If there is an encryption password file, then read the password.
    final char[] encryptionPassword;
    if (encryptionPasswordFile == null)
    {
      encryptionPassword = null;
    }
    else
    {
      final PasswordFileReader passwordFileReader = new PasswordFileReader();
      try
      {
        encryptionPassword =
             passwordFileReader.readPassword(encryptionPasswordFile);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw e;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_CD_KSC_ERROR_READING_PW_FILE.get(
                  encryptionPasswordFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // Open the file for reading.
    try (FileInputStream fis = new FileInputStream(file);
         BufferedInputStream bis = new BufferedInputStream(fis))
    {
      // Read the first byte of the file.
      bis.mark(1);
      final int firstByte = bis.read();
      bis.reset();


      // If the file is empty, then throw an exception, as that's not allowed.
      if (firstByte < 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_CD_KSC_DECODE_ERROR_EMPTY_PK_FILE.get(file.getAbsolutePath()));
      }


      // If the first byte is 0x30, then that indicates it's a DER sequence.
      if (firstByte == 0x30)
      {
        return readDERPrivateKey(file, bis);
      }


      // Assume that the file is PEM-formatted.
      return readPEMPrivateKey(file, bis, encryptionPassword);
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_ERROR_READING_PK_FILE.get(file.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (encryptionPassword != null)
      {
        Arrays.fill(encryptionPassword, '\u0000');
      }
    }
  }



  /**
   * Reads a DER-formatted PKCS #8 private key from the provided input stream.
   *
   * @param  file         The file with which the provided input stream is
   *                      associated.  It must not be {@code null}.
   * @param  inputStream  The input stream from which the private key will be
   *                      read.  It must not be {@code null}.
   *
   * @return  The bytes that comprise the encoded PKCS #8 private key.
   *
   * @throws  LDAPException  If a problem occurs while attempting to read the
   *                         private key data from the given file.
   */
  @NotNull()
  private static byte[] readDERPrivateKey(
               @NotNull final File file,
               @NotNull final InputStream inputStream)
          throws LDAPException
  {
    try (ASN1StreamReader asn1Reader = new ASN1StreamReader(inputStream))
    {
      final ASN1Element element = asn1Reader.readElement();
      if (asn1Reader.readElement() != null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CD_KSC_DECODE_MULTIPLE_DER_KEYS_IN_FILE.get(
                  file.getAbsolutePath()));
      }

      return element.encode();
    }
    catch (final IOException e)
    {
      Debug.debugException(e);

      // Even though it's possible that it's an I/O problem, it's actually much
      // more likely to be a decoding problem.
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_DER_PK_ERROR.get(file.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads a PEM-formatted PKCS #8 private key from the provided input stream.
   *
   * @param  file                The file with which the provided input stream
   *                             is associated.  It must not be {@code null}.
   * @param  inputStream         The input stream from which the private key
   *                             will be read.  It must not be {@code null}.
   * @param  encryptionPassword  The password needed to decrypt the private key
   *                             if it is encrypted.  It may be {@code null} if
   *                             the private key is not encrypted.
   *
   * @return  The bytes that comprise the encoded PKCS #8 private key.
   *
   * @throws  IOException  If a problem occurs while trying to read from the
   *                       file.
   *
   * @throws  LDAPException  If the contents of the file cannot be parsed as a
   *                         valid PEM-formatted PKCS #8 private key.
   */
  @NotNull()
  private static byte[] readPEMPrivateKey(
               @NotNull final File file,
               @NotNull final InputStream inputStream,
               @Nullable final char[] encryptionPassword)
          throws IOException, LDAPException
  {
    try (PKCS8PEMFileReader pemReader = new PKCS8PEMFileReader(inputStream))
    {
      final PKCS8PrivateKey privateKey = pemReader.readPrivateKey();
      if (pemReader.readPrivateKey(encryptionPassword) != null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CD_KSC_DECODE_MULTIPLE_PEM_KEYS_IN_FILE.get(
                  file.getAbsolutePath()));
      }

      return privateKey.getPKCS8PrivateKeyBytes();
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_PEM_PK_ERROR.get(file.getAbsolutePath(),
                e.getMessage()),
           e);
    }
  }



  /**
   * Retrieves a list of the DER-formatted or PEM-formatted representations of
   * the X.509 certificates in the new certificate chain.
   *
   * @return  A list of the encoded representations of the X.509 certificates
   *          in the new certificate chain.
   */
  @NotNull()
  public List<byte[]> getCertificateChainData()
  {
    return certificateChainData;
  }



  /**
   * Retrieves the DER-formatted or PEM-formatted PKCS #8 private key for the
   * new certificate, if available.
   *
   * @return  The encoded representation of the PKCS #8 private key for the new
   *          certificate, or {@code null} if the new certificate should use the
   *          same private key as the current certificate.
   */
  @Nullable()
  public byte[] getPrivateKeyData()
  {
    return privateKeyData;
  }



  /**
   * Decodes a key store file replace certificate key store content object from
   * the provided ASN.1 element.
   *
   * @param  element  The ASN.1 element containing the encoded representation of
   *                  the key store file replace certificate key store content
   *                  object.  It must not be {@code null}.
   *
   * @return  The decoded key store content object.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a key store file replace certificate key store
   *                         content object.
   */
  @NotNull()
  static CertificateDataReplaceCertificateKeyStoreContent decodeInternal(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements = element.decodeAsSequence().elements();

      final ASN1Element[] chainElements =
           elements[0].decodeAsSequence().elements();
      final List<byte[]> chainBytes = new ArrayList<>();
      for (final ASN1Element e : chainElements)
      {
        chainBytes.add(e.decodeAsOctetString().getValue());
      }

      byte[] pkBytes = null;
      for (int i=1; i < elements.length; i++)
      {
        if (elements[i].getType() == TYPE_PRIVATE_KEY)
        {
          pkBytes = elements[i].decodeAsOctetString().getValue();
        }
      }

      return new CertificateDataReplaceCertificateKeyStoreContent(
           chainBytes, pkBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CD_KSC_DECODE_ERROR.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encode()
  {
    final List<ASN1Element> elements = new ArrayList<>(2);

    final List<ASN1Element> chainElements =
         new ArrayList<>(certificateChainData.size());
    for (final byte[] certBytes : certificateChainData)
    {
      chainElements.add(new ASN1OctetString(certBytes));
    }
    elements.add(new ASN1Sequence(TYPE_CERTIFICATE_CHAIN, chainElements));

    if (privateKeyData != null)
    {
      elements.add(new ASN1OctetString(TYPE_PRIVATE_KEY, privateKeyData));
    }

    return new ASN1Sequence(TYPE_KEY_STORE_CONTENT, elements);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CertificateDataReplaceCertificateKeyStoreContent(" +
         "certificateChainLength=");
    buffer.append(certificateChainData.size());
    buffer.append(", privateProvided=");
    buffer.append(privateKeyData != null);
    buffer.append(')');
  }
}
