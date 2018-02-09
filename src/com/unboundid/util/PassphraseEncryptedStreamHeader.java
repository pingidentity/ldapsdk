/*
 * Copyright 2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018 Ping Identity Corporation
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



import java.io.OutputStream;
import java.io.Serializable;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class represents a data structure that will be used to hold information
 * about the encryption performed by the {@link PassphraseEncryptedOutputStream}
 * when writing encrypted data, and that will be used by a
 * {@link PassphraseEncryptedInputStream} to obtain the settings needed to
 * decrypt the encrypted data.
 * <BR><BR>
 * The data associated with this class is completely threadsafe.  The methods
 * used to interact with input and output streams are not threadsafe in that
 * nothing else should be attempting to read from/write to the stream at the
 * same time.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class PassphraseEncryptedStreamHeader
       implements Serializable
{
  /**
   * The BER type used for the header element that specifies the encoding
   * version.
   */
  static final byte TYPE_ENCODING_VERSION = (byte) 0x80;



  /**
   * The BER type used for the header element containing the key factory
   * algorithm.
   */
  static final byte TYPE_KEY_FACTORY_ALGORITHM = (byte) 0x81;



  /**
   * The BER type used for the header element containing the key factory
   * iteration count.
   */
  static final byte TYPE_KEY_FACTORY_ITERATION_COUNT = (byte) 0x82;



  /**
   * The BER type used for the header element containing the key factory salt.
   */
  static final byte TYPE_KEY_FACTORY_SALT = (byte) 0x83;



  /**
   * The BER type used for the header element containing the key length in bits.
   */
  static final byte TYPE_KEY_FACTORY_KEY_LENGTH_BITS = (byte) 0x84;



  /**
   * The BER type used for the header element containing the cipher
   * transformation.
   */
  static final byte TYPE_CIPHER_TRANSFORMATION = (byte) 0x85;



  /**
   * The BER type used for the header element containing the cipher
   * initialization vector.
   */
  static final byte TYPE_CIPHER_INITIALIZATION_VECTOR = (byte) 0x86;



  /**
   * The BER type used for the header element containing the key identifier.
   */
  static final byte TYPE_KEY_IDENTIFIER = (byte) 0x87;



  /**
   * The "magic" value that will appear at the start of the header.
   */
  static final byte[] MAGIC_BYTES =
       { 0x55, 0x42, 0x49, 0x44, 0x50, 0x49, 0x4E, 0x48 };



  /**
   * The encoding version for a v1 encoding.
   */
  static final int ENCODING_VERSION_1 = 1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2497971977247119395L;


  // An encoded representation of this header.
  private final byte[] encodedHeader;

  // The salt used when generating the encryption key from the passphrase.
  private final byte[] keyFactorySalt;

  // The initialization vector used when creating the cipher.
  private final byte[] cipherInitializationVector;

  // The iteration count used when generating the encryption key from the
  private final int keyFactoryIterationCount;
  // passphrase.

  // The length (in bits) of the encryption key generated from the passphrase.
  private final int keyFactoryKeyLengthBits;

  // The cipher transformation used for the encryption.
  private final String cipherTransformation;

  // The name of the key factory used to generate the encryption key from the
  // passphrase.
  private final String keyFactoryAlgorithm;

  // An optional identifier that can be used to associate this header with some
  // other encryption settings object.
  private final String keyIdentifier;



  /**
   * Creates a new passphrase-encrypted stream header with the provided
   * information.
   *
   * @param  keyFactoryAlgorithm         The key factory algorithm used to
   *                                     generate the encryption key from the
   *                                     passphrase.  It must not be
   *                                     {@code null}.
   * @param  keyFactoryIterationCount    The iteration count used to generate
   *                                     the encryption key from the passphrase.
   * @param  keyFactorySalt              The salt used to generate the
   *                                     encryption key from the passphrase.
   *                                     It must not be {@code null}.
   * @param  keyFactoryKeyLengthBits     The length (in bits) of the encryption
   *                                     key generated from the passphrase.
   * @param  cipherTransformation        The cipher transformation used for the
   *                                     encryption.  It must not be
   *                                     {@code null}.
   * @param  cipherInitializationVector  The initialization vector used when
   *                                     creating the cipher.  It must not be
   *                                     {@code null}.
   * @param  keyIdentifier               An optional identifier that can be used
   *                                     to associate this passphrase-encrypted
   *                                     stream header with some other
   *                                     encryption settings object.  It may
   *                                     optionally be {@code null}.
   */
  PassphraseEncryptedStreamHeader(final String keyFactoryAlgorithm,
                                  final int keyFactoryIterationCount,
                                  final byte[] keyFactorySalt,
                                  final int keyFactoryKeyLengthBits,
                                  final String cipherTransformation,
                                  final byte[] cipherInitializationVector,
                                  final String keyIdentifier)
  {
    this.keyFactoryAlgorithm = keyFactoryAlgorithm;
    this.keyFactoryIterationCount = keyFactoryIterationCount;
    this.keyFactorySalt = Arrays.copyOf(keyFactorySalt, keyFactorySalt.length);
    this.keyFactoryKeyLengthBits = keyFactoryKeyLengthBits;
    this.cipherTransformation = cipherTransformation;
    this.cipherInitializationVector = Arrays.copyOf(cipherInitializationVector,
         cipherInitializationVector.length);
    this.keyIdentifier = keyIdentifier;

    encodedHeader = encode(keyFactoryAlgorithm, keyFactoryIterationCount,
         this.keyFactorySalt, keyFactoryKeyLengthBits, cipherTransformation,
         this.cipherInitializationVector, keyIdentifier);
  }



  /**
   * Generates an encoded representation of the header with the provided
   * settings.
   *
   * @param  keyFactoryAlgorithm         The key factory algorithm used to
   *                                     generate the encryption key from the
   *                                     passphrase.  It must not be
   *                                     {@code null}.
   * @param  keyFactoryIterationCount    The iteration count used to generate
   *                                     the encryption key from the passphrase.
   * @param  keyFactorySalt              The salt used to generate the
   *                                     encryption key from the passphrase.
   *                                     It must not be {@code null}.
   * @param  keyFactoryKeyLengthBits     The length (in bits) of the encryption
   *                                     key generated from the passphrase.
   * @param  cipherTransformation        The cipher transformation used for the
   *                                     encryption.  It must not be
   *                                     {@code null}.
   * @param  cipherInitializationVector  The initialization vector used when
   *                                     creating the cipher.  It must not be
   *                                     {@code null}.
   * @param  keyIdentifier               An optional identifier that can be used
   *                                     to associate this passphrase-encrypted
   *                                     stream header with some other
   *                                     encryption settings object.  It may
   *                                     optionally be {@code null}.
   *
   * @return  The encoded representation of the header.
   */
  private static byte[] encode(final String keyFactoryAlgorithm,
                               final int keyFactoryIterationCount,
                               final byte[] keyFactorySalt,
                               final int keyFactoryKeyLengthBits,
                               final String cipherTransformation,
                               final byte[] cipherInitializationVector,
                               final String keyIdentifier)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(8);
    elements.add(new ASN1Integer(TYPE_ENCODING_VERSION, ENCODING_VERSION_1));
    elements.add(new ASN1OctetString(TYPE_KEY_FACTORY_ALGORITHM,
         keyFactoryAlgorithm));
    elements.add(new ASN1Integer(TYPE_KEY_FACTORY_ITERATION_COUNT,
         keyFactoryIterationCount));
    elements.add(new ASN1OctetString(TYPE_KEY_FACTORY_SALT, keyFactorySalt));
    elements.add(new ASN1Integer(TYPE_KEY_FACTORY_KEY_LENGTH_BITS,
         keyFactoryKeyLengthBits));
    elements.add(new ASN1OctetString(TYPE_CIPHER_TRANSFORMATION,
         cipherTransformation));
    elements.add(new ASN1OctetString(TYPE_CIPHER_INITIALIZATION_VECTOR,
         cipherInitializationVector));

    if (keyIdentifier != null)
    {
      elements.add(new ASN1OctetString(TYPE_KEY_IDENTIFIER, keyIdentifier));
    }

    final byte[] elementBytes = new ASN1Sequence(elements).encode();
    final byte[] headerBytes =
         new byte[MAGIC_BYTES.length + elementBytes.length];
    System.arraycopy(MAGIC_BYTES, 0, headerBytes, 0, MAGIC_BYTES.length);
    System.arraycopy(elementBytes, 0, headerBytes, MAGIC_BYTES.length,
         elementBytes.length);
    return headerBytes;
  }



  /**
   * Writes an encoded representation of this passphrase-encrypted stream header
   * to the provided output stream.  The output stream will remain open after
   * this method completes.
   *
   * @param  outputStream  The output stream to which the header will be
   *                       written.
   *
   * @throws  IOException  If a problem is encountered while trying to write to
   *                       the provided output stream.
   */
  public void writeTo(final OutputStream outputStream)
         throws IOException
  {
    outputStream.write(encodedHeader);
  }



  /**
   * Reads a passphrase-encrypted stream header from the provided input stream.
   * This method will not close the provided input stream, regardless of whether
   * it returns successfully or throws an exception.  If it returns
   * successfully, then the position then the header bytes will have been
   * consumed, so the next data to be read should be the data encrypted with
   * these settings.  If it throws an exception, then some unknown amount of
   * data may have been read from the stream.
   *
   * @param  inputStream  The input stream from which to read the encoded
   *                      passphrase-encrypted stream header.  It must not be
   *                      {@code null}.
   *
   * @return  The passphrase-encrypted stream header that was read from the
   *          provided input stream.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from the provided input stream.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the data that was read.
   */
  public static PassphraseEncryptedStreamHeader
                     readFrom(final InputStream inputStream)
         throws IOException, LDAPException
  {
    // Read the magic from the input stream.
    for (int i=0; i < MAGIC_BYTES.length; i++)
    {
      final int magicByte = inputStream.read();
      if (magicByte < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_ENCRYPTED_STREAM_HEADER_READ_END_OF_STREAM_IN_MAGIC.get());
      }
      else if (magicByte != MAGIC_BYTES[i])
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_ENCRYPTED_STREAM_HEADER_READ_MAGIC_MISMATCH.get());
      }
    }


    // The remainder of the header should be an ASN.1 sequence.  Read and
    // process that sequenced.
    try
    {
      final ASN1Element headerSequenceElement =
           ASN1Element.readFrom(inputStream);
      if (headerSequenceElement == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_ENCRYPTED_STREAM_HEADER_READ_END_OF_STREAM_AFTER_MAGIC.get(
                  ));
      }

      final ASN1Sequence headerSequence =
           ASN1Sequence.decodeAsSequence(headerSequenceElement);
      return decodeHeaderSequence(headerSequence);
    }
    catch (final IOException | LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_ENCRYPTED_STREAM_HEADER_READ_ASN1_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Decodes the contents of the provided byte array as a passphrase-encrypted
   * stream header.  The provided array must contain only the header, with no
   * additional data before or after.
   *
   * @param  encodedHeader  The bytes that comprise the header to decode.  It
   *                        must not be {@code null} or empty.
   *
   * @return  The passphrase-encrypted stream header that was decoded from the
   *          provided byte array.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the data as a passphrase-encrypted stream header.
   */
  public static PassphraseEncryptedStreamHeader
                     decode(final byte[] encodedHeader)
         throws LDAPException
  {
    // Make sure that the array is long enough to hold a valid header.
    if (encodedHeader.length <= MAGIC_BYTES.length)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_ENCRYPTED_STREAM_HEADER_DECODE_TOO_SHORT.get());
    }


    // Make sure that the array starts with the provided magic value.
    for (int i=0; i < MAGIC_BYTES.length; i++)
    {
      if (encodedHeader[i] != MAGIC_BYTES[i])
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_ENCRYPTED_STREAM_HEADER_DECODE_MAGIC_MISMATCH.get());
      }
    }


    // Decode the remainder of the array as an ASN.1 sequence.
    final ASN1Sequence headerSequence;
    try
    {
      final byte[] encodedHeaderWithoutMagic =
           new byte[encodedHeader.length - MAGIC_BYTES.length];
      System.arraycopy(encodedHeader, MAGIC_BYTES.length,
           encodedHeaderWithoutMagic, 0, encodedHeaderWithoutMagic.length);
      headerSequence = ASN1Sequence.decodeAsSequence(encodedHeaderWithoutMagic);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_ENCRYPTED_STREAM_HEADER_DECODE_ASN1_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    return decodeHeaderSequence(headerSequence);
  }



  /**
   * Decodes the contents of the provided ASN.1 sequence as the portion of a
   * passphrase-encrypted stream header that follows the magic bytes.
   *
   * @param  headerSequence  The header sequence portion of the encoded header.
   *
   * @return  The passphrase-encrypted stream header that was decoded from the
   *          provided ASN.1 sequence.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the data as a passphrase-encrypted stream header.
   */
  private static PassphraseEncryptedStreamHeader decodeHeaderSequence(
                      final ASN1Sequence headerSequence)
          throws LDAPException
  {
    try
    {
      // The first element must be the encoding version, and it must be 1.
      final ASN1Element[] headerElements = headerSequence.elements();
      final ASN1Integer versionElement =
           ASN1Integer.decodeAsInteger(headerElements[0]);
      if (versionElement.intValue() != ENCODING_VERSION_1)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_ENCRYPTED_HEADER_SEQUENCE_UNSUPPORTED_VERSION.get(
                  versionElement.intValue()));
      }

      // The second element must be the key factory algorithm.
      final String keyFactoryAlgorithm =
           ASN1OctetString.decodeAsOctetString(headerElements[1]).stringValue();

      // The third element must be the key factory iteration count.
      final int keyFactoryIterationCount =
           ASN1Integer.decodeAsInteger(headerElements[2]).intValue();

      // The fourth element must be the key factory salt.
      final byte[] keyFactorySalt =
           ASN1OctetString.decodeAsOctetString(headerElements[3]).getValue();

      // The fifth element must be the key length in bits.
      final int keyFactoryKeyLengthBits =
           ASN1Integer.decodeAsInteger(headerElements[4]).intValue();

      // The sixth element must be the cipher transformation.
      final String cipherTransformation =
           ASN1OctetString.decodeAsOctetString(headerElements[5]).stringValue();

      // The seventh element must be the initialization vector.
      final byte[] cipherInitializationVector =
           ASN1OctetString.decodeAsOctetString(headerElements[6]).getValue();

      // Look through any remaining elements and decode them as appropriate.
      String keyIdentifier = null;
      for (int i=7; i < headerElements.length; i++)
      {
        switch (headerElements[i].getType())
        {
          case TYPE_KEY_IDENTIFIER:
            keyIdentifier = ASN1OctetString.decodeAsOctetString(
                 headerElements[i]).stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PW_ENCRYPTED_HEADER_SEQUENCE_UNRECOGNIZED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(headerElements[i].getType())));
        }
      }

      return new PassphraseEncryptedStreamHeader(keyFactoryAlgorithm,
           keyFactoryIterationCount, keyFactorySalt, keyFactoryKeyLengthBits,
           cipherTransformation, cipherInitializationVector, keyIdentifier);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_ENCRYPTED_HEADER_SEQUENCE_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a cipher with the provided mode using the given passphrase.
   *
   * @param  mode        The mode to use for the cipher.  It must be one of
   *                     {@code Cipher.ENCRYPT_MODE} or
   *                     {@code Cipher.DECRYPT_MODE}.
   * @param  passphrase  The passphrase to use to generate the encryption key.
   *
   * @return  The {@code Cipher} instance that was created.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    creating the cipher.
   */
  Cipher createCipher(final int mode, final char[] passphrase)
         throws GeneralSecurityException
  {
    final SecretKeyFactory keyFactory =
         SecretKeyFactory.getInstance(keyFactoryAlgorithm);
    final PBEKeySpec keySpec = new PBEKeySpec(passphrase, keyFactorySalt,
         keyFactoryIterationCount, keyFactoryKeyLengthBits);

    final String cipherAlgorithm = cipherTransformation.substring(0,
         cipherTransformation.indexOf('/'));
    final SecretKeySpec encryptionKey = new SecretKeySpec(
         keyFactory.generateSecret(keySpec).getEncoded(), cipherAlgorithm);

    final Cipher cipher = Cipher.getInstance(cipherTransformation);
    cipher.init(mode, encryptionKey,
         new IvParameterSpec(cipherInitializationVector));

    return cipher;
  }



  /**
   * Retrieves the key factory algorithm used to generate the encryption key
   * from the passphrase.
   *
   * @return  The key factory algorithm used to generate the encryption key from
   *          the passphrase.
   */
  public String getKeyFactoryAlgorithm()
  {
    return keyFactoryAlgorithm;
  }



  /**
   * Retrieves the iteration count used to generate the encryption key from the
   * passphrase.
   *
   * @return  The iteration count used to generate the encryption key from the
   *          passphrase.
   */
  public int getKeyFactoryIterationCount()
  {
    return keyFactoryIterationCount;
  }



  /**
   * Retrieves the salt used to generate the encryption key from the passphrase.
   *
   * @return  The salt used to generate the encryption key from the passphrase.
   */
  public byte[] getKeyFactorySalt()
  {
    return Arrays.copyOf(keyFactorySalt, keyFactorySalt.length);
  }



  /**
   * Retrieves the length (in bits) of the encryption key generated from the
   * passphrase.
   *
   * @return  The length (in bits) of the encryption key generated from the
   *          passphrase.
   */
  public int getKeyFactoryKeyLengthBits()
  {
    return keyFactoryKeyLengthBits;
  }



  /**
   * Retrieves the cipher transformation used for the encryption.
   *
   * @return  The cipher transformation used for the encryption.
   */
  public String getCipherTransformation()
  {
    return cipherTransformation;
  }



  /**
   * Retrieves the cipher initialization vector used for the encryption.
   *
   * @return  The cipher initialization vector used for the encryption.
   */
  public byte[] getCipherInitializationVector()
  {
    return Arrays.copyOf(cipherInitializationVector,
         cipherInitializationVector.length);
  }



  /**
   * Retrieves the key identifier used to associate this passphrase-encrypted
   * stream header with some other encryption settings object, if defined.
   *
   * @return  The key identifier used to associate this passphrase-encrypted
   *          stream header with some other encryption settings object, or
   *          {@code null} if none was provided.
   */
  public String getKeyIdentifier()
  {
    return keyIdentifier;
  }



  /**
   * Retrieves an encoded representation of this passphrase-encrypted stream
   * header.
   *
   * @return  An encoded representation of this passphrase-encrypted stream
   *          header.
   */
  public byte[] getEncodedHeader()
  {
    return Arrays.copyOf(encodedHeader, encodedHeader.length);
  }



  /**
   * Retrieves a string representation of this passphrase-encrypted stream
   * header.
   *
   * @return  A string representation of this passphrase-encrypted stream
   *         header.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this passphrase-encrypted stream header
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PassphraseEncryptedStreamHeader(keyFactoryAlgorithm='");
    buffer.append(keyFactoryAlgorithm);
    buffer.append("', keyFactoryIterationCount=");
    buffer.append(keyFactoryIterationCount);
    buffer.append(", keyFactorySaltLengthBytes=");
    buffer.append(keyFactorySalt.length);
    buffer.append(", keyFactoryKeyLengthBits=");
    buffer.append(keyFactoryKeyLengthBits);
    buffer.append(", cipherTransformation'=");
    buffer.append(cipherTransformation);
    buffer.append("', cipherInitializationVectorLengthBytes=");
    buffer.append(cipherInitializationVector.length);
    buffer.append('\'');

    if (keyIdentifier != null)
    {
      buffer.append(", keyIdentifier='");
      buffer.append(keyIdentifier);
      buffer.append('\'');
    }

    buffer.append(", encodedHeaderLengthBytes=");
    buffer.append(encodedHeader.length);
    buffer.append(')');
  }
}
