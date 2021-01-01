/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides an {@code InputStream} implementation that can read
 * encrypted data written by the {@link PassphraseEncryptedOutputStream}.  It
 * will use a provided password in conjunction with a
 * {@link PassphraseEncryptedStreamHeader} that will either be read from the
 * beginning of the stream or provided in the constructor.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PassphraseEncryptedInputStream
       extends InputStream
{
  // The cipher input stream that will be used to actually read and decrypt the
  // data.
  @NotNull private final CipherInputStream cipherInputStream;

  // A header containing the encoded encryption details.
  @NotNull private final PassphraseEncryptedStreamHeader encryptionHeader;



  /**
   * Creates a new passphrase-encrypted input stream that will read the
   * {@link PassphraseEncryptedStreamHeader} from the underlying input stream.
   *
   * @param  passphrase          The passphrase used to generate the encryption
   *                             key when the corresponding
   *                             {@link PassphraseEncryptedOutputStream} was
   *                             created.
   * @param  wrappedInputStream  The input stream from which the encryption
   *                             header and encrypted data will be read.
   *
   * @throws  IOException  If a problem is encountered while trying to read the
   *                       encryption header from the provided input stream.
   *
   * @throws  LDAPException  If s problem is encountered while trying to parse
   *                         the encryption header read from the provided input
   *                         stream.
   *
   * @throws  InvalidKeyException  If the MAC contained in the header does not
   *                               match the expected value.
   *
   * @throws  GeneralSecurityException  If a problem occurs while attempting to
   *                                    initialize the decryption.
   */
  public PassphraseEncryptedInputStream(@NotNull final String passphrase,
              @NotNull final InputStream wrappedInputStream)
         throws IOException, LDAPException, InvalidKeyException,
                GeneralSecurityException
  {
    this(passphrase.toCharArray(), wrappedInputStream);
  }



  /**
   * Creates a new passphrase-encrypted input stream that will read the
   * {@link PassphraseEncryptedStreamHeader} from the underlying input stream.
   *
   * @param  passphrase          The passphrase used to generate the encryption
   *                             key when the corresponding
   *                             {@link PassphraseEncryptedOutputStream} was
   *                             created.
   * @param  wrappedInputStream  The input stream from which the encryption
   *                             header and encrypted data will be read.
   *
   * @throws  IOException  If a problem is encountered while trying to read the
   *                       encryption header from the provided input stream.
   *
   * @throws  LDAPException  If s problem is encountered while trying to parse
   *                         the encryption header read from the provided input
   *                         stream.
   *
   * @throws  InvalidKeyException  If the MAC contained in the header does not
   *                               match the expected value.
   *
   * @throws  GeneralSecurityException  If a problem occurs while attempting to
   *                                    initialize the decryption.
   */
  public PassphraseEncryptedInputStream(@NotNull final char[] passphrase,
              @NotNull final InputStream wrappedInputStream)
         throws IOException, LDAPException, InvalidKeyException,
                GeneralSecurityException
  {
    this(wrappedInputStream,
         PassphraseEncryptedStreamHeader.readFrom(wrappedInputStream,
              passphrase));
  }



  /**
   * Creates a new passphrase-encrypted input stream using the provided
   * information.
   *
   * @param  wrappedInputStream  The input stream from which the encrypted data
   *                             will be read.
   * @param  encryptionHeader    The encryption header with the information
   *                             needed (in conjunction with the given
   *                             passphrase) to decrypt the data read from the
   *                             provided input stream.
   *
   * @throws  GeneralSecurityException  If a problem occurs while attempting to
   *                                    initialize the decryption.
   */
  public PassphraseEncryptedInputStream(
              @NotNull final InputStream wrappedInputStream,
              @NotNull final PassphraseEncryptedStreamHeader encryptionHeader)
         throws GeneralSecurityException
  {
    this.encryptionHeader = encryptionHeader;

    final Cipher cipher = encryptionHeader.createCipher(Cipher.DECRYPT_MODE);
    cipherInputStream = new CipherInputStream(wrappedInputStream, cipher);
  }



  /**
   * Retrieves a single byte of decrypted data read from the underlying input
   * stream.
   *
   * @return  A value that is between 0 and 255 representing the byte that was
   *          read, or -1 to indicate that the end of the input stream has been
   *          reached.
   *
   * @throws  IOException  If a problem is encountered while reading or
   *                       decrypting the data.
   */
  @Override()
  public int read()
         throws IOException
  {
    return cipherInputStream.read();
  }



  /**
   * Reads decrypted data and writes it into the provided byte array.
   *
   * @param  b  The byte array into which the decrypted data will be placed,
   *            starting with an index of zero.  It must not be {@code null} or
   *            empty.
   *
   * @return  The number of bytes added to the provided buffer, or -1 if the end
   *          of the input stream has been reached and there is no more data to
   *          read.
   *
   * @throws  IOException  If a problem is encountered while reading or
   *                       decrypting the data.
   */
  @Override()
  public int read(@NotNull final byte[] b)
         throws IOException
  {
    return cipherInputStream.read(b);
  }



  /**
   * Reads decrypted data and writes it into the specified portion of the
   * provided byte array.
   *
   * @param  b       The byte array into which the decrypted data will be
   *                 placed.  It must not be {@code null} or empty.
   * @param  offset  The position in the provided array at which to begin adding
   *                 the decrypted data.  It must be greater than or equal to
   *                 zero and less than the length of the provided array.
   * @param  length  The maximum number of bytes to be added to the given array.
   *                 This must be greater than zero, and the sum of the
   *                 {@code offset} and {@code length} must be less than or
   *                 equal to the length of the provided array.
   *
   * @return  The number of bytes added to the provided buffer, or -1 if the end
   *          of the input stream has been reached and there is no more data to
   *          read.
   *
   * @throws  IOException  If a problem is encountered while reading or
   *                       decrypting the data.
   */
  @Override()
  public int read(@NotNull final byte[] b, final int offset, final int length)
         throws IOException
  {
    return cipherInputStream.read(b, offset, length);
  }



  /**
   * Skips over and discards up to the specified number of bytes of decrypted
   * data obtained from the underlying input stream.
   *
   * @param  maxBytesToSkip  The maximum number of bytes to skip.
   *
   * @return  The number of bytes that were actually skipped.
   *
   * @throws  IOException  If a problem is encountered while skipping data from
   *                       the stream.
   */
  @Override()
  public long skip(final long maxBytesToSkip)
         throws IOException
  {
    return cipherInputStream.skip(maxBytesToSkip);
  }



  /**
   * Retrieves an estimate of the number of decrypted byte that are available to
   * read from the underlying stream without blocking.  Note that some
   * implementations always return a value of zero, so a return value of zero
   * does not necessarily mean that there is no data available to read.
   *
   * @return  An estimate of the number of decrypted bytes that are available to
   *          read from the underlying stream without blocking.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       determine the number of bytes available to read.
   */
  @Override()
  public int available()
         throws IOException
  {
    return cipherInputStream.available();
  }



  /**
   * Closes this input stream and the underlying stream.
   *
   * @throws  IOException  If a problem is encountered while closing the stream.
   */
  @Override()
  public void close()
         throws IOException
  {
    cipherInputStream.close();
  }



  /**
   * Indicates whether this input stream supports the use of the
   * {@link #mark(int)} and {@link #reset()} methods.
   *
   * @return  {@code true} if this input stream supports the {@code mark} and
   *          {@code reset} methods, or {@code false} if not.
   */
  @Override()
  public boolean markSupported()
  {
    return cipherInputStream.markSupported();
  }



  /**
   * Marks the current position in this input stream so that the caller may
   * return to that spot (and re-read the data) using the {@link #reset()}
   * method.  Use the {@link #markSupported()} method to determine whether this
   * feature is supported for this input stream.
   *
   * @param  readLimit  The maximum number of bytes expected to be read between
   *                    the mark and the call to the {@code reset} method.
   */
  @Override()
  public void mark(final int readLimit)
  {
    cipherInputStream.mark(readLimit);
  }



  /**
   * Attempts to reset the position of this input stream to the position of the
   * last call to {@link #mark(int)}.  Use the {@link #markSupported()} method
   * to determine whether this feature is supported for ths input stream.
   *
   * @throws  IOException  If a problem is encountered while performing the
   *                       reset (e.g., no mark has been set, if too much data
   *                       has been read since setting the mark, or if the
   *                       {@code mark} and {@code reset} methods are not
   *                       supported).
   */
  @Override()
  public void reset()
         throws IOException
  {
    cipherInputStream.reset();
  }



  /**
   * Retrieves an encryption header with details about the encryption used when
   * the data was originally written.
   *
   * @return  An encryption header with details about the encryption used when
   *          the data was originally written.
   */
  @NotNull()
  public PassphraseEncryptedStreamHeader getEncryptionHeader()
  {
    return encryptionHeader;
  }
}
