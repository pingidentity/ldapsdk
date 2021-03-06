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
package com.unboundid.util.ssl.cert;



import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a mechanism for reading a PEM-encoded PKCS #8 private key
 * from a specified file.  While it is generally expected that a private key
 * file will contain only a single key, it is possible to read multiple keys
 * from the same file.  Each private key should consist of the following:
 * <UL>
 *   <LI>A line containing only the string "-----BEGIN PRIVATE KEY-----" or
 *       ""-----BEGIN RSA PRIVATE KEY-----.</LI>
 *   <LI>One or more lines representing the base64-encoded representation of the
 *       bytes that comprise the PKCS #8 private key.</LI>
 *   <LI>A line containing only the string "-----END PRIVATE KEY-----" or
 *       ""-----END RSA PRIVATE KEY-----.</LI>
 * </UL>
 * <BR><BR>
 * Any spaces that appear at the beginning or end of each line will be ignored.
 * Empty lines and lines that start with the octothorpe (#) character will also
 * be ignored.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PKCS8PEMFileReader
       implements Closeable
{
  /**
   * The header string that should appear on a line by itself before the
   * base64-encoded representation of the bytes that comprise a PKCS #8 private
   * key.
   */
  @NotNull public static final String BEGIN_PRIVATE_KEY_HEADER =
       "-----BEGIN PRIVATE KEY-----";



  /**
   * An alternative begin header string that may appear on a line by itself for
   * cases in which the certificate uses an RSA key pair.
   */
  @NotNull public static final String BEGIN_RSA_PRIVATE_KEY_HEADER =
       "-----BEGIN RSA PRIVATE KEY-----";



  /**
   * The footer string that should appear on a line by itself after the
   * base64-encoded representation of the bytes that comprise a PKCS #8 private
   * key.
   */
  @NotNull public static final String END_PRIVATE_KEY_FOOTER =
       "-----END PRIVATE KEY-----";



  /**
   * An alternative end footer string that may appear on a line by itself for
   * cases in which the certificate uses an RSA key pair.
   */
  @NotNull public static final String END_RSA_PRIVATE_KEY_FOOTER =
       "-----END RSA PRIVATE KEY-----";



  // The reader that will be used to consume data from the PEM file.
  @NotNull private final BufferedReader reader;



  /**
   * Creates a new PKCS #8 PEM file reader that will read private key
   * information from the specified file.
   *
   * @param  pemFilePath  The path to the PEM file from which the private key
   *                      should be read.  This must not be {@code null} and the
   *                      file must exist.
   *
   * @throws  IOException  If a problem occurs while attempting to open the file
   *                       for reading.
   */
  public PKCS8PEMFileReader(@NotNull final String pemFilePath)
         throws IOException
  {
    this(new File(pemFilePath));
  }



  /**
   * Creates a new PKCS #8 PEM file reader that will read private key
   * information from the specified file.
   *
   * @param  pemFile  The PEM file from which the private key should be read.
   *                  This must not be {@code null} and the file must
   *                  exist.
   *
   * @throws  IOException  If a problem occurs while attempting to open the file
   *                       for reading.
   */
  public PKCS8PEMFileReader(@NotNull final File pemFile)
         throws IOException
  {
    this(new FileInputStream(pemFile));
  }



  /**
   * Creates a new PKCS #8 PEM file reader that will read private key
   * information from the provided input stream.
   *
   * @param  inputStream  The input stream from which the private key should
   *                      be read.  This must not be {@code null} and it must be
   *                      open for reading.
   */
  public PKCS8PEMFileReader(@NotNull final InputStream inputStream)
  {
    reader = new BufferedReader(new InputStreamReader(inputStream));
  }



  /**
   * Reads the next private key from the PEM file.
   *
   * @return  The private key that was read, or {@code null} if the end of the
   *          file has been reached.
   *
   * @throws  IOException  If a problem occurs while trying to read data from
   *                       the PEM file.
   *
   * @throws  CertException  If a problem occurs while trying to interpret data
   *                         read from the PEM file as a PKCS #8 private key.
   */
  @Nullable()
  public PKCS8PrivateKey readPrivateKey()
         throws IOException, CertException
  {
    String beginLine = null;
    final StringBuilder base64Buffer = new StringBuilder();

    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        // We hit the end of the file.  If we read a begin header, then that's
        // an error.
        if (beginLine != null)
        {
          throw new CertException(ERR_PKCS8_PEM_READER_EOF_WITHOUT_END.get(
               END_PRIVATE_KEY_FOOTER, beginLine));
        }

        return null;
      }

      final String trimmedLine = line.trim();
      if (trimmedLine.isEmpty() || trimmedLine.startsWith("#"))
      {
        continue;
      }

      final String upperLine = StaticUtils.toUpperCase(trimmedLine);
      if (BEGIN_PRIVATE_KEY_HEADER.equals(upperLine) ||
           BEGIN_RSA_PRIVATE_KEY_HEADER.equals(upperLine))
      {
        if (beginLine != null)
        {
          throw new CertException(ERR_PKCS8_PEM_READER_REPEATED_BEGIN.get(
               upperLine));
        }
        else
        {
          beginLine = upperLine;
        }
      }
      else if (END_PRIVATE_KEY_FOOTER.equals(upperLine) ||
           END_RSA_PRIVATE_KEY_FOOTER.equals(upperLine))
      {
        if (beginLine == null)
        {
          throw new CertException(ERR_PKCS8_PEM_READER_END_WITHOUT_BEGIN.get(
               upperLine, beginLine));
        }
        else if (base64Buffer.length() == 0)
        {
          throw new CertException(ERR_PKCS8_PEM_READER_END_WITHOUT_DATA.get(
               upperLine, beginLine));
        }
        else
        {
          final byte[] pkcs8Bytes;
          try
          {
            pkcs8Bytes = Base64.decode(base64Buffer.toString());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_PKCS8_PEM_READER_CANNOT_BASE64_DECODE.get(), e);
          }

          return new PKCS8PrivateKey(pkcs8Bytes);
        }
      }
      else
      {
        if (beginLine == null)
        {
          throw new CertException(ERR_PKCS8_PEM_READER_DATA_WITHOUT_BEGIN.get(
               BEGIN_PRIVATE_KEY_HEADER));
        }

        base64Buffer.append(trimmedLine);
      }
    }
  }



  /**
   * Closes this PKCS #8 PEM file reader.
   *
   * @throws  IOException  If a problem is encountered while attempting to close
   *                       the reader.
   */
  @Override()
  public void close()
         throws IOException
  {
    reader.close();
  }
}
