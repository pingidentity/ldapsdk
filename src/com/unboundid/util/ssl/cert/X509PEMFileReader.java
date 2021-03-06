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
 * This class provides a mechanism for reading PEM-encoded X.509 certificates
 * from a specified file.  The PEM file may contain zero or more certificates.
 * Each certificate should consist of the following:
 * <UL>
 *   <LI>A line containing only the string "-----BEGIN CERTIFICATE-----".</LI>
 *   <LI>One or more lines representing the base64-encoded representation of the
 *       bytes that comprise the X.509 certificate.</LI>
 *   <LI>A line containing only the string "-----END CERTIFICATE-----".</LI>
 * </UL>
 * <BR><BR>
 * Any spaces that appear at the beginning or end of each line will be ignored.
 * Empty lines and lines that start with the octothorpe (#) character will also
 * be ignored.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class X509PEMFileReader
       implements Closeable
{
  /**
   * The header string that should appear on a line by itself before the
   * base64-encoded representation of the bytes that comprise an X.509
   * certificate.
   */
  @NotNull public static final String BEGIN_CERTIFICATE_HEADER =
       "-----BEGIN CERTIFICATE-----";



  /**
   * The footer string that should appear on a line by itself after the
   * base64-encoded representation of the bytes that comprise an X.509
   * certificate.
   */
  @NotNull public static final String END_CERTIFICATE_FOOTER =
       "-----END CERTIFICATE-----";



  // The reader that will be used to consume data from the PEM file.
  @NotNull private final BufferedReader reader;



  /**
   * Creates a new X.509 PEM file reader that will read certificate information
   * from the specified file.
   *
   * @param  pemFilePath  The path to the PEM file from which the certificates
   *                      should be read.  This must not be {@code null} and the
   *                      file must exist.
   *
   * @throws  IOException  If a problem occurs while attempting to open the file
   *                       for reading.
   */
  public X509PEMFileReader(@NotNull final String pemFilePath)
         throws IOException
  {
    this(new File(pemFilePath));
  }



  /**
   * Creates a new X.509 PEM file reader that will read certificate information
   * from the specified file.
   *
   * @param  pemFile  The PEM file from which the certificates should be read.
   *                  This must not be {@code null} and the file must
   *                  exist.
   *
   * @throws  IOException  If a problem occurs while attempting to open the file
   *                       for reading.
   */
  public X509PEMFileReader(@NotNull final File pemFile)
         throws IOException
  {
    this(new FileInputStream(pemFile));
  }



  /**
   * Creates a new X.509 PEM file reader that will read certificate information
   * from the provided input stream.
   *
   * @param  inputStream  The input stream from which the certificates should
   *                      be read.  This must not be {@code null} and it must be
   *                      open for reading.
   */
  public X509PEMFileReader(@NotNull final InputStream inputStream)
  {
    reader = new BufferedReader(new InputStreamReader(inputStream));
  }



  /**
   * Reads the next certificate from the PEM file.
   *
   * @return  The certificate that was read, or {@code null} if the end of the
   *          file has been reached.
   *
   * @throws  IOException  If a problem occurs while trying to read data from
   *                       the PEM file.
   *
   * @throws  CertException  If a problem occurs while trying to interpret data
   *                         read from the PEM file as an X.509 certificate.
   */
  @Nullable()
  public X509Certificate readCertificate()
         throws IOException, CertException
  {
    boolean beginFound = false;
    final StringBuilder base64Buffer = new StringBuilder();

    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        // We hit the end of the file.  If we read a begin header, then that's
        // an error.
        if (beginFound)
        {
          throw new CertException(ERR_X509_PEM_READER_EOF_WITHOUT_END.get(
               END_CERTIFICATE_FOOTER, BEGIN_CERTIFICATE_HEADER));
        }

        return null;
      }

      final String trimmedLine = line.trim();
      if (trimmedLine.isEmpty() || trimmedLine.startsWith("#"))
      {
        continue;
      }

      final String upperLine = StaticUtils.toUpperCase(trimmedLine);
      if (BEGIN_CERTIFICATE_HEADER.equals(upperLine))
      {
        if (beginFound)
        {
          throw new CertException(ERR_X509_PEM_READER_REPEATED_BEGIN.get(
               BEGIN_CERTIFICATE_HEADER));
        }
        else
        {
          beginFound = true;
        }
      }
      else if (END_CERTIFICATE_FOOTER.equals(upperLine))
      {
        if (! beginFound)
        {
          throw new CertException(ERR_X509_PEM_READER_END_WITHOUT_BEGIN.get(
               END_CERTIFICATE_FOOTER, BEGIN_CERTIFICATE_HEADER));
        }
        else if (base64Buffer.length() == 0)
        {
          throw new CertException(ERR_X509_PEM_READER_END_WITHOUT_DATA.get(
               END_CERTIFICATE_FOOTER, BEGIN_CERTIFICATE_HEADER));
        }
        else
        {
          final byte[] x509Bytes;
          try
          {
            x509Bytes = Base64.decode(base64Buffer.toString());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_X509_PEM_READER_CANNOT_BASE64_DECODE.get(), e);
          }

          return new X509Certificate(x509Bytes);
        }
      }
      else
      {
        if (! beginFound)
        {
          throw new CertException(ERR_X509_PEM_READER_DATA_WITHOUT_BEGIN.get(
               BEGIN_CERTIFICATE_HEADER));
        }

        base64Buffer.append(trimmedLine);
      }
    }
  }



  /**
   * Closes this X.509 PEM file reader.
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
