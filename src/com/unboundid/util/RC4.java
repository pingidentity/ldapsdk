/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
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
 * Copyright (C) 2007-2022 Ping Identity Corporation
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

public class RC4 {

    byte[] s;
    int i, j;

    public RC4()
    {
    }
    public RC4(byte[] key)
    {
        init(key, 0, key.length);
    }

    public void init(byte[] key, int ki, int klen)
    {
        s = new byte[256];

        for (i = 0; i < 256; i++)
            s[i] = (byte)i;

        for (i = j = 0; i < 256; i++) {
            j = (j + key[ki + i % klen] + s[i]) & 0xff;
            byte t = s[i];
            s[i] = s[j];
            s[j] = t;
        }

        i = j = 0;
    }
    public void update(byte[] src, int soff, int slen, byte[] dst, int doff)
    {
        int slim;

        slim = soff + slen;
        while (soff < slim) {
            i = (i + 1) & 0xff;
            j = (j + s[i]) & 0xff;
            byte t = s[i];
            s[i] = s[j];
            s[j] = t;
            dst[doff++] = (byte)(src[soff++] ^ s[(s[i] + s[j]) & 0xff]);
        }
    }
}