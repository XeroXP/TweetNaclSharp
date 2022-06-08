namespace TweetNaclSharp
{
    internal class Poly1305
    {
        private byte[] buffer;
        private ushort[] r;
        private ushort[] h;
        private ushort[] pad;
        private int leftover;
        private int fin;

        public Poly1305(byte[] key)
        {
            buffer = new byte[16];
            r = new ushort[10];
            h = new ushort[10];
            pad = new ushort[8];
            leftover = 0;
            fin = 0;

            var t0 = key[0] & 0xff | (key[1] & 0xff) << 8;
            r[0] = (ushort)(t0 & 0x1fff);
            var t1 = key[2] & 0xff | (key[3] & 0xff) << 8;
            r[1] = (ushort)((t0 >> 13 | t1 << 3) & 0x1fff);
            var t2 = key[4] & 0xff | (key[5] & 0xff) << 8;
            r[2] = (ushort)((t1 >> 10 | t2 << 6) & 0x1f03);
            var t3 = key[6] & 0xff | (key[7] & 0xff) << 8;
            r[3] = (ushort)((t2 >> 7 | t3 << 9) & 0x1fff);
            var t4 = key[8] & 0xff | (key[9] & 0xff) << 8;
            r[4] = (ushort)((t3 >> 4 | t4 << 12) & 0x00ff);
            r[5] = (ushort)(t4 >> 1 & 0x1ffe);
            var t5 = key[10] & 0xff | (key[11] & 0xff) << 8;
            r[6] = (ushort)((t4 >> 14 | t5 << 2) & 0x1fff);
            var t6 = key[12] & 0xff | (key[13] & 0xff) << 8;
            r[7] = (ushort)((t5 >> 11 | t6 << 5) & 0x1f81);
            var t7 = key[14] & 0xff | (key[15] & 0xff) << 8;
            r[8] = (ushort)((t6 >> 8 | t7 << 8) & 0x1fff);
            r[9] = (ushort)(t7 >> 5 & 0x007f);

            pad[0] = (ushort)(key[16] & 0xff | (key[17] & 0xff) << 8);
            pad[1] = (ushort)(key[18] & 0xff | (key[19] & 0xff) << 8);
            pad[2] = (ushort)(key[20] & 0xff | (key[21] & 0xff) << 8);
            pad[3] = (ushort)(key[22] & 0xff | (key[23] & 0xff) << 8);
            pad[4] = (ushort)(key[24] & 0xff | (key[25] & 0xff) << 8);
            pad[5] = (ushort)(key[26] & 0xff | (key[27] & 0xff) << 8);
            pad[6] = (ushort)(key[28] & 0xff | (key[29] & 0xff) << 8);
            pad[7] = (ushort)(key[30] & 0xff | (key[31] & 0xff) << 8);
        }

        public void Blocks(byte[] m, int mpos, int bytes)
        {
            var hibit = fin != 0 ? 0 : 1 << 11;
            int t0, t1, t2, t3, t4, t5, t6, t7, c;
            int d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

            ushort h0 = h[0],
                h1 = h[1],
                h2 = h[2],
                h3 = h[3],
                h4 = h[4],
                h5 = h[5],
                h6 = h[6],
                h7 = h[7],
                h8 = h[8],
                h9 = h[9];

            ushort r0 = r[0],
                r1 = r[1],
                r2 = r[2],
                r3 = r[3],
                r4 = r[4],
                r5 = r[5],
                r6 = r[6],
                r7 = r[7],
                r8 = r[8],
                r9 = r[9];

            while (bytes >= 16)
            {
                t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8;
                h0 += (ushort)(t0 & 0x1fff);
                t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8;
                h1 += (ushort)((t0 >> 13 | t1 << 3) & 0x1fff);
                t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8;
                h2 += (ushort)((t1 >> 10 | t2 << 6) & 0x1fff);
                t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8;
                h3 += (ushort)((t2 >> 7 | t3 << 9) & 0x1fff);
                t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8;
                h4 += (ushort)((t3 >> 4 | t4 << 12) & 0x1fff);
                h5 += (ushort)(t4 >> 1 & 0x1fff);
                t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8;
                h6 += (ushort)((t4 >> 14 | t5 << 2) & 0x1fff);
                t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8;
                h7 += (ushort)((t5 >> 11 | t6 << 5) & 0x1fff);
                t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8;
                h8 += (ushort)((t6 >> 8 | t7 << 8) & 0x1fff);
                h9 += (ushort)(t7 >> 5 | hibit);

                c = 0;

                d0 = c;
                d0 += h0 * r0;
                d0 += h1 * (5 * r9);
                d0 += h2 * (5 * r8);
                d0 += h3 * (5 * r7);
                d0 += h4 * (5 * r6);
                c = d0 >> 13; d0 &= 0x1fff;
                d0 += h5 * (5 * r5);
                d0 += h6 * (5 * r4);
                d0 += h7 * (5 * r3);
                d0 += h8 * (5 * r2);
                d0 += h9 * (5 * r1);
                c += d0 >> 13; d0 &= 0x1fff;

                d1 = c;
                d1 += h0 * r1;
                d1 += h1 * r0;
                d1 += h2 * (5 * r9);
                d1 += h3 * (5 * r8);
                d1 += h4 * (5 * r7);
                c = d1 >> 13; d1 &= 0x1fff;
                d1 += h5 * (5 * r6);
                d1 += h6 * (5 * r5);
                d1 += h7 * (5 * r4);
                d1 += h8 * (5 * r3);
                d1 += h9 * (5 * r2);
                c += d1 >> 13; d1 &= 0x1fff;

                d2 = c;
                d2 += h0 * r2;
                d2 += h1 * r1;
                d2 += h2 * r0;
                d2 += h3 * (5 * r9);
                d2 += h4 * (5 * r8);
                c = d2 >> 13; d2 &= 0x1fff;
                d2 += h5 * (5 * r7);
                d2 += h6 * (5 * r6);
                d2 += h7 * (5 * r5);
                d2 += h8 * (5 * r4);
                d2 += h9 * (5 * r3);
                c += d2 >> 13; d2 &= 0x1fff;

                d3 = c;
                d3 += h0 * r3;
                d3 += h1 * r2;
                d3 += h2 * r1;
                d3 += h3 * r0;
                d3 += h4 * (5 * r9);
                c = d3 >> 13; d3 &= 0x1fff;
                d3 += h5 * (5 * r8);
                d3 += h6 * (5 * r7);
                d3 += h7 * (5 * r6);
                d3 += h8 * (5 * r5);
                d3 += h9 * (5 * r4);
                c += d3 >> 13; d3 &= 0x1fff;

                d4 = c;
                d4 += h0 * r4;
                d4 += h1 * r3;
                d4 += h2 * r2;
                d4 += h3 * r1;
                d4 += h4 * r0;
                c = d4 >> 13; d4 &= 0x1fff;
                d4 += h5 * (5 * r9);
                d4 += h6 * (5 * r8);
                d4 += h7 * (5 * r7);
                d4 += h8 * (5 * r6);
                d4 += h9 * (5 * r5);
                c += d4 >> 13; d4 &= 0x1fff;

                d5 = c;
                d5 += h0 * r5;
                d5 += h1 * r4;
                d5 += h2 * r3;
                d5 += h3 * r2;
                d5 += h4 * r1;
                c = d5 >> 13; d5 &= 0x1fff;
                d5 += h5 * r0;
                d5 += h6 * (5 * r9);
                d5 += h7 * (5 * r8);
                d5 += h8 * (5 * r7);
                d5 += h9 * (5 * r6);
                c += d5 >> 13; d5 &= 0x1fff;

                d6 = c;
                d6 += h0 * r6;
                d6 += h1 * r5;
                d6 += h2 * r4;
                d6 += h3 * r3;
                d6 += h4 * r2;
                c = d6 >> 13; d6 &= 0x1fff;
                d6 += h5 * r1;
                d6 += h6 * r0;
                d6 += h7 * (5 * r9);
                d6 += h8 * (5 * r8);
                d6 += h9 * (5 * r7);
                c += d6 >> 13; d6 &= 0x1fff;

                d7 = c;
                d7 += h0 * r7;
                d7 += h1 * r6;
                d7 += h2 * r5;
                d7 += h3 * r4;
                d7 += h4 * r3;
                c = d7 >> 13; d7 &= 0x1fff;
                d7 += h5 * r2;
                d7 += h6 * r1;
                d7 += h7 * r0;
                d7 += h8 * (5 * r9);
                d7 += h9 * (5 * r8);
                c += d7 >> 13; d7 &= 0x1fff;

                d8 = c;
                d8 += h0 * r8;
                d8 += h1 * r7;
                d8 += h2 * r6;
                d8 += h3 * r5;
                d8 += h4 * r4;
                c = d8 >> 13; d8 &= 0x1fff;
                d8 += h5 * r3;
                d8 += h6 * r2;
                d8 += h7 * r1;
                d8 += h8 * r0;
                d8 += h9 * (5 * r9);
                c += d8 >> 13; d8 &= 0x1fff;

                d9 = c;
                d9 += h0 * r9;
                d9 += h1 * r8;
                d9 += h2 * r7;
                d9 += h3 * r6;
                d9 += h4 * r5;
                c = d9 >> 13; d9 &= 0x1fff;
                d9 += h5 * r4;
                d9 += h6 * r3;
                d9 += h7 * r2;
                d9 += h8 * r1;
                d9 += h9 * r0;
                c += d9 >> 13; d9 &= 0x1fff;

                c = (c << 2) + c | 0;
                c = c + d0 | 0;
                d0 = c & 0x1fff;
                c = c >> 13;
                d1 += c;

                h0 = (ushort)d0;
                h1 = (ushort)d1;
                h2 = (ushort)d2;
                h3 = (ushort)d3;
                h4 = (ushort)d4;
                h5 = (ushort)d5;
                h6 = (ushort)d6;
                h7 = (ushort)d7;
                h8 = (ushort)d8;
                h9 = (ushort)d9;

                mpos += 16;
                bytes -= 16;
            }
            h[0] = h0;
            h[1] = h1;
            h[2] = h2;
            h[3] = h3;
            h[4] = h4;
            h[5] = h5;
            h[6] = h6;
            h[7] = h7;
            h[8] = h8;
            h[9] = h9;
        }

        public void Finish(byte[] mac, int macpos)
        {
            var g = new ushort[10];
            int c, mask, f, i;

            if (leftover != 0)
            {
                i = leftover;
                buffer[i++] = 1;
                for (; i < 16; i++) buffer[i] = 0;
                fin = 1;
                Blocks(buffer, 0, 16);
            }

            c = h[1] >> 13;
            h[1] &= 0x1fff;
            for (i = 2; i < 10; i++)
            {
                h[i] = (ushort)(h[i] + c);
                c = h[i] >> 13;
                h[i] &= 0x1fff;
            }
            h[0] = (ushort)(h[0] + c * 5);
            c = h[0] >> 13;
            h[0] &= 0x1fff;
            h[1] = (ushort)(h[1] + c);
            c = h[1] >> 13;
            h[1] &= 0x1fff;
            h[2] = (ushort)(h[2] + c);

            g[0] = (ushort)(h[0] + 5);
            c = g[0] >> 13;
            g[0] &= 0x1fff;
            for (i = 1; i < 10; i++)
            {
                g[i] = (ushort)(h[i] + c);
                c = g[i] >> 13;
                g[i] &= 0x1fff;
            }
            g[9] -= 1 << 13;

            mask = (c ^ 1) - 1;
            for (i = 0; i < 10; i++) g[i] &= (ushort)mask;
            mask = ~mask;
            for (i = 0; i < 10; i++) h[i] = (ushort)(h[i] & mask | g[i]);

            h[0] = (ushort)((h[0] | h[1] << 13) & 0xffff);
            h[1] = (ushort)((h[1] >> 3 | h[2] << 10) & 0xffff);
            h[2] = (ushort)((h[2] >> 6 | h[3] << 7) & 0xffff);
            h[3] = (ushort)((h[3] >> 9 | h[4] << 4) & 0xffff);
            h[4] = (ushort)((h[4] >> 12 | h[5] << 1 | h[6] << 14) & 0xffff);
            h[5] = (ushort)((h[6] >> 2 | h[7] << 11) & 0xffff);
            h[6] = (ushort)((h[7] >> 5 | h[8] << 8) & 0xffff);
            h[7] = (ushort)((h[8] >> 8 | h[9] << 5) & 0xffff);

            f = h[0] + pad[0];
            h[0] = (ushort)(f & 0xffff);
            for (i = 1; i < 8; i++)
            {
                f = (h[i] + pad[i] | 0) + (f >> 16) | 0;
                h[i] = (ushort)(f & 0xffff);
            }

            mac[macpos + 0] = (byte)(h[0] >> 0 & 0xff);
            mac[macpos + 1] = (byte)(h[0] >> 8 & 0xff);
            mac[macpos + 2] = (byte)(h[1] >> 0 & 0xff);
            mac[macpos + 3] = (byte)(h[1] >> 8 & 0xff);
            mac[macpos + 4] = (byte)(h[2] >> 0 & 0xff);
            mac[macpos + 5] = (byte)(h[2] >> 8 & 0xff);
            mac[macpos + 6] = (byte)(h[3] >> 0 & 0xff);
            mac[macpos + 7] = (byte)(h[3] >> 8 & 0xff);
            mac[macpos + 8] = (byte)(h[4] >> 0 & 0xff);
            mac[macpos + 9] = (byte)(h[4] >> 8 & 0xff);
            mac[macpos + 10] = (byte)(h[5] >> 0 & 0xff);
            mac[macpos + 11] = (byte)(h[5] >> 8 & 0xff);
            mac[macpos + 12] = (byte)(h[6] >> 0 & 0xff);
            mac[macpos + 13] = (byte)(h[6] >> 8 & 0xff);
            mac[macpos + 14] = (byte)(h[7] >> 0 & 0xff);
            mac[macpos + 15] = (byte)(h[7] >> 8 & 0xff);
        }

        public void Update(byte[] m, int mpos, int bytes)
        {
            int i, want;

            if (leftover != 0)
            {
                want = 16 - leftover;
                if (want > bytes)
                    want = bytes;
                for (i = 0; i < want; i++)
                    buffer[leftover + i] = m[mpos + i];
                bytes -= want;
                mpos += want;
                leftover += want;
                if (leftover < 16)
                    return;
                Blocks(buffer, 0, 16);
                leftover = 0;
            }

            if (bytes >= 16)
            {
                want = bytes - bytes % 16;
                Blocks(m, mpos, want);
                mpos += want;
                bytes -= want;
            }

            if (bytes != 0)
            {
                for (i = 0; i < bytes; i++)
                    buffer[leftover + i] = m[mpos + i];
                leftover += bytes;
            }
        }
    }
}
