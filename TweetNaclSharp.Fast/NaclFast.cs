using System.Security.Cryptography;
using System.Text;
using TweetNaclSharp.Core;
using TweetNaclSharp.Core.Extensions;

namespace TweetNaclSharp
{
    public class NaclFast
    {
        #region Low Level
        private static long[] Gf(long[]? init = null)
        {
            var r = new long[16];
            if (init != null) for (var i = 0; i < init.Length; i++) r[i] = init[i];
            return r;
        }

        private static Action<byte[], int> randomBytes = (byte[] d, int n) =>
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(d, 0, n);
            }
        };

        private static readonly byte[] _0 = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static readonly byte[] _9 = new byte[32] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static readonly long[] gf0 = Gf(),
            gf1 = Gf(new long[] { 1 }),
            _121665 = Gf(new long[] { 0xdb41, 1 }),
            D = Gf(new long[] { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 }),
            D2 = Gf(new long[] { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 }),
            X = Gf(new long[] { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 }),
            Y = Gf(new long[] { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 }),
            I = Gf(new long[] { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 });

        private static void Ts64(byte[] x, int i, uint h, uint l)
        {
            x[i] = (byte)((h >> 24) & 0xff);
            x[i + 1] = (byte)((h >> 16) & 0xff);
            x[i + 2] = (byte)((h >> 8) & 0xff);
            x[i + 3] = (byte)(h & 0xff);
            x[i + 4] = (byte)((l >> 24) & 0xff);
            x[i + 5] = (byte)((l >> 16) & 0xff);
            x[i + 6] = (byte)((l >> 8) & 0xff);
            x[i + 7] = (byte)(l & 0xff);
        }

        private static int Vn(byte[] x, uint xi, byte[] y, uint yi, uint n)
        {
            int i, d = 0;
            for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
            return (1 & ((d - 1) >> 8)) - 1;
        }

        private static int CryptoVerify16(byte[] x, uint xi, byte[] y, uint yi)
        {
            return Vn(x, xi, y, yi, 16);
        }

        private static int CryptoVerify32(byte[] x, uint xi, byte[] y, uint yi)
        {
            return Vn(x, xi, y, yi, 32);
        }

        private static void CoreSalsa20(byte[] o, byte[] p, byte[] k, byte[] c)
        {
            uint j0 = (uint)(c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24),
                j1 = (uint)(k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24),
                j2 = (uint)(k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24),
                j3 = (uint)(k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24),
                j4 = (uint)(k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24),
                j5 = (uint)(c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24),
                j6 = (uint)(p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24),
                j7 = (uint)(p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24),
                j8 = (uint)(p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24),
                j9 = (uint)(p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24),
                j10 = (uint)(c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24),
                j11 = (uint)(k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24),
                j12 = (uint)(k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24),
                j13 = (uint)(k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24),
                j14 = (uint)(k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24),
                j15 = (uint)(c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24);

            uint x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
                x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
                x15 = j15, u;

            for (var i = 0; i < 20; i += 2)
            {
                u = x0 + x12 | 0;
                x4 ^= u << 7 | u >> (32 - 7);
                u = x4 + x0 | 0;
                x8 ^= u << 9 | u >> (32 - 9);
                u = x8 + x4 | 0;
                x12 ^= u << 13 | u >> (32 - 13);
                u = x12 + x8 | 0;
                x0 ^= u << 18 | u >> (32 - 18);

                u = x5 + x1 | 0;
                x9 ^= u << 7 | u >> (32 - 7);
                u = x9 + x5 | 0;
                x13 ^= u << 9 | u >> (32 - 9);
                u = x13 + x9 | 0;
                x1 ^= u << 13 | u >> (32 - 13);
                u = x1 + x13 | 0;
                x5 ^= u << 18 | u >> (32 - 18);

                u = x10 + x6 | 0;
                x14 ^= u << 7 | u >> (32 - 7);
                u = x14 + x10 | 0;
                x2 ^= u << 9 | u >> (32 - 9);
                u = x2 + x14 | 0;
                x6 ^= u << 13 | u >> (32 - 13);
                u = x6 + x2 | 0;
                x10 ^= u << 18 | u >> (32 - 18);

                u = x15 + x11 | 0;
                x3 ^= u << 7 | u >> (32 - 7);
                u = x3 + x15 | 0;
                x7 ^= u << 9 | u >> (32 - 9);
                u = x7 + x3 | 0;
                x11 ^= u << 13 | u >> (32 - 13);
                u = x11 + x7 | 0;
                x15 ^= u << 18 | u >> (32 - 18);

                u = x0 + x3 | 0;
                x1 ^= u << 7 | u >> (32 - 7);
                u = x1 + x0 | 0;
                x2 ^= u << 9 | u >> (32 - 9);
                u = x2 + x1 | 0;
                x3 ^= u << 13 | u >> (32 - 13);
                u = x3 + x2 | 0;
                x0 ^= u << 18 | u >> (32 - 18);

                u = x5 + x4 | 0;
                x6 ^= u << 7 | u >> (32 - 7);
                u = x6 + x5 | 0;
                x7 ^= u << 9 | u >> (32 - 9);
                u = x7 + x6 | 0;
                x4 ^= u << 13 | u >> (32 - 13);
                u = x4 + x7 | 0;
                x5 ^= u << 18 | u >> (32 - 18);

                u = x10 + x9 | 0;
                x11 ^= u << 7 | u >> (32 - 7);
                u = x11 + x10 | 0;
                x8 ^= u << 9 | u >> (32 - 9);
                u = x8 + x11 | 0;
                x9 ^= u << 13 | u >> (32 - 13);
                u = x9 + x8 | 0;
                x10 ^= u << 18 | u >> (32 - 18);

                u = x15 + x14 | 0;
                x12 ^= u << 7 | u >> (32 - 7);
                u = x12 + x15 | 0;
                x13 ^= u << 9 | u >> (32 - 9);
                u = x13 + x12 | 0;
                x14 ^= u << 13 | u >> (32 - 13);
                u = x14 + x13 | 0;
                x15 ^= u << 18 | u >> (32 - 18);
            }
            x0 = x0 + j0 | 0;
            x1 = x1 + j1 | 0;
            x2 = x2 + j2 | 0;
            x3 = x3 + j3 | 0;
            x4 = x4 + j4 | 0;
            x5 = x5 + j5 | 0;
            x6 = x6 + j6 | 0;
            x7 = x7 + j7 | 0;
            x8 = x8 + j8 | 0;
            x9 = x9 + j9 | 0;
            x10 = x10 + j10 | 0;
            x11 = x11 + j11 | 0;
            x12 = x12 + j12 | 0;
            x13 = x13 + j13 | 0;
            x14 = x14 + j14 | 0;
            x15 = x15 + j15 | 0;

            o[0] = (byte)(x0 >> 0 & 0xff);
            o[1] = (byte)(x0 >> 8 & 0xff);
            o[2] = (byte)(x0 >> 16 & 0xff);
            o[3] = (byte)(x0 >> 24 & 0xff);

            o[4] = (byte)(x1 >> 0 & 0xff);
            o[5] = (byte)(x1 >> 8 & 0xff);
            o[6] = (byte)(x1 >> 16 & 0xff);
            o[7] = (byte)(x1 >> 24 & 0xff);

            o[8] = (byte)(x2 >> 0 & 0xff);
            o[9] = (byte)(x2 >> 8 & 0xff);
            o[10] = (byte)(x2 >> 16 & 0xff);
            o[11] = (byte)(x2 >> 24 & 0xff);

            o[12] = (byte)(x3 >> 0 & 0xff);
            o[13] = (byte)(x3 >> 8 & 0xff);
            o[14] = (byte)(x3 >> 16 & 0xff);
            o[15] = (byte)(x3 >> 24 & 0xff);

            o[16] = (byte)(x4 >> 0 & 0xff);
            o[17] = (byte)(x4 >> 8 & 0xff);
            o[18] = (byte)(x4 >> 16 & 0xff);
            o[19] = (byte)(x4 >> 24 & 0xff);

            o[20] = (byte)(x5 >> 0 & 0xff);
            o[21] = (byte)(x5 >> 8 & 0xff);
            o[22] = (byte)(x5 >> 16 & 0xff);
            o[23] = (byte)(x5 >> 24 & 0xff);

            o[24] = (byte)(x6 >> 0 & 0xff);
            o[25] = (byte)(x6 >> 8 & 0xff);
            o[26] = (byte)(x6 >> 16 & 0xff);
            o[27] = (byte)(x6 >> 24 & 0xff);

            o[28] = (byte)(x7 >> 0 & 0xff);
            o[29] = (byte)(x7 >> 8 & 0xff);
            o[30] = (byte)(x7 >> 16 & 0xff);
            o[31] = (byte)(x7 >> 24 & 0xff);

            o[32] = (byte)(x8 >> 0 & 0xff);
            o[33] = (byte)(x8 >> 8 & 0xff);
            o[34] = (byte)(x8 >> 16 & 0xff);
            o[35] = (byte)(x8 >> 24 & 0xff);

            o[36] = (byte)(x9 >> 0 & 0xff);
            o[37] = (byte)(x9 >> 8 & 0xff);
            o[38] = (byte)(x9 >> 16 & 0xff);
            o[39] = (byte)(x9 >> 24 & 0xff);

            o[40] = (byte)(x10 >> 0 & 0xff);
            o[41] = (byte)(x10 >> 8 & 0xff);
            o[42] = (byte)(x10 >> 16 & 0xff);
            o[43] = (byte)(x10 >> 24 & 0xff);

            o[44] = (byte)(x11 >> 0 & 0xff);
            o[45] = (byte)(x11 >> 8 & 0xff);
            o[46] = (byte)(x11 >> 16 & 0xff);
            o[47] = (byte)(x11 >> 24 & 0xff);

            o[48] = (byte)(x12 >> 0 & 0xff);
            o[49] = (byte)(x12 >> 8 & 0xff);
            o[50] = (byte)(x12 >> 16 & 0xff);
            o[51] = (byte)(x12 >> 24 & 0xff);

            o[52] = (byte)(x13 >> 0 & 0xff);
            o[53] = (byte)(x13 >> 8 & 0xff);
            o[54] = (byte)(x13 >> 16 & 0xff);
            o[55] = (byte)(x13 >> 24 & 0xff);

            o[56] = (byte)(x14 >> 0 & 0xff);
            o[57] = (byte)(x14 >> 8 & 0xff);
            o[58] = (byte)(x14 >> 16 & 0xff);
            o[59] = (byte)(x14 >> 24 & 0xff);

            o[60] = (byte)(x15 >> 0 & 0xff);
            o[61] = (byte)(x15 >> 8 & 0xff);
            o[62] = (byte)(x15 >> 16 & 0xff);
            o[63] = (byte)(x15 >> 24 & 0xff);
        }

        private static void CoreHsalsa20(byte[] o, byte[] p, byte[] k, byte[] c)
        {
            uint j0 = (uint)(c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24),
                j1 = (uint)(k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24),
                j2 = (uint)(k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24),
                j3 = (uint)(k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24),
                j4 = (uint)(k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24),
                j5 = (uint)(c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24),
                j6 = (uint)(p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24),
                j7 = (uint)(p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24),
                j8 = (uint)(p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24),
                j9 = (uint)(p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24),
                j10 = (uint)(c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24),
                j11 = (uint)(k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24),
                j12 = (uint)(k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24),
                j13 = (uint)(k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24),
                j14 = (uint)(k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24),
                j15 = (uint)(c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24);

            uint x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
                x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
                x15 = j15, u;

            for (var i = 0; i < 20; i += 2)
            {
                u = x0 + x12 | 0;
                x4 ^= u << 7 | u >> (32 - 7);
                u = x4 + x0 | 0;
                x8 ^= u << 9 | u >> (32 - 9);
                u = x8 + x4 | 0;
                x12 ^= u << 13 | u >> (32 - 13);
                u = x12 + x8 | 0;
                x0 ^= u << 18 | u >> (32 - 18);

                u = x5 + x1 | 0;
                x9 ^= u << 7 | u >> (32 - 7);
                u = x9 + x5 | 0;
                x13 ^= u << 9 | u >> (32 - 9);
                u = x13 + x9 | 0;
                x1 ^= u << 13 | u >> (32 - 13);
                u = x1 + x13 | 0;
                x5 ^= u << 18 | u >> (32 - 18);

                u = x10 + x6 | 0;
                x14 ^= u << 7 | u >> (32 - 7);
                u = x14 + x10 | 0;
                x2 ^= u << 9 | u >> (32 - 9);
                u = x2 + x14 | 0;
                x6 ^= u << 13 | u >> (32 - 13);
                u = x6 + x2 | 0;
                x10 ^= u << 18 | u >> (32 - 18);

                u = x15 + x11 | 0;
                x3 ^= u << 7 | u >> (32 - 7);
                u = x3 + x15 | 0;
                x7 ^= u << 9 | u >> (32 - 9);
                u = x7 + x3 | 0;
                x11 ^= u << 13 | u >> (32 - 13);
                u = x11 + x7 | 0;
                x15 ^= u << 18 | u >> (32 - 18);

                u = x0 + x3 | 0;
                x1 ^= u << 7 | u >> (32 - 7);
                u = x1 + x0 | 0;
                x2 ^= u << 9 | u >> (32 - 9);
                u = x2 + x1 | 0;
                x3 ^= u << 13 | u >> (32 - 13);
                u = x3 + x2 | 0;
                x0 ^= u << 18 | u >> (32 - 18);

                u = x5 + x4 | 0;
                x6 ^= u << 7 | u >> (32 - 7);
                u = x6 + x5 | 0;
                x7 ^= u << 9 | u >> (32 - 9);
                u = x7 + x6 | 0;
                x4 ^= u << 13 | u >> (32 - 13);
                u = x4 + x7 | 0;
                x5 ^= u << 18 | u >> (32 - 18);

                u = x10 + x9 | 0;
                x11 ^= u << 7 | u >> (32 - 7);
                u = x11 + x10 | 0;
                x8 ^= u << 9 | u >> (32 - 9);
                u = x8 + x11 | 0;
                x9 ^= u << 13 | u >> (32 - 13);
                u = x9 + x8 | 0;
                x10 ^= u << 18 | u >> (32 - 18);

                u = x15 + x14 | 0;
                x12 ^= u << 7 | u >> (32 - 7);
                u = x12 + x15 | 0;
                x13 ^= u << 9 | u >> (32 - 9);
                u = x13 + x12 | 0;
                x14 ^= u << 13 | u >> (32 - 13);
                u = x14 + x13 | 0;
                x15 ^= u << 18 | u >> (32 - 18);
            }

            o[0] = (byte)(x0 >> 0 & 0xff);
            o[1] = (byte)(x0 >> 8 & 0xff);
            o[2] = (byte)(x0 >> 16 & 0xff);
            o[3] = (byte)(x0 >> 24 & 0xff);

            o[4] = (byte)(x5 >> 0 & 0xff);
            o[5] = (byte)(x5 >> 8 & 0xff);
            o[6] = (byte)(x5 >> 16 & 0xff);
            o[7] = (byte)(x5 >> 24 & 0xff);

            o[8] = (byte)(x10 >> 0 & 0xff);
            o[9] = (byte)(x10 >> 8 & 0xff);
            o[10] = (byte)(x10 >> 16 & 0xff);
            o[11] = (byte)(x10 >> 24 & 0xff);

            o[12] = (byte)(x15 >> 0 & 0xff);
            o[13] = (byte)(x15 >> 8 & 0xff);
            o[14] = (byte)(x15 >> 16 & 0xff);
            o[15] = (byte)(x15 >> 24 & 0xff);

            o[16] = (byte)(x6 >> 0 & 0xff);
            o[17] = (byte)(x6 >> 8 & 0xff);
            o[18] = (byte)(x6 >> 16 & 0xff);
            o[19] = (byte)(x6 >> 24 & 0xff);

            o[20] = (byte)(x7 >> 0 & 0xff);
            o[21] = (byte)(x7 >> 8 & 0xff);
            o[22] = (byte)(x7 >> 16 & 0xff);
            o[23] = (byte)(x7 >> 24 & 0xff);

            o[24] = (byte)(x8 >> 0 & 0xff);
            o[25] = (byte)(x8 >> 8 & 0xff);
            o[26] = (byte)(x8 >> 16 & 0xff);
            o[27] = (byte)(x8 >> 24 & 0xff);

            o[28] = (byte)(x9 >> 0 & 0xff);
            o[29] = (byte)(x9 >> 8 & 0xff);
            o[30] = (byte)(x9 >> 16 & 0xff);
            o[31] = (byte)(x9 >> 24 & 0xff);
        }

        private static int CryptoCoreSalsa20(byte[] outp, byte[] inp, byte[] k, byte[] c)
        {
            CoreSalsa20(outp, inp, k, c);
            return 0;
        }

        private static int CryptoCoreHsalsa20(byte[] outp, byte[] inp, byte[] k, byte[] c)
        {
            CoreHsalsa20(outp, inp, k, c);
            return 0;
        }

        private static readonly byte[] Sigma = Encoding.ASCII.GetBytes("expand 32-byte k");

        private static int CryptoStreamSalsa20Xor(byte[] c, uint cpos, byte[] m, uint mpos, long b, byte[] n, byte[] k)
        {
            byte[] z = new byte[16];
            byte[] x = new byte[64];

            uint u = 0;

            for (var i = 0; i < 16; i++)
            {
                z[i] = 0;
            }
            for (var i = 0; i < 8; i++)
            {
                z[i] = n[i];
            }

            while (b >= 64)
            {
                CryptoCoreSalsa20(x, z, k, Sigma);

                for (var i = 0; i < 64; ++i)
                {
                    c[cpos + i] = (byte)(m[mpos + i] ^ x[i]);
                }

                u = 1;
                for (var i = 8; i < 16; i++)
                {
                    u += (z[i] & (uint)0xff) | 0;
                    z[i] = (byte)(u & 0xff);
                    u >>= 8;
                }

                b -= 64;
                cpos += 64;
                mpos += 64;
            }

            if (b > 0)
            {
                CryptoCoreSalsa20(x, z, k, Sigma);

                for (long i = 0; i < b; i++)
                {
                    c[cpos + i] = (byte)(m[mpos + i] ^ x[i]);
                }
            }

            return 0;
        }

        private static int CryptoStreamSalsa20(byte[] c, uint cpos, ulong b, byte[] n, byte[] k)
        {
            byte[] z = new byte[16];
            byte[] x = new byte[64];

            uint u = 0;

            for (var i = 0; i < 16; i++)
            {
                z[i] = 0;
            }
            for (var i = 0; i < 8; i++)
            {
                z[i] = n[i];
            }

            while (b >= 64)
            {
                CryptoCoreSalsa20(x, z, k, Sigma);

                for (var i = 0; i < 64; ++i)
                {
                    c[cpos + i] = x[i];
                }

                u = 1;
                for (var i = 8; i < 16; i++)
                {
                    u += (z[i] & (uint)0xff) | 0;
                    z[i] = (byte)(u & 0xff);
                    u >>= 8;
                }

                b -= 64;
                cpos += 64;
            }

            if (b > 0)
            {
                CryptoCoreSalsa20(x, z, k, Sigma);

                for (ulong i = 0; i < b; i++)
                {
                    c[cpos + i] = x[i];
                }
            }

            return 0;
        }

        private static int CryptoStream(byte[] c, uint cpos, ulong d, byte[] n, byte[] k)
        {
            var s = new byte[32];
            CryptoCoreHsalsa20(s, n, k, Sigma);
            var sn = new byte[8];
            for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
            return CryptoStreamSalsa20(c, cpos, d, sn, s);
        }

        private static int CryptoStreamXor(byte[] c, uint cpos, byte[] m, uint mpos, long d, byte[] n, byte[] k)
        {
            var s = new byte[32];
            CryptoCoreHsalsa20(s, n, k, Sigma);
            var sn = new byte[8];
            for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
            return CryptoStreamSalsa20Xor(c, cpos, m, mpos, d, sn, s);
        }

        public static int CryptoOnetimeauth(byte[] outp, int outpos, byte[] m, int mpos, int n, byte[] k)
        {
            var s = new Poly1305(k);
            s.Update(m, mpos, n);
            s.Finish(outp, outpos);
            return 0;
        }

        private static int CryptoOnetimeauthVerify(byte[] h, uint hpos, byte[] m, int mpos, int n, byte[] k)
        {
            var x = new byte[16];
            CryptoOnetimeauth(x, 0, m, mpos, n, k);
            return CryptoVerify16(h, hpos, x, 0);
        }

        private static int CryptoSecretbox(byte[] c, byte[] m, int d, byte[] n, byte[] k)
        {
            if (d < 32) return -1;
            CryptoStreamXor(c, 0, m, 0, d, n, k);
            CryptoOnetimeauth(c, 16, c, 32, d - 32, c);
            for (var i = 0; i < 16; i++) c[i] = 0;
            return 0;
        }

        private static int CryptoSecretboxOpen(byte[] m, byte[] c, int d, byte[] n, byte[] k)
        {
            var x = new byte[32];
            if (d < 32) return -1;
            CryptoStream(x, 0, 32, n, k);
            if (CryptoOnetimeauthVerify(c, 16, c, 32, d - 32, x) != 0) return -1;
            CryptoStreamXor(m, 0, c, 0, d, n, k);
            for (var i = 0; i < 32; i++) m[i] = 0;
            return 0;
        }

        private static void Set25519(long[] r, long[] a)
        {
            for (var i = 0; i < 16; i++) r[i] = a[i] | 0;
        }

        private static void Car25519(long[] o)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] += 65536;
                long c = (long)Math.Floor((double)o[i] / 65536);
                o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
                o[i] -= c << 16;
            }
        }

        private static void Sel25519(long[] p, long[] q, long b)
        {
            long t, c = ~(b - 1);
            for (var i = 0; i < 16; ++i)
            {
                t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        private static void Pack25519(byte[] o, long[] n)
        {
            long b = 0;
            long[] m = Gf(), t = Gf();

            for (var i = 0; i < 16; i++)
            {
                t[i] = n[i];
            }

            Car25519(t);
            Car25519(t);
            Car25519(t);

            for (var j = 0; j < 2; j++)
            {
                m[0] = t[0] - 0xffed;

                for (var i = 1; i < 15; i++)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }

                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                b = (m[15] >> 16) & 1;
                m[14] &= 0xffff;
                Sel25519(t, m, 1 - b);
            }

            for (var i = 0; i < 16; i++)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        private static int Neq25519(long[] a, long[] b)
        {
            byte[] c = new byte[32], d = new byte[32];
            Pack25519(c, a);
            Pack25519(d, b);
            return CryptoVerify32(c, 0, d, 0);
        }

        private static byte Par25519(long[] a)
        {
            var d = new byte[32];
            Pack25519(d, a);
            return (byte)(d[0] & 1);
        }

        private static void Unpack25519(long[] o, byte[] n)
        {
            for (var i = 0; i < 16; ++i)
            {
                o[i] = (0xff & n[2 * i]) + ((0xffL & n[2 * i + 1]) << 8);
            }

            o[15] &= 0x7fff;
        }

        private static void A(long[] o, long[] a, long[] b)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] = (a[i] + b[i]) | 0;
            }
        }

        private static void Z(long[] o, long[] a, long[] b)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] = (a[i] - b[i]) | 0;
            }
        }

        private static void M(long[] o, long[] a, long[] b)
        {
            long v, c,
                 t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0,
                 t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
                t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
                t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0,
                b0 = b[0],
                b1 = b[1],
                b2 = b[2],
                b3 = b[3],
                b4 = b[4],
                b5 = b[5],
                b6 = b[6],
                b7 = b[7],
                b8 = b[8],
                b9 = b[9],
                b10 = b[10],
                b11 = b[11],
                b12 = b[12],
                b13 = b[13],
                b14 = b[14],
                b15 = b[15];

            v = a[0];
            t0 += v * b0;
            t1 += v * b1;
            t2 += v * b2;
            t3 += v * b3;
            t4 += v * b4;
            t5 += v * b5;
            t6 += v * b6;
            t7 += v * b7;
            t8 += v * b8;
            t9 += v * b9;
            t10 += v * b10;
            t11 += v * b11;
            t12 += v * b12;
            t13 += v * b13;
            t14 += v * b14;
            t15 += v * b15;
            v = a[1];
            t1 += v * b0;
            t2 += v * b1;
            t3 += v * b2;
            t4 += v * b3;
            t5 += v * b4;
            t6 += v * b5;
            t7 += v * b6;
            t8 += v * b7;
            t9 += v * b8;
            t10 += v * b9;
            t11 += v * b10;
            t12 += v * b11;
            t13 += v * b12;
            t14 += v * b13;
            t15 += v * b14;
            t16 += v * b15;
            v = a[2];
            t2 += v * b0;
            t3 += v * b1;
            t4 += v * b2;
            t5 += v * b3;
            t6 += v * b4;
            t7 += v * b5;
            t8 += v * b6;
            t9 += v * b7;
            t10 += v * b8;
            t11 += v * b9;
            t12 += v * b10;
            t13 += v * b11;
            t14 += v * b12;
            t15 += v * b13;
            t16 += v * b14;
            t17 += v * b15;
            v = a[3];
            t3 += v * b0;
            t4 += v * b1;
            t5 += v * b2;
            t6 += v * b3;
            t7 += v * b4;
            t8 += v * b5;
            t9 += v * b6;
            t10 += v * b7;
            t11 += v * b8;
            t12 += v * b9;
            t13 += v * b10;
            t14 += v * b11;
            t15 += v * b12;
            t16 += v * b13;
            t17 += v * b14;
            t18 += v * b15;
            v = a[4];
            t4 += v * b0;
            t5 += v * b1;
            t6 += v * b2;
            t7 += v * b3;
            t8 += v * b4;
            t9 += v * b5;
            t10 += v * b6;
            t11 += v * b7;
            t12 += v * b8;
            t13 += v * b9;
            t14 += v * b10;
            t15 += v * b11;
            t16 += v * b12;
            t17 += v * b13;
            t18 += v * b14;
            t19 += v * b15;
            v = a[5];
            t5 += v * b0;
            t6 += v * b1;
            t7 += v * b2;
            t8 += v * b3;
            t9 += v * b4;
            t10 += v * b5;
            t11 += v * b6;
            t12 += v * b7;
            t13 += v * b8;
            t14 += v * b9;
            t15 += v * b10;
            t16 += v * b11;
            t17 += v * b12;
            t18 += v * b13;
            t19 += v * b14;
            t20 += v * b15;
            v = a[6];
            t6 += v * b0;
            t7 += v * b1;
            t8 += v * b2;
            t9 += v * b3;
            t10 += v * b4;
            t11 += v * b5;
            t12 += v * b6;
            t13 += v * b7;
            t14 += v * b8;
            t15 += v * b9;
            t16 += v * b10;
            t17 += v * b11;
            t18 += v * b12;
            t19 += v * b13;
            t20 += v * b14;
            t21 += v * b15;
            v = a[7];
            t7 += v * b0;
            t8 += v * b1;
            t9 += v * b2;
            t10 += v * b3;
            t11 += v * b4;
            t12 += v * b5;
            t13 += v * b6;
            t14 += v * b7;
            t15 += v * b8;
            t16 += v * b9;
            t17 += v * b10;
            t18 += v * b11;
            t19 += v * b12;
            t20 += v * b13;
            t21 += v * b14;
            t22 += v * b15;
            v = a[8];
            t8 += v * b0;
            t9 += v * b1;
            t10 += v * b2;
            t11 += v * b3;
            t12 += v * b4;
            t13 += v * b5;
            t14 += v * b6;
            t15 += v * b7;
            t16 += v * b8;
            t17 += v * b9;
            t18 += v * b10;
            t19 += v * b11;
            t20 += v * b12;
            t21 += v * b13;
            t22 += v * b14;
            t23 += v * b15;
            v = a[9];
            t9 += v * b0;
            t10 += v * b1;
            t11 += v * b2;
            t12 += v * b3;
            t13 += v * b4;
            t14 += v * b5;
            t15 += v * b6;
            t16 += v * b7;
            t17 += v * b8;
            t18 += v * b9;
            t19 += v * b10;
            t20 += v * b11;
            t21 += v * b12;
            t22 += v * b13;
            t23 += v * b14;
            t24 += v * b15;
            v = a[10];
            t10 += v * b0;
            t11 += v * b1;
            t12 += v * b2;
            t13 += v * b3;
            t14 += v * b4;
            t15 += v * b5;
            t16 += v * b6;
            t17 += v * b7;
            t18 += v * b8;
            t19 += v * b9;
            t20 += v * b10;
            t21 += v * b11;
            t22 += v * b12;
            t23 += v * b13;
            t24 += v * b14;
            t25 += v * b15;
            v = a[11];
            t11 += v * b0;
            t12 += v * b1;
            t13 += v * b2;
            t14 += v * b3;
            t15 += v * b4;
            t16 += v * b5;
            t17 += v * b6;
            t18 += v * b7;
            t19 += v * b8;
            t20 += v * b9;
            t21 += v * b10;
            t22 += v * b11;
            t23 += v * b12;
            t24 += v * b13;
            t25 += v * b14;
            t26 += v * b15;
            v = a[12];
            t12 += v * b0;
            t13 += v * b1;
            t14 += v * b2;
            t15 += v * b3;
            t16 += v * b4;
            t17 += v * b5;
            t18 += v * b6;
            t19 += v * b7;
            t20 += v * b8;
            t21 += v * b9;
            t22 += v * b10;
            t23 += v * b11;
            t24 += v * b12;
            t25 += v * b13;
            t26 += v * b14;
            t27 += v * b15;
            v = a[13];
            t13 += v * b0;
            t14 += v * b1;
            t15 += v * b2;
            t16 += v * b3;
            t17 += v * b4;
            t18 += v * b5;
            t19 += v * b6;
            t20 += v * b7;
            t21 += v * b8;
            t22 += v * b9;
            t23 += v * b10;
            t24 += v * b11;
            t25 += v * b12;
            t26 += v * b13;
            t27 += v * b14;
            t28 += v * b15;
            v = a[14];
            t14 += v * b0;
            t15 += v * b1;
            t16 += v * b2;
            t17 += v * b3;
            t18 += v * b4;
            t19 += v * b5;
            t20 += v * b6;
            t21 += v * b7;
            t22 += v * b8;
            t23 += v * b9;
            t24 += v * b10;
            t25 += v * b11;
            t26 += v * b12;
            t27 += v * b13;
            t28 += v * b14;
            t29 += v * b15;
            v = a[15];
            t15 += v * b0;
            t16 += v * b1;
            t17 += v * b2;
            t18 += v * b3;
            t19 += v * b4;
            t20 += v * b5;
            t21 += v * b6;
            t22 += v * b7;
            t23 += v * b8;
            t24 += v * b9;
            t25 += v * b10;
            t26 += v * b11;
            t27 += v * b12;
            t28 += v * b13;
            t29 += v * b14;
            t30 += v * b15;

            t0 += 38 * t16;
            t1 += 38 * t17;
            t2 += 38 * t18;
            t3 += 38 * t19;
            t4 += 38 * t20;
            t5 += 38 * t21;
            t6 += 38 * t22;
            t7 += 38 * t23;
            t8 += 38 * t24;
            t9 += 38 * t25;
            t10 += 38 * t26;
            t11 += 38 * t27;
            t12 += 38 * t28;
            t13 += 38 * t29;
            t14 += 38 * t30;
            // t15 left as is

            // first car
            c = 1;
            v = t0 + c + 65535; c = (long)Math.Floor((double)v / 65536); t0 = v - c * 65536;
            v = t1 + c + 65535; c = (long)Math.Floor((double)v / 65536); t1 = v - c * 65536;
            v = t2 + c + 65535; c = (long)Math.Floor((double)v / 65536); t2 = v - c * 65536;
            v = t3 + c + 65535; c = (long)Math.Floor((double)v / 65536); t3 = v - c * 65536;
            v = t4 + c + 65535; c = (long)Math.Floor((double)v / 65536); t4 = v - c * 65536;
            v = t5 + c + 65535; c = (long)Math.Floor((double)v / 65536); t5 = v - c * 65536;
            v = t6 + c + 65535; c = (long)Math.Floor((double)v / 65536); t6 = v - c * 65536;
            v = t7 + c + 65535; c = (long)Math.Floor((double)v / 65536); t7 = v - c * 65536;
            v = t8 + c + 65535; c = (long)Math.Floor((double)v / 65536); t8 = v - c * 65536;
            v = t9 + c + 65535; c = (long)Math.Floor((double)v / 65536); t9 = v - c * 65536;
            v = t10 + c + 65535; c = (long)Math.Floor((double)v / 65536); t10 = v - c * 65536;
            v = t11 + c + 65535; c = (long)Math.Floor((double)v / 65536); t11 = v - c * 65536;
            v = t12 + c + 65535; c = (long)Math.Floor((double)v / 65536); t12 = v - c * 65536;
            v = t13 + c + 65535; c = (long)Math.Floor((double)v / 65536); t13 = v - c * 65536;
            v = t14 + c + 65535; c = (long)Math.Floor((double)v / 65536); t14 = v - c * 65536;
            v = t15 + c + 65535; c = (long)Math.Floor((double)v / 65536); t15 = v - c * 65536;
            t0 += c - 1 + 37 * (c - 1);

            // second car
            c = 1;
            v = t0 + c + 65535; c = (long)Math.Floor((double)v / 65536); t0 = v - c * 65536;
            v = t1 + c + 65535; c = (long)Math.Floor((double)v / 65536); t1 = v - c * 65536;
            v = t2 + c + 65535; c = (long)Math.Floor((double)v / 65536); t2 = v - c * 65536;
            v = t3 + c + 65535; c = (long)Math.Floor((double)v / 65536); t3 = v - c * 65536;
            v = t4 + c + 65535; c = (long)Math.Floor((double)v / 65536); t4 = v - c * 65536;
            v = t5 + c + 65535; c = (long)Math.Floor((double)v / 65536); t5 = v - c * 65536;
            v = t6 + c + 65535; c = (long)Math.Floor((double)v / 65536); t6 = v - c * 65536;
            v = t7 + c + 65535; c = (long)Math.Floor((double)v / 65536); t7 = v - c * 65536;
            v = t8 + c + 65535; c = (long)Math.Floor((double)v / 65536); t8 = v - c * 65536;
            v = t9 + c + 65535; c = (long)Math.Floor((double)v / 65536); t9 = v - c * 65536;
            v = t10 + c + 65535; c = (long)Math.Floor((double)v / 65536); t10 = v - c * 65536;
            v = t11 + c + 65535; c = (long)Math.Floor((double)v / 65536); t11 = v - c * 65536;
            v = t12 + c + 65535; c = (long)Math.Floor((double)v / 65536); t12 = v - c * 65536;
            v = t13 + c + 65535; c = (long)Math.Floor((double)v / 65536); t13 = v - c * 65536;
            v = t14 + c + 65535; c = (long)Math.Floor((double)v / 65536); t14 = v - c * 65536;
            v = t15 + c + 65535; c = (long)Math.Floor((double)v / 65536); t15 = v - c * 65536;
            t0 += c - 1 + 37 * (c - 1);

            o[0] = t0;
            o[1] = t1;
            o[2] = t2;
            o[3] = t3;
            o[4] = t4;
            o[5] = t5;
            o[6] = t6;
            o[7] = t7;
            o[8] = t8;
            o[9] = t9;
            o[10] = t10;
            o[11] = t11;
            o[12] = t12;
            o[13] = t13;
            o[14] = t14;
            o[15] = t15;
        }

        private static void S(long[] o, long[] a)
        {
            M(o, a, a);
        }

        private static void Inv25519(long[] o, long[] i)
        {
            long[] c = Gf();

            for (var a = 0; a < 16; a++)
            {
                c[a] = i[a];
            }

            for (var a = 253; a >= 0; a--)
            {
                S(c, c);
                if (a != 2 && a != 4)
                {
                    M(c, c, i);
                }
            }

            for (var a = 0; a < 16; a++)
            {
                o[a] = c[a];
            }
        }

        private static void Pow2523(long[] o, long[] i)
        {
            var c = Gf();
            for (var a = 0; a < 16; a++) c[a] = i[a];
            for (var a = 250; a >= 0; a--)
            {
                S(c, c);
                if (a != 1) M(c, c, i);
            }
            for (var a = 0; a < 16; a++) o[a] = c[a];
        }

        private static int CryptoScalarmult(byte[] q, byte[] n, byte[] p)
        {
            byte[] z = new byte[32];
            long[] x = new long[80];
            long[] a = Gf(),
                b = Gf(),
                c = Gf(),
                d = Gf(),
                e = Gf(),
                f = Gf();

            long r = 0;

            for (var i = 0; i < 31; i++)
            {
                z[i] = n[i];
            }

            z[31] = (byte)((n[31] & 127) | 64);
            z[0] &= 248;

            Unpack25519(x, p);

            for (var i = 0; i < 16; i++)
            {
                b[i] = x[i];
                d[i] = a[i] = c[i] = 0;
            }

            a[0] = d[0] = 1;

            for (var i = 254; i >= 0; --i)
            {
                r = (z[i >> 3] >> (i & 7)) & 1;
                Sel25519(a, b, r);
                Sel25519(c, d, r);
                A(e, a, c);
                Z(a, a, c);
                A(c, b, d);
                Z(b, b, d);
                S(d, e);
                S(f, a);
                M(a, c, a);
                M(c, b, e);
                A(e, a, c);
                Z(a, a, c);
                S(b, a);
                Z(c, d, f);
                M(a, c, _121665);
                A(a, a, d);
                M(c, c, a);
                M(a, d, f);
                M(d, b, x);
                S(b, e);
                Sel25519(a, b, r);
                Sel25519(c, d, r);
            }
            for (var i = 0; i < 16; i++)
            {
                x[i + 16] = a[i];
                x[i + 32] = c[i];
                x[i + 48] = b[i];
                x[i + 64] = d[i];
            }

            var x32 = x.SubArray(32);
            var x16 = x.SubArray(16);

            Inv25519(x32, x32);

            M(x16, x16, x32);

            Pack25519(q, x16);

            return 0;
        }

        private static int CryptoScalarmultBase(byte[] q, byte[] n)
        {
            return CryptoScalarmult(q, n, _9);
        }

        private static int CryptoBoxKeypair(byte[] y, byte[] x)
        {
            randomBytes(x, 32);
            return CryptoScalarmultBase(y, x);
        }

        private static int CryptoBoxBeforenm(byte[] k, byte[] y, byte[] x)
        {
            var s = new byte[32];
            CryptoScalarmult(s, x, y);
            return CryptoCoreHsalsa20(k, _0, s, Sigma);
        }

        private static int CryptoBoxAfternm(byte[] c, byte[] m, int d, byte[] n, byte[] k) => CryptoSecretbox(c, m, d, n, k);
        private static int CryptoBoxOpenAfternm(byte[] m, byte[] c, int d, byte[] n, byte[] k) => CryptoSecretboxOpen(m, c, d, n, k);

        private static int CryptoBox(byte[] c, byte[] m, int d, byte[] n, byte[] y, byte[] x)
        {
            var k = new byte[32];
            CryptoBoxBeforenm(k, y, x);
            return CryptoBoxAfternm(c, m, d, n, k);
        }

        private static int CryptoBoxOpen(byte[] m, byte[] c, int d, byte[] n, byte[] y, byte[] x)
        {
            var k = new byte[32];
            CryptoBoxBeforenm(k, y, x);
            return CryptoBoxOpenAfternm(m, c, d, n, k);
        }

        private static uint[] K = {
          0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
          0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
          0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
          0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
          0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
          0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
          0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
          0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
          0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
          0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
          0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
          0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
          0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
          0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
          0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
          0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
          0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
          0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
          0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
          0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
          0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
          0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
          0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
          0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
          0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
          0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
          0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
          0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
          0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
          0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
          0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
          0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
          0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
          0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
          0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
          0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
          0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
          0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
          0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
          0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
        };

        private static int CryptoHashblocksHl(uint[] hh, uint[] hl, byte[] m, int n)
        {
            uint[] wh = new uint[16], wl = new uint[16];
            uint bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7,
                bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7,
                th, tl, i, j, h, l, a, b, c, d;

            uint ah0 = hh[0],
                ah1 = hh[1],
                ah2 = hh[2],
                ah3 = hh[3],
                ah4 = hh[4],
                ah5 = hh[5],
                ah6 = hh[6],
                ah7 = hh[7],

                al0 = hl[0],
                al1 = hl[1],
                al2 = hl[2],
                al3 = hl[3],
                al4 = hl[4],
                al5 = hl[5],
                al6 = hl[6],
                al7 = hl[7];

            var pos = 0;
            while (n >= 128)
            {
                for (i = 0; i < 16; i++)
                {
                    j = (uint)(8 * i + pos);
                    wh[i] = (uint)((m[j + 0] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]);
                    wl[i] = (uint)((m[j + 4] << 24) | (m[j + 5] << 16) | (m[j + 6] << 8) | m[j + 7]);
                }
                for (i = 0; i < 80; i++)
                {
                    bh0 = ah0;
                    bh1 = ah1;
                    bh2 = ah2;
                    bh3 = ah3;
                    bh4 = ah4;
                    bh5 = ah5;
                    bh6 = ah6;
                    bh7 = ah7;

                    bl0 = al0;
                    bl1 = al1;
                    bl2 = al2;
                    bl3 = al3;
                    bl4 = al4;
                    bl5 = al5;
                    bl6 = al6;
                    bl7 = al7;

                    // add
                    h = ah7;
                    l = al7;

                    a = l & 0xffff; b = l >> 16;
                    c = h & 0xffff; d = h >> 16;

                    // Sigma1
                    h = ((ah4 >> 14) | (al4 << (32 - 14))) ^ ((ah4 >> 18) | (al4 << (32 - 18))) ^ ((al4 >> (41 - 32)) | (ah4 << (32 - (41 - 32))));
                    l = ((al4 >> 14) | (ah4 << (32 - 14))) ^ ((al4 >> 18) | (ah4 << (32 - 18))) ^ ((ah4 >> (41 - 32)) | (al4 << (32 - (41 - 32))));

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    // Ch
                    h = (ah4 & ah5) ^ (~ah4 & ah6);
                    l = (al4 & al5) ^ (~al4 & al6);

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    // K
                    h = K[i * 2];
                    l = K[i * 2 + 1];

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    // w
                    h = wh[i % 16];
                    l = wl[i % 16];

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    b += a >> 16;
                    c += b >> 16;
                    d += c >> 16;

                    th = c & 0xffff | d << 16;
                    tl = a & 0xffff | b << 16;

                    // add
                    h = th;
                    l = tl;

                    a = l & 0xffff; b = l >> 16;
                    c = h & 0xffff; d = h >> 16;

                    // Sigma0
                    h = ((ah0 >> 28) | (al0 << (32 - 28))) ^ ((al0 >> (34 - 32)) | (ah0 << (32 - (34 - 32)))) ^ ((al0 >> (39 - 32)) | (ah0 << (32 - (39 - 32))));
                    l = ((al0 >> 28) | (ah0 << (32 - 28))) ^ ((ah0 >> (34 - 32)) | (al0 << (32 - (34 - 32)))) ^ ((ah0 >> (39 - 32)) | (al0 << (32 - (39 - 32))));

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    // Maj
                    h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
                    l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    b += a >> 16;
                    c += b >> 16;
                    d += c >> 16;

                    bh7 = (c & 0xffff) | (d << 16);
                    bl7 = (a & 0xffff) | (b << 16);

                    // add
                    h = bh3;
                    l = bl3;

                    a = l & 0xffff; b = l >> 16;
                    c = h & 0xffff; d = h >> 16;

                    h = th;
                    l = tl;

                    a += l & 0xffff; b += l >> 16;
                    c += h & 0xffff; d += h >> 16;

                    b += a >> 16;
                    c += b >> 16;
                    d += c >> 16;

                    bh3 = (c & 0xffff) | (d << 16);
                    bl3 = (a & 0xffff) | (b << 16);

                    ah1 = bh0;
                    ah2 = bh1;
                    ah3 = bh2;
                    ah4 = bh3;
                    ah5 = bh4;
                    ah6 = bh5;
                    ah7 = bh6;
                    ah0 = bh7;

                    al1 = bl0;
                    al2 = bl1;
                    al3 = bl2;
                    al4 = bl3;
                    al5 = bl4;
                    al6 = bl5;
                    al7 = bl6;
                    al0 = bl7;

                    if (i % 16 == 15)
                    {
                        for (j = 0; j < 16; j++)
                        {
                            // add
                            h = wh[j];
                            l = wl[j];

                            a = l & 0xffff; b = l >> 16;
                            c = h & 0xffff; d = h >> 16;

                            h = wh[(j + 9) % 16];
                            l = wl[(j + 9) % 16];

                            a += l & 0xffff; b += l >> 16;
                            c += h & 0xffff; d += h >> 16;

                            // sigma0
                            th = wh[(j + 1) % 16];
                            tl = wl[(j + 1) % 16];
                            h = ((th >> 1) | (tl << (32 - 1))) ^ ((th >> 8) | (tl << (32 - 8))) ^ (th >> 7);
                            l = ((tl >> 1) | (th << (32 - 1))) ^ ((tl >> 8) | (th << (32 - 8))) ^ ((tl >> 7) | (th << (32 - 7)));

                            a += l & 0xffff; b += l >> 16;
                            c += h & 0xffff; d += h >> 16;

                            // sigma1
                            th = wh[(j + 14) % 16];
                            tl = wl[(j + 14) % 16];
                            h = ((th >> 19) | (tl << (32 - 19))) ^ ((tl >> (61 - 32)) | (th << (32 - (61 - 32)))) ^ (th >> 6);
                            l = ((tl >> 19) | (th << (32 - 19))) ^ ((th >> (61 - 32)) | (tl << (32 - (61 - 32)))) ^ ((tl >> 6) | (th << (32 - 6)));

                            a += l & 0xffff; b += l >> 16;
                            c += h & 0xffff; d += h >> 16;

                            b += a >> 16;
                            c += b >> 16;
                            d += c >> 16;

                            wh[j] = (c & 0xffff) | (d << 16);
                            wl[j] = (a & 0xffff) | (b << 16);
                        }
                    }
                }

                // add
                h = ah0;
                l = al0;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[0];
                l = hl[0];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[0] = ah0 = (c & 0xffff) | (d << 16);
                hl[0] = al0 = (a & 0xffff) | (b << 16);

                h = ah1;
                l = al1;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[1];
                l = hl[1];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[1] = ah1 = (c & 0xffff) | (d << 16);
                hl[1] = al1 = (a & 0xffff) | (b << 16);

                h = ah2;
                l = al2;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[2];
                l = hl[2];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[2] = ah2 = (c & 0xffff) | (d << 16);
                hl[2] = al2 = (a & 0xffff) | (b << 16);

                h = ah3;
                l = al3;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[3];
                l = hl[3];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[3] = ah3 = (c & 0xffff) | (d << 16);
                hl[3] = al3 = (a & 0xffff) | (b << 16);

                h = ah4;
                l = al4;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[4];
                l = hl[4];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[4] = ah4 = (c & 0xffff) | (d << 16);
                hl[4] = al4 = (a & 0xffff) | (b << 16);

                h = ah5;
                l = al5;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[5];
                l = hl[5];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[5] = ah5 = (c & 0xffff) | (d << 16);
                hl[5] = al5 = (a & 0xffff) | (b << 16);

                h = ah6;
                l = al6;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[6];
                l = hl[6];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[6] = ah6 = (c & 0xffff) | (d << 16);
                hl[6] = al6 = (a & 0xffff) | (b << 16);

                h = ah7;
                l = al7;

                a = l & 0xffff; b = l >> 16;
                c = h & 0xffff; d = h >> 16;

                h = hh[7];
                l = hl[7];

                a += l & 0xffff; b += l >> 16;
                c += h & 0xffff; d += h >> 16;

                b += a >> 16;
                c += b >> 16;
                d += c >> 16;

                hh[7] = ah7 = (c & 0xffff) | (d << 16);
                hl[7] = al7 = (a & 0xffff) | (b << 16);

                pos += 128;
                n -= 128;
            }

            return n;
        }

        private static int CryptoHash(byte[] outp, byte[] m, int n)
        {
            uint[] hh = new uint[8],
              hl = new uint[8];
            var x = new byte[256];
            int i, b = n;

            hh[0] = 0x6a09e667;
            hh[1] = 0xbb67ae85;
            hh[2] = 0x3c6ef372;
            hh[3] = 0xa54ff53a;
            hh[4] = 0x510e527f;
            hh[5] = 0x9b05688c;
            hh[6] = 0x1f83d9ab;
            hh[7] = 0x5be0cd19;

            hl[0] = 0xf3bcc908;
            hl[1] = 0x84caa73b;
            hl[2] = 0xfe94f82b;
            hl[3] = 0x5f1d36f1;
            hl[4] = 0xade682d1;
            hl[5] = 0x2b3e6c1f;
            hl[6] = 0xfb41bd6b;
            hl[7] = 0x137e2179;

            CryptoHashblocksHl(hh, hl, m, n);
            n %= 128;

            for (i = 0; i < n; i++) x[i] = m[b - n + i];
            x[n] = 128;

            n = 256 - 128 * (n < 112 ? 1 : 0);
            x[n - 9] = 0;
            Ts64(x, n - 8, (uint)((b / 0x20000000) | 0), (uint)(b << 3));
            CryptoHashblocksHl(hh, hl, x, n);

            for (i = 0; i < 8; i++) Ts64(outp, 8 * i, hh[i], hl[i]);

            return 0;
        }

        private static void Add(long[][] p, long[][] q)
        {
            long[] a = Gf(), b = Gf(), c = Gf(),
                d = Gf(), e = Gf(), f = Gf(),
                g = Gf(), h = Gf(), t = Gf();

            Z(a, p[1], p[0]);
            Z(t, q[1], q[0]);
            M(a, a, t);
            A(b, p[0], p[1]);
            A(t, q[0], q[1]);
            M(b, b, t);
            M(c, p[3], q[3]);
            M(c, c, D2);
            M(d, p[2], q[2]);
            A(d, d, d);
            Z(e, b, a);
            Z(f, d, c);
            A(g, d, c);
            A(h, b, a);

            M(p[0], e, f);
            M(p[1], h, g);
            M(p[2], g, f);
            M(p[3], e, h);
        }

        private static void Cswap(long[][] p, long[][] q, long b)
        {
            for (var i = 0; i < 4; i++)
            {
                Sel25519(p[i], q[i], b);
            }
        }

        private static void Pack(byte[] r, long[][] p)
        {
            long[] tx = Gf(), ty = Gf(), zi = Gf();
            Inv25519(zi, p[2]);
            M(tx, p[0], zi);
            M(ty, p[1], zi);
            Pack25519(r, ty);
            r[31] ^= (byte)(Par25519(tx) << 7);
        }

        private static void Scalarmult(long[][] p, long[][] q, byte[] s)
        {
            Set25519(p[0], gf0);
            Set25519(p[1], gf1);
            Set25519(p[2], gf1);
            Set25519(p[3], gf0);
            for (var i = 255; i >= 0; --i)
            {
                var b = (s[(i / 8) | 0] >> (i & 7)) & 1;
                Cswap(p, q, b);
                Add(q, p);
                Add(p, p);
                Cswap(p, q, b);
            }
        }

        private static void Scalarbase(long[][] p, byte[] s)
        {
            var q = new long[][]{ Gf(), Gf(), Gf(), Gf() };
            Set25519(q[0], X);
            Set25519(q[1], Y);
            Set25519(q[2], gf1);
            M(q[3], X, Y);
            Scalarmult(p, q, s);
        }

        private static int CryptoSignKeypair(byte[] pk, byte[] sk, bool seeded = false)
        {
            var d = new byte[64];
            var p = new long[][] { Gf(), Gf(), Gf(), Gf() };

            if (!seeded) randomBytes(sk, 32);
            CryptoHash(d, sk, 32);
            d[0] &= 248;
            d[31] &= 127;
            d[31] |= 64;

            Scalarbase(p, d);
            Pack(pk, p);

            for (var i = 0; i < 32; i++) sk[i + 32] = pk[i];
            return 0;
        }

        private static readonly long[] L = new long[] { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

        private static void ModL(byte[] r, long[] x)
        {
            long carry, i, j, k;
            for (i = 63; i >= 32; --i)
            {
                carry = 0;
                for (j = i - 32, k = i - 12; j < k; ++j)
                {
                    x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                    carry = (long)Math.Floor((double)(x[j] + 128) / 256);
                    x[j] -= carry * 256;
                }
                x[j] += carry;
                x[i] = 0;
            }
            carry = 0;
            for (j = 0; j < 32; j++)
            {
                x[j] += carry - (x[31] >> 4) * L[j];
                carry = x[j] >> 8;
                x[j] &= 255;
            }
            for (j = 0; j < 32; j++) x[j] -= carry * L[j];
            for (i = 0; i < 32; i++)
            {
                x[i + 1] += x[i] >> 8;
                r[i] = (byte)(x[i] & 255);
            }
        }

        private static void Reduce(byte[] r)
        {
            var x = new long[64];
            for (var i = 0; i < 64; i++) x[i] = r[i];
            for (var i = 0; i < 64; i++) r[i] = 0;
            ModL(r, x);
        }

        // Note: difference from C - smlen returned, not passed as argument.
        private static int CryptoSign(byte[] sm, byte[] m, int n, byte[] sk)
        {
            byte[] d = new byte[64], h = new byte[64], r = new byte[64];
            var x = new long[64];
            var p = new long[][] { Gf(), Gf(), Gf(), Gf() };

            CryptoHash(d, sk, 32);
            d[0] &= 248;
            d[31] &= 127;
            d[31] |= 64;

            var smlen = n + 64;
            for (var i = 0; i < n; i++) sm[64 + i] = m[i];
            for (var i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

            CryptoHash(r, sm.SubArray(32), n + 32);
            Reduce(r);
            Scalarbase(p, r);
            Pack(sm, p);

            for (var i = 32; i < 64; i++) sm[i] = sk[i];
            CryptoHash(h, sm, n + 64);
            Reduce(h);

            for (var i = 0; i < 64; i++) x[i] = 0;
            for (var i = 0; i < 32; i++) x[i] = r[i];
            for (var i = 0; i < 32; i++)
            {
                for (var j = 0; j < 32; j++)
                {
                    x[i + j] += h[i] * d[j];
                }
            }

            var sm32 = sm.SubArray(32);
            ModL(sm32, x);
            Array.Copy(sm32, 0, sm, 32, sm.Length - 32);

            return smlen;
        }

        private static int Unpackneg(long[][] r, byte[] p)
        {
            long[] t = Gf(), chk = Gf(), num = Gf(),
                den = Gf(), den2 = Gf(), den4 = Gf(),
                den6 = Gf();

            Set25519(r[2], gf1);
            Unpack25519(r[1], p);
            S(num, r[1]);
            M(den, num, D);
            Z(num, num, r[2]);
            A(den, r[2], den);

            S(den2, den);
            S(den4, den2);
            M(den6, den4, den2);
            M(t, den6, num);
            M(t, t, den);

            Pow2523(t, t);
            M(t, t, num);
            M(t, t, den);
            M(t, t, den);
            M(r[0], t, den);

            S(chk, r[0]);
            M(chk, chk, den);
            if (Neq25519(chk, num) != 0) M(r[0], r[0], I);

            S(chk, r[0]);
            M(chk, chk, den);
            if (Neq25519(chk, num) != 0) return -1;

            if (Par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

            M(r[3], r[0], r[1]);
            return 0;
        }

        private static int CryptoSignOpen(byte[] m, byte[] sm, int n, byte[] pk)
        {
            byte[] t = new byte[32], h = new byte[64];
            long[][] p = new long[][] { Gf(), Gf(), Gf(), Gf() },
                q = new long[][] { Gf(), Gf(), Gf(), Gf() };

            if (n < 64) return -1;

            if (Unpackneg(q, pk) != 0) return -1;

            for (var i = 0; i < n; i++) m[i] = sm[i];
            for (var i = 0; i < 32; i++) m[i + 32] = pk[i];
            CryptoHash(h, m, n);
            Reduce(h);
            Scalarmult(p, q, h);

            Scalarbase(q, sm.SubArray(32));
            Add(p, q);
            Pack(t, p);

            n -= 64;
            if (CryptoVerify32(sm, 0, t, 0) != 0)
            {
                for (var i = 0; i < n; i++) m[i] = 0;
                return -1;
            }

            for (var i = 0; i < n; i++) m[i] = sm[i + 64];
            return n;
        }

        private static readonly int crypto_secretbox_KEYBYTES = 32,
            crypto_secretbox_NONCEBYTES = 24,
            crypto_secretbox_ZEROBYTES = 32,
            crypto_secretbox_BOXZEROBYTES = 16,
            crypto_scalarmult_BYTES = 32,
            crypto_scalarmult_SCALARBYTES = 32,
            crypto_box_PUBLICKEYBYTES = 32,
            crypto_box_SECRETKEYBYTES = 32,
            crypto_box_BEFORENMBYTES = 32,
            crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
            crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
            crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
            crypto_sign_BYTES = 64,
            crypto_sign_PUBLICKEYBYTES = 32,
            crypto_sign_SECRETKEYBYTES = 64,
            crypto_sign_SEEDBYTES = 32,
            crypto_hash_BYTES = 64;
        #endregion Low Level

        #region High Level
        private static void CheckLengths(byte[] k, byte[] n)
        {
            if (k.Length != crypto_secretbox_KEYBYTES) throw new NaclException("bad key size");
            if (n.Length != crypto_secretbox_NONCEBYTES) throw new NaclException("bad nonce size");
        }

        private static void CheckBoxLengths(byte[] pk, byte[] sk)
        {
            if (pk.Length != crypto_box_PUBLICKEYBYTES) throw new NaclException("bad public key size");
            if (sk.Length != crypto_box_SECRETKEYBYTES) throw new NaclException("bad secret key size");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="n"></param>
        /// <returns>A byte[] of the given length containing random bytes of cryptographic quality.</returns>
        public static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            randomBytes(b, n);
            return b;
        }

        /// <summary>
        /// Encrypts and authenticates message using the key and the nonce. The nonce must be unique for each distinct message for this key.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <returns>An encrypted and authenticated message, which is TweetNaclSharp.Nacl.SecretboxOverheadLength longer than the original message.</returns>
        public static byte[] Secretbox(byte[] msg, byte[] nonce, byte[] key)
        {
            CheckLengths(key, nonce);
            var m = new byte[crypto_secretbox_ZEROBYTES + msg.Length];
            var c = new byte[m.Length];
            for (var i = 0; i < msg.Length; i++) m[i + crypto_secretbox_ZEROBYTES] = msg[i];
            CryptoSecretbox(c, m, m.Length, nonce, key);
            return c.SubArray(crypto_secretbox_BOXZEROBYTES);
        }

        /// <summary>
        /// Authenticates and decrypts the given secret box using the key and the nonce.
        /// </summary>
        /// <param name="box"></param>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <returns>The original message, or null if authentication fails.</returns>
        public static byte[]? SecretboxOpen(byte[] box, byte[] nonce, byte[] key)
        {
            CheckLengths(key, nonce);
            var c = new byte[crypto_secretbox_BOXZEROBYTES + box.Length];
            var m = new byte[c.Length];
            for (var i = 0; i < box.Length; i++) c[i + crypto_secretbox_BOXZEROBYTES] = box[i];
            if (c.Length < 32) return null;
            if (CryptoSecretboxOpen(m, c, c.Length, nonce, key) != 0) return null;
            return m.SubArray(crypto_secretbox_ZEROBYTES);
        }

        /// <summary>
        /// Length of key in bytes.
        /// </summary>
        public static readonly int SecretboxKeyLength = crypto_secretbox_KEYBYTES;
        /// <summary>
        /// Length of nonce in bytes.
        /// </summary>
        public static readonly int SecretboxNonceLength = crypto_secretbox_NONCEBYTES;
        /// <summary>
        /// Length of overhead added to secret box compared to original message.
        /// </summary>
        public static readonly int SecretboxOverheadLength = crypto_secretbox_BOXZEROBYTES;

        /// <summary>
        /// Multiplies an integer n by a group element p.
        /// </summary>
        /// <param name="n"></param>
        /// <param name="p"></param>
        /// <returns>The resulting group element.</returns>
        /// <exception cref="NaclException"></exception>
        public static byte[] ScalarMult(byte[] n, byte[] p)
        {
            if (n.Length != crypto_scalarmult_SCALARBYTES) throw new NaclException("bad n size");
            if (p.Length != crypto_scalarmult_BYTES) throw new NaclException("bad p size");
            var q = new byte[crypto_scalarmult_BYTES];
            CryptoScalarmult(q, n, p);
            return q;
        }

        /// <summary>
        /// Multiplies an integer n by a standard group element.
        /// </summary>
        /// <param name="n"></param>
        /// <returns>The resulting group element.</returns>
        /// <exception cref="NaclException"></exception>
        public static byte[] ScalarMultBase(byte[] n)
        {
            if (n.Length != crypto_scalarmult_SCALARBYTES) throw new NaclException("bad n size");
            var q = new byte[crypto_scalarmult_BYTES];
            CryptoScalarmultBase(q, n);
            return q;
        }

        /// <summary>
        /// Length of scalar in bytes.
        /// </summary>
        public static readonly int ScalarMultScalarLength = crypto_scalarmult_SCALARBYTES;
        /// <summary>
        /// Length of group element in bytes.
        /// </summary>
        public static readonly int ScalarMultGroupElementLength = crypto_scalarmult_BYTES;

        /// <summary>
        /// Encrypts and authenticates message using peer's public key, our secret key, and the given nonce, which must be unique for each distinct message for a key pair.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="nonce"></param>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns>An encrypted and authenticated message, which is TweetNaclSharp.Nacl.BoxOverheadLength longer than the original message.</returns>
        public static byte[] Box(byte[] msg, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            var k = BoxBefore(publicKey, secretKey);
            return Secretbox(msg, nonce, k);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns>A precomputed shared key which can be used in TweetNaclSharp.Nacl.BoxAfter and TweetNaclSharp.Nacl.BoxOpenAfter.</returns>
        public static byte[] BoxBefore(byte[] publicKey, byte[] secretKey)
        {
            CheckBoxLengths(publicKey, secretKey);
            var k = new byte[crypto_box_BEFORENMBYTES];
            CryptoBoxBeforenm(k, publicKey, secretKey);
            return k;
        }

        /// <summary>
        /// Same as TweetNaclSharp.Nacl.Box, but uses a shared key precomputed with TweetNaclSharp.Nacl.BoxBefore.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] BoxAfter(byte[] msg, byte[] nonce, byte[] key) => Secretbox(msg, nonce, key);

        /// <summary>
        /// Authenticates and decrypts the given box with peer's public key, our secret key, and the given nonce.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="nonce"></param>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns>The original message, or null if authentication fails.</returns>
        public static byte[]? BoxOpen(byte[] msg, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            var k = BoxBefore(publicKey, secretKey);
            return SecretboxOpen(msg, nonce, k);
        }

        /// <summary>
        /// Same as TweetNaclSharp.Nacl.BoxOpen, but uses a shared key precomputed with TweetNaclSharp.Nacl.BoxBefore.
        /// </summary>
        /// <param name="box"></param>
        /// <param name="nonce"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[]? BoxOpenAfter(byte[] box, byte[] nonce, byte[] key) => SecretboxOpen(box, nonce, key);

        /// <summary>
        /// Generates a new random key pair for box.
        /// </summary>
        /// <returns>Key pair as an object with PublicKey and SecretKey member.</returns>
        public static KeyPair BoxKeyPair()
        {
            var pk = new byte[crypto_box_PUBLICKEYBYTES];
            var sk = new byte[crypto_box_SECRETKEYBYTES];
            CryptoBoxKeypair(pk, sk);
            return new KeyPair { PublicKey = pk, SecretKey = sk };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretKey"></param>
        /// <returns>A key pair for box with public key corresponding to the given secret key.</returns>
        /// <exception cref="NaclException"></exception>
        public static KeyPair BoxKeyPairFromSecretKey(byte[] secretKey)
        {
            if (secretKey.Length != crypto_box_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var pk = new byte[crypto_box_PUBLICKEYBYTES];
            CryptoScalarmultBase(pk, secretKey);
            return new KeyPair { PublicKey = pk, SecretKey = secretKey };
        }

        /// <summary>
        /// Length of public key in bytes.
        /// </summary>
        public static readonly int BoxPublicKeyLength = crypto_box_PUBLICKEYBYTES;
        /// <summary>
        /// Length of secret key in bytes.
        /// </summary>
        public static readonly int BoxSecretKeyLength = crypto_box_SECRETKEYBYTES;
        /// <summary>
        /// Length of precomputed shared key in bytes.
        /// </summary>
        public static readonly int BoxSharedKeyLength = crypto_box_BEFORENMBYTES;
        /// <summary>
        /// Length of nonce in bytes.
        /// </summary>
        public static readonly int BoxNonceLength = crypto_box_NONCEBYTES;
        /// <summary>
        /// Length of overhead added to box compared to original message.
        /// </summary>
        public static readonly int BoxOverheadLength = SecretboxOverheadLength;

        /// <summary>
        /// Signs the message using the secret key.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="secretKey"></param>
        /// <returns>A signed message.</returns>
        /// <exception cref="NaclException"></exception>
        public static byte[] Sign(byte[] msg, byte[] secretKey)
        {
            if (secretKey.Length != crypto_sign_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var signedMsg = new byte[crypto_sign_BYTES + msg.Length];
            CryptoSign(signedMsg, msg, msg.Length, secretKey);
            return signedMsg;
        }

        /// <summary>
        /// Verifies the signed message.
        /// </summary>
        /// <param name="signedMsg"></param>
        /// <param name="publicKey"></param>
        /// <returns>The message without signature or null if verification failed.</returns>
        /// <exception cref="NaclException"></exception>
        public static byte[]? SignOpen(byte[] signedMsg, byte[] publicKey)
        {
            if (publicKey.Length != crypto_sign_PUBLICKEYBYTES)
                throw new NaclException("bad public key size");
            var tmp = new byte[signedMsg.Length];
            var mlen = CryptoSignOpen(tmp, signedMsg, signedMsg.Length, publicKey);
            if (mlen < 0) return null;
            var m = new byte[mlen];
            for (var i = 0; i < m.Length; i++) m[i] = tmp[i];
            return m;
        }

        /// <summary>
        /// Signs the message using the secret key.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="secretKey"></param>
        /// <returns>A signature.</returns>
        public static byte[] SignDetached(byte[] msg, byte[] secretKey)
        {
            var signedMsg = Sign(msg, secretKey);
            var sig = new byte[crypto_sign_BYTES];
            for (var i = 0; i < sig.Length; i++) sig[i] = signedMsg[i];
            return sig;
        }

        /// <summary>
        /// Verifies the signature for the message.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="sig"></param>
        /// <param name="publicKey"></param>
        /// <returns>True if verification succeeded or false if it failed.</returns>
        /// <exception cref="NaclException"></exception>
        public static bool SignDetachedVerify(byte[] msg, byte[] sig, byte[] publicKey)
        {
            if (sig.Length != crypto_sign_BYTES)
                throw new NaclException("bad signature size");
            if (publicKey.Length != crypto_sign_PUBLICKEYBYTES)
                throw new NaclException("bad public key size");
            var sm = new byte[crypto_sign_BYTES + msg.Length];
            var m = new byte[crypto_sign_BYTES + msg.Length];

            for (var i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
            for (var i = 0; i < msg.Length; i++) sm[i + crypto_sign_BYTES] = msg[i];
            return (CryptoSignOpen(m, sm, sm.Length, publicKey) >= 0);
        }

        /// <summary>
        /// Generates new random key pair for signing.
        /// </summary>
        /// <returns>Key pair as an object with PublicKey and SecretKey members.</returns>
        public static KeyPair SignKeyPair()
        {
            var pk = new byte[crypto_sign_PUBLICKEYBYTES];
            var sk = new byte[crypto_sign_SECRETKEYBYTES];
            CryptoSignKeypair(pk, sk);
            return new KeyPair { PublicKey = pk, SecretKey = sk };
        }

        /// <summary>
        /// The secret key must have been generated by TweetNaclSharp.Nacl.SignKeyPair or TweetNaclSharp.Nacl.SignKeyPairFromSeed.
        /// </summary>
        /// <param name="secretKey"></param>
        /// <returns>A signing key pair with public key corresponding to the given 64-byte secret key.</returns>
        /// <exception cref="NaclException"></exception>
        public static KeyPair SignKeyPairFromSecretKey(byte[] secretKey)
        {
            if (secretKey.Length != crypto_sign_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var pk = new byte[crypto_sign_PUBLICKEYBYTES];
            for (var i = 0; i < pk.Length; i++) pk[i] = secretKey[32 + i];
            return new KeyPair { PublicKey = pk, SecretKey = secretKey };
        }

        /// <summary>
        /// The seed must contain enough entropy to be secure. This method is not recommended for general use: instead, use TweetNaclSharp.Nacl.SignKeyPair to generate a new key pair from a random seed.
        /// </summary>
        /// <param name="seed"></param>
        /// <returns>A new signing key pair generated deterministically from a 32-byte seed.</returns>
        /// <exception cref="NaclException"></exception>
        public static KeyPair SignKeyPairFromSeed(byte[] seed)
        {
            if (seed.Length != crypto_sign_SEEDBYTES)
                throw new NaclException("bad seed size");
            var pk = new byte[crypto_sign_PUBLICKEYBYTES];
            var sk = new byte[crypto_sign_SECRETKEYBYTES];
            for (var i = 0; i < 32; i++) sk[i] = seed[i];
            CryptoSignKeypair(pk, sk, true);
            return new KeyPair { PublicKey = pk, SecretKey = sk };
        }

        /// <summary>
        /// Length of signing public key in bytes.
        /// </summary>
        public static readonly int SignPublicKeyLength = crypto_sign_PUBLICKEYBYTES;
        /// <summary>
        /// Length of signing secret key in bytes.
        /// </summary>
        public static readonly int SignSecretKeyLength = crypto_sign_SECRETKEYBYTES;
        /// <summary>
        /// Length of seed for TweetNaclSharp.Nacl.SignKeyPairFromSeed in bytes.
        /// </summary>
        public static readonly int SignSeedLength = crypto_sign_SEEDBYTES;
        /// <summary>
        /// Length of signature in bytes.
        /// </summary>
        public static readonly int SignSignatureLength = crypto_sign_BYTES;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="msg"></param>
        /// <returns>SHA-512 hash of the message.</returns>
        public static byte[] Hash(byte[] msg)
        {
            var h = new byte[crypto_hash_BYTES];
            CryptoHash(h, msg, msg.Length);
            return h;
        }

        /// <summary>
        /// Length of hash in bytes.
        /// </summary>
        public static readonly int HashHashLength = crypto_hash_BYTES;

        /// <summary>
        /// Compares x and y in constant time.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns>True if their lengths are non-zero and equal, and their contents are equal. False if either of the arguments has zero length, or arguments have different lengths, or their contents differ.</returns>
        public static bool Verify(byte[] x, byte[] y)
        {
            // Zero length arguments are considered not equal.
            if (x.Length == 0 || y.Length == 0) return false;
            if (x.Length != y.Length) return false;
            return (Vn(x, 0, y, 0, (uint)x.Length) == 0) ? true : false;
        }

        /// <summary>
        /// Completely replaces internal random byte generator with the one provided.
        /// </summary>
        /// <param name="randomBytesFunc"></param>
        public static void SetPRNG(Action<byte[], int> randomBytesFunc)
        {
            randomBytes = randomBytesFunc;
        }
        #endregion High Level
    }
}