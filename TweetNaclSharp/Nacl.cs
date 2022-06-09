using System.Security.Cryptography;
using System.Text;
using TweetNaclSharp.Core;
using TweetNaclSharp.Core.Extensions;

namespace TweetNaclSharp
{
    public class Nacl
    {
        #region Low Level
        private static U64Class U64(uint h, uint l)
        {
            return new U64Class(h, l);
        }
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

        private static uint L32(uint x, int c) { return (x << c) | (x >> (32 - c)); }

        private static uint Ld32(byte[] x, long i)
        {
            var u = (x[i + 3] & 0xff);
            u = (u << 8) | (x[i + 2] & 0xff);
            u = (u << 8) | (x[i + 1] & 0xff);
            return (uint)((u << 8) | (x[i + 0] & 0xff));
        }

        private static U64Class Dl64(byte[] x, long i)
        {
            var h = (x[i] << 24) | (x[i + 1] << 16) | (x[i + 2] << 8) | x[i + 3];
            var l = (x[i + 4] << 24) | (x[i + 5] << 16) | (x[i + 6] << 8) | x[i + 7];
            return U64((uint)h, (uint)l);
        }

        private static void St32(byte[] x, int j, uint u)
        {
            for (var i = 0; i < 4; i++)
            {
                x[j + i] = (byte)u;
                u >>= 8;
            }
        }

        private static void Ts64(byte[] x, int i, U64Class u)
        {
            x[i] = (byte)((u.Hi >> 24) & 0xff);
            x[i + 1] = (byte)((u.Hi >> 16) & 0xff);
            x[i + 2] = (byte)((u.Hi >> 8) & 0xff);
            x[i + 3] = (byte)(u.Hi & 0xff);
            x[i + 4] = (byte)((u.Lo >> 24) & 0xff);
            x[i + 5] = (byte)((u.Lo >> 16) & 0xff);
            x[i + 6] = (byte)((u.Lo >> 8) & 0xff);
            x[i + 7] = (byte)(u.Lo & 0xff);
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

        private static void Core(byte[] outp, byte[] inp, byte[] k, byte[] c, bool h)
        {
            uint[] w = new uint[16];
            uint[] x = new uint[16];
            uint[] y = new uint[16];
            uint[] t = new uint[4];

            for (var i = 0; i < 4; i++)
            {
                x[5 * i] = Ld32(c, 4 * i);
                x[1 + i] = Ld32(k, 4 * i);
                x[6 + i] = Ld32(inp, 4 * i);
                x[11 + i] = Ld32(k, 16 + 4 * i);
            }

            for (var i = 0; i < 16; i++)
            {
                y[i] = x[i];
            }

            for (var i = 0; i < 20; i++)
            {
                for (var j = 0; j < 4; j++)
                {
                    for (var m = 0; m < 4; m++)
                    {
                        t[m] = x[(5 * j + 4 * m) % 16];
                    }

                    t[1] ^= L32((t[0] + t[3]) | 0, 7);
                    t[2] ^= L32((t[1] + t[0]) | 0, 9);
                    t[3] ^= L32((t[2] + t[1]) | 0, 13);
                    t[0] ^= L32((t[3] + t[2]) | 0, 18);

                    for (var m = 0; m < 4; m++)
                    {
                        w[4 * j + (j + m) % 4] = t[m];
                    }
                }

                for (var m = 0; m < 16; m++)
                {
                    x[m] = w[m];
                }
            }

            if (h)
            {
                for (var i = 0; i < 16; i++)
                {
                    x[i] = (x[i] + y[i]) | 0;
                }

                for (var i = 0; i < 4; i++)
                {
                    x[5 * i] = (x[5 * i] - Ld32(c, 4 * i)) | 0;
                    x[6 + i] = (x[6 + i] - Ld32(inp, 4 * i)) | 0;
                }

                for (var i = 0; i < 4; i++)
                {
                    St32(outp, 4 * i, x[5 * i]);
                    St32(outp, 16 + 4 * i, x[6 + i]);
                }
            }
            else
            {
                for (var i = 0; i < 16; i++)
                {
                    St32(outp, 4 * i, (x[i] + y[i]) | 0);
                }
            }
        }

        private static int CryptoCoreSalsa20(byte[] outp, byte[] inp, byte[] k, byte[] c)
        {
            Core(outp, inp, k, c, false);
            return 0;
        }

        private static int CryptoCoreHsalsa20(byte[] outp, byte[] inp, byte[] k, byte[] c)
        {
            Core(outp, inp, k, c, true);
            return 0;
        }

        private static readonly byte[] Sigma = Encoding.ASCII.GetBytes("expand 32-byte k");

        private static int CryptoStreamSalsa20Xor(byte[] c, uint cpos, byte[]? m, uint mpos, ulong? b, byte[] n, byte[] k)
        {
            byte[] z = new byte[16];
            byte[] x = new byte[64];

            uint u = 0;

            if (!b.HasValue) return 0;

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
                    c[cpos + i] = (byte)((m != null ? m[mpos + i] : 0) ^ x[i]);
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
                if (m != null)
                {
                    mpos += 64;
                }
            }

            if (b > 0)
            {
                CryptoCoreSalsa20(x, z, k, Sigma);

                for (ulong i = 0; i < b; i++)
                {
                    c[cpos + i] = (byte)((m != null ? m[mpos + i] : 0) ^ x[i]);
                }
            }

            return 0;
        }

        private static int CryptoStreamSalsa20(byte[] c, uint cpos, ulong? d, byte[] n, byte[] k)
        {
            return CryptoStreamSalsa20Xor(c, cpos, null, 0, d, n, k);
        }

        private static int CryptoStream(byte[] c, uint cpos, ulong? d, byte[] n, byte[] k)
        {
            var s = new byte[32];
            CryptoCoreHsalsa20(s, n, k, Sigma);
            return CryptoStreamSalsa20(c, cpos, d, n.SubArray(16), s);
        }

        private static int CryptoStreamXor(byte[] c, uint cpos, byte[]? m, uint mpos, ulong? d, byte[] n, byte[] k)
        {
            var s = new byte[32];
            CryptoCoreHsalsa20(s, n, k, Sigma);
            return CryptoStreamSalsa20Xor(c, cpos, m, mpos, d, n.SubArray(16), s);
        }

        private static void Add1305(uint[] h, uint[] c)
        {
            uint u = 0;
            for (var j = 0; j < 17; j++)
            {
                u = (u + ((h[j] + c[j]) | 0)) | 0;
                h[j] = u & 255;
                u >>= 8;
            }
        }

        private static readonly uint[] Minusp = new uint[] { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 };

        public static int CryptoOnetimeauth(byte[] outp, uint outpos, byte[] m, uint mpos, uint n, byte[] k)
        {
            uint i = 0, j = 0, u = 0, s = 0;
            uint[] x = new uint[17], r = new uint[17],
                h = new uint[17], c = new uint[17],
                g = new uint[17];
            for (j = 0; j < 17; j++) r[j] = h[j] = 0;
            for (j = 0; j < 16; j++) r[j] = k[j];
            r[3] &= 15;
            r[4] &= 252;
            r[7] &= 15;
            r[8] &= 252;
            r[11] &= 15;
            r[12] &= 252;
            r[15] &= 15;

            while (n > 0)
            {
                for (j = 0; j < 17; j++) c[j] = 0;
                for (j = 0; (j < 16) && (j < n); ++j) c[j] = m[mpos + j];
                c[j] = 1;
                mpos += j; n -= j;
                Add1305(h, c);
                for (i = 0; i < 17; i++)
                {
                    x[i] = 0;
                    for (j = 0; j < 17; j++) x[i] = (x[i] + (h[j] * ((j <= i) ? r[i - j] : ((320 * r[i + 17 - j]) | 0))) | 0) | 0;
                }
                for (i = 0; i < 17; i++) h[i] = x[i];
                u = 0;
                for (j = 0; j < 16; j++)
                {
                    u = (u + h[j]) | 0;
                    h[j] = u & 255;
                    u >>= 8;
                }
                u = (u + h[16]) | 0; h[16] = u & 3;
                u = (5 * (u >> 2)) | 0;
                for (j = 0; j < 16; j++)
                {
                    u = (u + h[j]) | 0;
                    h[j] = u & 255;
                    u >>= 8;
                }
                u = (u + h[16]) | 0; h[16] = u;
            }

            for (j = 0; j < 17; j++) g[j] = h[j];
            Add1305(h, Minusp);
            s = (uint)(-(h[16] >> 7) | 0);
            for (j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

            for (j = 0; j < 16; j++) c[j] = k[j + 16];
            c[16] = 0;
            Add1305(h, c);
            for (j = 0; j < 16; j++) outp[outpos + j] = (byte)h[j];
            return 0;
        }

        private static int CryptoOnetimeauthVerify(byte[] h, uint hpos, byte[] m, uint mpos, uint n, byte[] k)
        {
            var x = new byte[16];
            CryptoOnetimeauth(x, 0, m, mpos, n, k);
            return CryptoVerify16(h, hpos, x, 0);
        }

        private static int CryptoSecretbox(byte[] c, byte[]? m, uint d, byte[] n, byte[] k)
        {
            if (d < 32) return -1;
            CryptoStreamXor(c, 0, m, 0, d, n, k);
            CryptoOnetimeauth(c, 16, c, 32, d - 32, c);
            for (var i = 0; i < 16; i++) c[i] = 0;
            return 0;
        }

        private static int CryptoSecretboxOpen(byte[] m, byte[] c, uint d, byte[] n, byte[] k)
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
            long[] t = new long[31];

            for (var i = 0; i < 31; i++)
            {
                t[i] = 0;
            }

            for (var i = 0; i < 16; i++)
            {
                for (var j = 0; j < 16; j++)
                {
                    t[i + j] += a[i] * b[j];
                }
            }

            for (var i = 0; i < 15; i++)
            {
                t[i] += 38 * t[i + 16];
            }

            for (var i = 0; i < 16; i++)
            {
                o[i] = t[i];
            }

            Car25519(o);
            Car25519(o);
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

        private static int CryptoBoxAfternm(byte[] c, byte[]? m, uint d, byte[] n, byte[] k) => CryptoSecretbox(c, m, d, n, k);
        private static int CryptoBoxOpenAfternm(byte[] m, byte[] c, uint d, byte[] n, byte[] k) => CryptoSecretboxOpen(m, c, d, n, k);

        private static int CryptoBox(byte[] c, byte[]? m, uint d, byte[] n, byte[] y, byte[] x)
        {
            var k = new byte[32];
            CryptoBoxBeforenm(k, y, x);
            return CryptoBoxAfternm(c, m, d, n, k);
        }

        private static int CryptoBoxOpen(byte[] m, byte[] c, uint d, byte[] n, byte[] y, byte[] x)
        {
            var k = new byte[32];
            CryptoBoxBeforenm(k, y, x);
            return CryptoBoxOpenAfternm(m, c, d, n, k);
        }

        private static U64Class Add64(params U64Class[] arguments)
        {
            uint a = 0, b = 0, c = 0, d = 0, m16 = 65535, l, h, i;
            for (i = 0; i < arguments.Length; i++)
            {
                l = arguments[i].Lo;
                h = arguments[i].Hi;
                a += (l & m16); b += (l >> 16);
                c += (h & m16); d += (h >> 16);
            }

            b += (a >> 16);
            c += (b >> 16);
            d += (c >> 16);

            return U64((c & m16) | (d << 16), (a & m16) | (b << 16));
        }

        private static U64Class Shr64(U64Class x, int c)
        {
            return U64((x.Hi >> c), (x.Lo >> c) | (x.Hi << (32 - c)));
        }

        private static U64Class Xor64(params U64Class[] arguments)
        {
            uint l = 0, h = 0, i;
            for (i = 0; i < arguments.Length; i++)
            {
                l ^= arguments[i].Lo;
                h ^= arguments[i].Hi;
            }
            return U64(h, l);
        }

        private static U64Class R(U64Class x, int c)
        {
            uint h = 0, l = 0;
            int c1 = 32 - c;
            if (c < 32)
            {
                h = (x.Hi >> c) | (x.Lo << c1);
                l = (x.Lo >> c) | (x.Hi << c1);
            }
            else if (c < 64)
            {
                h = (x.Lo >> c) | (x.Hi << c1);
                l = (x.Hi >> c) | (x.Lo << c1);
            }
            return U64(h, l);
        }

        private static U64Class Ch(U64Class x, U64Class y, U64Class z)
        {
            uint h = (x.Hi & y.Hi) ^ (~x.Hi & z.Hi),
                l = (x.Lo & y.Lo) ^ (~x.Lo & z.Lo);
            return U64(h, l);
        }

        private static U64Class Maj(U64Class x, U64Class y, U64Class z)
        {
            uint h = (x.Hi & y.Hi) ^ (x.Hi & z.Hi) ^ (y.Hi & z.Hi),
                l = (x.Lo & y.Lo) ^ (x.Lo & z.Lo) ^ (y.Lo & z.Lo);
            return U64(h, l);
        }

        private static U64Class Sigma0(U64Class x) { return Xor64(R(x, 28), R(x, 34), R(x, 39)); }
        private static U64Class Sigma1(U64Class x) { return Xor64(R(x, 14), R(x, 18), R(x, 41)); }
        private static U64Class sigma0(U64Class x) { return Xor64(R(x, 1), R(x, 8), Shr64(x, 7)); }
        private static U64Class sigma1(U64Class x) { return Xor64(R(x, 19), R(x, 61), Shr64(x, 6)); }

        private static U64Class[] K = {
          U64(0x428a2f98, 0xd728ae22), U64(0x71374491, 0x23ef65cd),
          U64(0xb5c0fbcf, 0xec4d3b2f), U64(0xe9b5dba5, 0x8189dbbc),
          U64(0x3956c25b, 0xf348b538), U64(0x59f111f1, 0xb605d019),
          U64(0x923f82a4, 0xaf194f9b), U64(0xab1c5ed5, 0xda6d8118),
          U64(0xd807aa98, 0xa3030242), U64(0x12835b01, 0x45706fbe),
          U64(0x243185be, 0x4ee4b28c), U64(0x550c7dc3, 0xd5ffb4e2),
          U64(0x72be5d74, 0xf27b896f), U64(0x80deb1fe, 0x3b1696b1),
          U64(0x9bdc06a7, 0x25c71235), U64(0xc19bf174, 0xcf692694),
          U64(0xe49b69c1, 0x9ef14ad2), U64(0xefbe4786, 0x384f25e3),
          U64(0x0fc19dc6, 0x8b8cd5b5), U64(0x240ca1cc, 0x77ac9c65),
          U64(0x2de92c6f, 0x592b0275), U64(0x4a7484aa, 0x6ea6e483),
          U64(0x5cb0a9dc, 0xbd41fbd4), U64(0x76f988da, 0x831153b5),
          U64(0x983e5152, 0xee66dfab), U64(0xa831c66d, 0x2db43210),
          U64(0xb00327c8, 0x98fb213f), U64(0xbf597fc7, 0xbeef0ee4),
          U64(0xc6e00bf3, 0x3da88fc2), U64(0xd5a79147, 0x930aa725),
          U64(0x06ca6351, 0xe003826f), U64(0x14292967, 0x0a0e6e70),
          U64(0x27b70a85, 0x46d22ffc), U64(0x2e1b2138, 0x5c26c926),
          U64(0x4d2c6dfc, 0x5ac42aed), U64(0x53380d13, 0x9d95b3df),
          U64(0x650a7354, 0x8baf63de), U64(0x766a0abb, 0x3c77b2a8),
          U64(0x81c2c92e, 0x47edaee6), U64(0x92722c85, 0x1482353b),
          U64(0xa2bfe8a1, 0x4cf10364), U64(0xa81a664b, 0xbc423001),
          U64(0xc24b8b70, 0xd0f89791), U64(0xc76c51a3, 0x0654be30),
          U64(0xd192e819, 0xd6ef5218), U64(0xd6990624, 0x5565a910),
          U64(0xf40e3585, 0x5771202a), U64(0x106aa070, 0x32bbd1b8),
          U64(0x19a4c116, 0xb8d2d0c8), U64(0x1e376c08, 0x5141ab53),
          U64(0x2748774c, 0xdf8eeb99), U64(0x34b0bcb5, 0xe19b48a8),
          U64(0x391c0cb3, 0xc5c95a63), U64(0x4ed8aa4a, 0xe3418acb),
          U64(0x5b9cca4f, 0x7763e373), U64(0x682e6ff3, 0xd6b2b8a3),
          U64(0x748f82ee, 0x5defb2fc), U64(0x78a5636f, 0x43172f60),
          U64(0x84c87814, 0xa1f0ab72), U64(0x8cc70208, 0x1a6439ec),
          U64(0x90befffa, 0x23631e28), U64(0xa4506ceb, 0xde82bde9),
          U64(0xbef9a3f7, 0xb2c67915), U64(0xc67178f2, 0xe372532b),
          U64(0xca273ece, 0xea26619c), U64(0xd186b8c7, 0x21c0c207),
          U64(0xeada7dd6, 0xcde0eb1e), U64(0xf57d4f7f, 0xee6ed178),
          U64(0x06f067aa, 0x72176fba), U64(0x0a637dc5, 0xa2c898a6),
          U64(0x113f9804, 0xbef90dae), U64(0x1b710b35, 0x131c471b),
          U64(0x28db77f5, 0x23047d84), U64(0x32caab7b, 0x40c72493),
          U64(0x3c9ebe0a, 0x15c9bebc), U64(0x431d67c4, 0x9c100d4c),
          U64(0x4cc5d4be, 0xcb3e42b6), U64(0x597f299c, 0xfc657e2a),
          U64(0x5fcb6fab, 0x3ad6faec), U64(0x6c44198c, 0x4a475817)
        };

        private static int CryptoHashblocks(byte[] x, byte[] m, int n)
        {
            U64Class[] z = new U64Class[8];
            U64Class[] b = new U64Class[8];
            U64Class[] a = new U64Class[8];
            U64Class[] w = new U64Class[16];
            U64Class t = new();

            for (var i = 0; i < 8; i++) z[i] = a[i] = Dl64(x, 8 * i);

            var pos = 0;
            while (n >= 128)
            {
                for (var i = 0; i < 16; i++) w[i] = Dl64(m, 8 * i + pos);
                for (var i = 0; i < 80; i++)
                {
                    for (var j = 0; j < 8; j++) b[j] = a[j];
                    t = Add64(a[7], Sigma1(a[4]), Ch(a[4], a[5], a[6]), K[i], w[i % 16]);
                    b[7] = Add64(t, Sigma0(a[0]), Maj(a[0], a[1], a[2]));
                    b[3] = Add64(b[3], t);
                    for (var j = 0; j < 8; j++) a[(j + 1) % 8] = b[j];
                    if (i % 16 == 15)
                    {
                        for (var j = 0; j < 16; j++)
                        {
                            w[j] = Add64(w[j], w[(j + 9) % 16], sigma0(w[(j + 1) % 16]), sigma1(w[(j + 14) % 16]));
                        }
                    }
                }

                for (var i = 0; i < 8; i++)
                {
                    a[i] = Add64(a[i], z[i]);
                    z[i] = a[i];
                }

                pos += 128;
                n -= 128;
            }

            for (var i = 0; i < 8; i++) Ts64(x, 8 * i, z[i]);
            return n;
        }

        private static readonly byte[] iv = {
          0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
          0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
          0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
          0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
          0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,
          0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
          0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
          0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
        };

        private static int CryptoHash(byte[] outp, byte[] m, int n)
        {
            byte[] h = new byte[64], x = new byte[256];
            var b = n;

            for (var i = 0; i < 64; i++) h[i] = iv[i];

            CryptoHashblocks(h, m, n);
            n %= 128;

            for (var i = 0; i < 256; i++) x[i] = 0;
            for (var i = 0; i < n; i++) x[i] = m[b - n + i];
            x[n] = 128;

            n = 256 - 128 * (n < 112 ? 1 : 0);
            x[n - 9] = 0;
            Ts64(x, n - 8, U64((uint)((b / 0x20000000) | 0), (uint)(b << 3)));
            CryptoHashblocks(h, x, n);

            for (var i = 0; i < 64; i++) outp[i] = h[i];

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
            CryptoSecretbox(c, m, (uint)m.Length, nonce, key);
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
            if (CryptoSecretboxOpen(m, c, (uint)c.Length, nonce, key) != 0) return null;
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