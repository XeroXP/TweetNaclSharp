using TweetNaclSharp.Core;
using TweetNaclSharp.Core.Extensions;

namespace TweetNaclSharp
{
    public partial class Nacl
    {
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

        public static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            RandomBytes(b, n);
            return b;
        }

        public static byte[] Secretbox(byte[] msg, byte[] nonce, byte[] key)
        {
            CheckLengths(key, nonce);
            var m = new byte[crypto_secretbox_ZEROBYTES + msg.Length];
            var c = new byte[m.Length];
            for (var i = 0; i < msg.Length; i++) m[i + crypto_secretbox_ZEROBYTES] = msg[i];
            CryptoSecretbox(c, m, (uint)m.Length, nonce, key);
            return c.SubArray(crypto_secretbox_BOXZEROBYTES);
        }

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

        public static readonly int SecretboxKeyLength = crypto_secretbox_KEYBYTES;
        public static readonly int SecretboxNonceLength = crypto_secretbox_NONCEBYTES;
        public static readonly int SecretboxOverheadLength = crypto_secretbox_BOXZEROBYTES;

        public static byte[] ScalarMult(byte[] n, byte[] p)
        {
            if (n.Length != crypto_scalarmult_SCALARBYTES) throw new NaclException("bad n size");
            if (p.Length != crypto_scalarmult_BYTES) throw new NaclException("bad p size");
            var q = new byte[crypto_scalarmult_BYTES];
            CryptoScalarmult(q, n, p);
            return q;
        }

        public static byte[] ScalarMultBase(byte[] n)
        {
            if (n.Length != crypto_scalarmult_SCALARBYTES) throw new NaclException("bad n size");
            var q = new byte[crypto_scalarmult_BYTES];
            CryptoScalarmultBase(q, n);
            return q;
        }

        public static readonly int ScalarMultScalarLength = crypto_scalarmult_SCALARBYTES;
        public static readonly int ScalarMultGroupElementLength = crypto_scalarmult_BYTES;

        public static byte[] Box(byte[] msg, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            var k = BoxBefore(publicKey, secretKey);
            return Secretbox(msg, nonce, k);
        }

        public static byte[] BoxBefore(byte[] publicKey, byte[] secretKey)
        {
            CheckBoxLengths(publicKey, secretKey);
            var k = new byte[crypto_box_BEFORENMBYTES];
            CryptoBoxBeforenm(k, publicKey, secretKey);
            return k;
        }

        public static byte[] BoxAfter(byte[] msg, byte[] nonce, byte[] key) => Secretbox(msg, nonce, key);

        public static byte[]? BoxOpen(byte[] msg, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            var k = BoxBefore(publicKey, secretKey);
            return SecretboxOpen(msg, nonce, k);
        }

        public static byte[]? BoxOpenAfter(byte[] box, byte[] nonce, byte[] key) => SecretboxOpen(box, nonce, key);

        public static KeyPair BoxKeyPair()
        {
            var pk = new byte[crypto_box_PUBLICKEYBYTES];
            var sk = new byte[crypto_box_SECRETKEYBYTES];
            CryptoBoxKeypair(pk, sk);
            return new KeyPair { PublicKey = pk, SecretKey = sk };
        }

        public static KeyPair BoxKeyPairFromSecretKey(byte[] secretKey)
        {
            if (secretKey.Length != crypto_box_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var pk = new byte[crypto_box_PUBLICKEYBYTES];
            CryptoScalarmultBase(pk, secretKey);
            return new KeyPair { PublicKey = pk, SecretKey = secretKey };
        }

        public static readonly int BoxPublicKeyLength = crypto_box_PUBLICKEYBYTES;
        public static readonly int BoxSecretKeyLength = crypto_box_SECRETKEYBYTES;
        public static readonly int BoxSharedKeyLength = crypto_box_BEFORENMBYTES;
        public static readonly int BoxNonceLength = crypto_box_NONCEBYTES;
        public static readonly int BoxOverheadLength = SecretboxOverheadLength;

        public static byte[] Sign(byte[] msg, byte[] secretKey)
        {
            if (secretKey.Length != crypto_sign_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var signedMsg = new byte[crypto_sign_BYTES + msg.Length];
            CryptoSign(signedMsg, msg, msg.Length, secretKey);
            return signedMsg;
        }

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

        public static byte[] SignDetached(byte[] msg, byte[] secretKey)
        {
            var signedMsg = Sign(msg, secretKey);
            var sig = new byte[crypto_sign_BYTES];
            for (var i = 0; i < sig.Length; i++) sig[i] = signedMsg[i];
            return sig;
        }

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

        public static KeyPair SignKeyPair()
        {
            var pk = new byte[crypto_sign_PUBLICKEYBYTES];
            var sk = new byte[crypto_sign_SECRETKEYBYTES];
            CryptoSignKeypair(pk, sk);
            return new KeyPair { PublicKey = pk, SecretKey = sk };
        }

        public static KeyPair SignKeyPairFromSecretKey(byte[] secretKey)
        {
            if (secretKey.Length != crypto_sign_SECRETKEYBYTES)
                throw new NaclException("bad secret key size");
            var pk = new byte[crypto_sign_PUBLICKEYBYTES];
            for (var i = 0; i < pk.Length; i++) pk[i] = secretKey[32 + i];
            return new KeyPair { PublicKey = pk, SecretKey = secretKey };
        }

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

        public static readonly int SignPublicKeyLength = crypto_sign_PUBLICKEYBYTES;
        public static readonly int SignSecretKeyLength = crypto_sign_SECRETKEYBYTES;
        public static readonly int SignSeedLength = crypto_sign_SEEDBYTES;
        public static readonly int SignSignatureLength = crypto_sign_BYTES;

        public static byte[] Hash(byte[] msg)
        {
            var h = new byte[crypto_hash_BYTES];
            CryptoHash(h, msg, msg.Length);
            return h;
        }

        public static readonly int HashHashLength = crypto_hash_BYTES;

        public static bool Verify(byte[] x, byte[] y)
        {
            // Zero length arguments are considered not equal.
            if (x.Length == 0 || y.Length == 0) return false;
            if (x.Length != y.Length) return false;
            return (Vn(x, 0, y, 0, (uint)x.Length) == 0) ? true : false;
        }
    }
}
