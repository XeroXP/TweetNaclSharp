using NUnit.Framework;
using System.Collections.Generic;
using TweetNaclSharp;
using TweetNaclSharp.Core;
using TweetNaclSharp.Core.Extensions;
using TweetNaclSharp.Tests.Data;
using TweetNaclSharp.Util;

namespace TweetNaclFastSharp.Tests
{
    [TestFixture, Category("NaclFast")]
    public class NaclFastTests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void NaclFastVerify()
        {
            Assert.IsTrue(NaclFast.Verify(new byte[1], new byte[1]), "equal arrays of length 1 should verify");
            Assert.IsTrue(NaclFast.Verify(new byte[1000], new byte[1000]), "equal arrays of length 1000 should verify");
            byte[] a = new byte[764], b = new byte[764];
            for (var i = 0; i < a.Length; i++) a[i] = b[i] = (byte)(i & 0xff);
            Assert.IsTrue(NaclFast.Verify(a, b), "equal arrays should verify");
            Assert.IsTrue(NaclFast.Verify(a, a), "same arrays should verify");
            b[0] = 255;
            Assert.IsFalse(NaclFast.Verify(a, b), "different arrays don\'t verify");
            Assert.IsFalse(NaclFast.Verify(new byte[1], new byte[10]), "arrays of different lengths should not verify");
            Assert.IsFalse(NaclFast.Verify(new byte[0], new byte[0]), "zero-length arrays should not verify");
            Assert.Pass();
        }

        [Test]
        public void NaclFastRandomBytes()
        {
            var set = new Dictionary<string, bool>();
            for (var i = 0; i < 10000; i++)
            {
                var s = NaclUtil.EncodeBase64(NaclFast.RandomBytes(32));
                if (set.ContainsKey(s))
                {
                    Assert.Fail("duplicate random sequence! {0}", s);
                    return;
                }
                set[s] = true;
            }
            Assert.Pass("no collisions");
        }

        [Test]
        public void NaclFastCryptoOnetimeauthSpecifiedVectors()
        {
            var outp = new byte[16];
            OnetimeauthSpec.Data.ForEach(v => {
                NaclFast.CryptoOnetimeauth(outp, 0, v.M, 0, v.M.Length, v.K);
                Assert.AreEqual(NaclUtil.EncodeBase64(outp), NaclUtil.EncodeBase64(v.Outp));
            });
            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxRandomTestVectors()
        {
            SecretboxRandom.Data.ForEach(vec => {
                var key = NaclUtil.DecodeBase64(vec[0]);
                var nonce = NaclUtil.DecodeBase64(vec[1]);
                var msg = NaclUtil.DecodeBase64(vec[2]);
                var goodBox = NaclUtil.DecodeBase64(vec[3]);
                var box = NaclFast.Secretbox(msg, nonce, key);
                Assert.NotNull(box, "box should be created");
                Assert.AreEqual(NaclUtil.EncodeBase64(box), NaclUtil.EncodeBase64(goodBox));
                var openedBox = NaclFast.SecretboxOpen(goodBox, nonce, key);
                Assert.NotNull(openedBox, "box should open");
                Assert.AreEqual(NaclUtil.EncodeBase64(openedBox), NaclUtil.EncodeBase64(msg));
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxAndNaclFastSecretboxOpen()
        {
            var key = new byte[NaclFast.SecretboxKeyLength];
            var nonce = new byte[NaclFast.SecretboxNonceLength];
            for (var i = 0; i < key.Length; i++) key[i] = (byte)(i & 0xff);
            for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)((32 + i) & 0xff);
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var box = NaclFast.Secretbox(msg, nonce, key);
            var openedMsg = NaclFast.SecretboxOpen(box, nonce, key);
            Assert.AreEqual(NaclUtil.EncodeUTF8(openedMsg), NaclUtil.EncodeUTF8(msg), "opened messages should be equal");

            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxOpenWithInvalidBox()
        {
            var key = new byte[NaclFast.SecretboxKeyLength];
            var nonce = new byte[NaclFast.SecretboxNonceLength];
            Assert.AreEqual(NaclFast.SecretboxOpen(new byte[0], nonce, key), null);
            Assert.AreEqual(NaclFast.SecretboxOpen(new byte[10], nonce, key), null);
            Assert.AreEqual(NaclFast.SecretboxOpen(new byte[100], nonce, key), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxOpenWithInvalidNonce()
        {
            var key = new byte[NaclFast.SecretboxKeyLength];
            var nonce = new byte[NaclFast.SecretboxNonceLength];
            for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i & 0xff);
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var box = NaclFast.Secretbox(msg, nonce, key);
            Assert.AreEqual(NaclUtil.EncodeUTF8(NaclFast.SecretboxOpen(box, nonce, key)), NaclUtil.EncodeUTF8(msg));
            nonce[0] = 255;
            Assert.AreEqual(NaclFast.SecretboxOpen(box, nonce, key), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxOpenWithInvalidKey()
        {
            var key = new byte[NaclFast.SecretboxKeyLength];
            for (var i = 0; i < key.Length; i++) key[i] = (byte)(i & 0xff);
            var nonce = new byte[NaclFast.SecretboxNonceLength];
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var box = NaclFast.Secretbox(msg, nonce, key);
            Assert.AreEqual(NaclUtil.EncodeUTF8(NaclFast.SecretboxOpen(box, nonce, key)), NaclUtil.EncodeUTF8(msg));
            key[0] = 255;
            Assert.AreEqual(NaclFast.SecretboxOpen(box, nonce, key), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastSecretboxWithMessageLengthsOf0To1024()
        {
            var key = new byte[NaclFast.SecretboxKeyLength];
            for (var i = 0; i < key.Length; i++) key[i] = (byte)(i & 0xff);
            var nonce = new byte[NaclFast.SecretboxNonceLength];
            var fullMsg = new byte[1024];
            for (var i = 0; i < fullMsg.Length; i++) fullMsg[i] = (byte)(i & 0xff);
            for (var i = 0; i < fullMsg.Length; i++)
            {
                var msg = fullMsg.SubArray(0, i);
                var box = NaclFast.Secretbox(msg, nonce, key);
                var unbox = NaclFast.SecretboxOpen(box, nonce, key);
                Assert.AreEqual(NaclUtil.EncodeUTF8(msg), NaclUtil.EncodeUTF8(unbox));
            }

            Assert.Pass();
        }

        [Test]
        public void NaclFastScalarmultBase()
        {
            var golden = new byte[] { 0x89, 0x16, 0x1f, 0xde, 0x88, 0x7b, 0x2b, 0x53, 0xde, 0x54,
                0x9a, 0xf4, 0x83, 0x94, 0x01, 0x06, 0xec, 0xc1, 0x14, 0xd6, 0x98, 0x2d,
                0xaa, 0x98, 0x25, 0x6d, 0xe2, 0x3b, 0xdf, 0x77, 0x66, 0x1a };
            var input = new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (var i = 0; i < 200; i++)
            {
                input = NaclFast.ScalarMultBase(input);
            }
            Assert.AreEqual(NaclUtil.EncodeUTF8(input), NaclUtil.EncodeUTF8(golden));

            Assert.Pass();
        }

        [Test]
        public void NaclFastScalarmultAndNaclFastScalarmultBaseRandomTestVectors()
        {
            ScalarmultRandom.Data.ForEach(vec => {
                var pk1 = NaclUtil.DecodeBase64(vec[0]);
                var sk1 = NaclUtil.DecodeBase64(vec[1]);
                var pk2 = NaclUtil.DecodeBase64(vec[2]);
                var sk2 = NaclUtil.DecodeBase64(vec[3]);
                var outp = NaclUtil.DecodeBase64(vec[4]);

                var jpk1 = NaclFast.ScalarMultBase(sk1);
                Assert.AreEqual(NaclUtil.EncodeUTF8(jpk1), NaclUtil.EncodeUTF8(pk1));
                var jpk2 = NaclFast.ScalarMultBase(sk2);
                Assert.AreEqual(NaclUtil.EncodeUTF8(jpk2), NaclUtil.EncodeUTF8(pk2));
                var jout1 = NaclFast.ScalarMult(sk1, pk2);
                Assert.AreEqual(NaclUtil.EncodeUTF8(jout1), NaclUtil.EncodeUTF8(outp));
                var jout2 = NaclFast.ScalarMult(sk2, pk1);
                Assert.AreEqual(NaclUtil.EncodeUTF8(jout2), NaclUtil.EncodeUTF8(outp));
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxRandomTestVectors()
        {
            var nonce = new byte[NaclFast.BoxNonceLength];
            BoxRandom.Data.ForEach(vec => {
                var pk1 = NaclUtil.DecodeBase64(vec[0]);
                var sk2 = NaclUtil.DecodeBase64(vec[1]);
                var msg = NaclUtil.DecodeBase64(vec[2]);
                var goodBox = NaclUtil.DecodeBase64(vec[3]);

                var box = NaclFast.Box(msg, nonce, pk1, sk2);
                Assert.AreEqual(NaclUtil.EncodeUTF8(box), NaclUtil.EncodeUTF8(goodBox));
                var openedBox = NaclFast.BoxOpen(goodBox, nonce, pk1, sk2);
                Assert.AreEqual(NaclUtil.EncodeUTF8(openedBox), NaclUtil.EncodeUTF8(msg));
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxKeyPair()
        {
            var keys = NaclFast.BoxKeyPair();
            Assert.IsTrue(keys.SecretKey != null && keys.SecretKey.Length == NaclFast.BoxSecretKeyLength, "has secret key");
            Assert.IsTrue(keys.PublicKey != null && keys.PublicKey.Length == NaclFast.BoxPublicKeyLength, "has public key");
            Assert.AreNotEqual(NaclUtil.EncodeUTF8(keys.SecretKey), NaclUtil.EncodeUTF8(keys.PublicKey));

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxKeyPairFromSecretKey()
        {
            var k1 = NaclFast.BoxKeyPair();
            var k2 = NaclFast.BoxKeyPairFromSecretKey(k1.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.SecretKey), NaclUtil.EncodeUTF8(k1.SecretKey));
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.PublicKey), NaclUtil.EncodeUTF8(k1.PublicKey));

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxAndNaclFastBoxOpen()
        {
            var clientKeys = NaclFast.BoxKeyPair();
            var serverKeys = NaclFast.BoxKeyPair();
            var nonce = new byte[NaclFast.BoxNonceLength];
            for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)((32 + i) & 0xff);
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var clientBox = NaclFast.Box(msg, nonce, serverKeys.PublicKey, clientKeys.SecretKey);
            var clientMsg = NaclFast.BoxOpen(clientBox, nonce, clientKeys.PublicKey, serverKeys.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(clientMsg), NaclUtil.EncodeUTF8(msg));
            var serverBox = NaclFast.Box(msg, nonce, clientKeys.PublicKey, serverKeys.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(clientBox), NaclUtil.EncodeUTF8(serverBox));
            var serverMsg = NaclFast.BoxOpen(serverBox, nonce, serverKeys.PublicKey, clientKeys.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(serverMsg), NaclUtil.EncodeUTF8(msg));

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxOpenWithInvalidBox()
        {
            var clientKeys = NaclFast.BoxKeyPair();
            var serverKeys = NaclFast.BoxKeyPair();
            var nonce = new byte[NaclFast.BoxNonceLength];
            Assert.AreEqual(NaclFast.BoxOpen(new byte[0], nonce, serverKeys.PublicKey, clientKeys.SecretKey), null);
            Assert.AreEqual(NaclFast.BoxOpen(new byte[10], nonce, serverKeys.PublicKey, clientKeys.SecretKey), null);
            Assert.AreEqual(NaclFast.BoxOpen(new byte[100], nonce, serverKeys.PublicKey, clientKeys.SecretKey), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxOpenWithInvalidNonce()
        {
            var clientKeys = NaclFast.BoxKeyPair();
            var serverKeys = NaclFast.BoxKeyPair();
            var nonce = new byte[NaclFast.BoxNonceLength];
            for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i & 0xff);
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var box = NaclFast.Box(msg, nonce, clientKeys.PublicKey, serverKeys.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(NaclFast.BoxOpen(box, nonce, serverKeys.PublicKey, clientKeys.SecretKey)),
                    NaclUtil.EncodeUTF8(msg));
            nonce[0] = 255;
            Assert.AreEqual(NaclFast.BoxOpen(box, nonce, serverKeys.PublicKey, clientKeys.SecretKey), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastBoxOpenWithInvalidKeys()
        {
            var clientKeys = NaclFast.BoxKeyPair();
            var serverKeys = NaclFast.BoxKeyPair();
            var nonce = new byte[NaclFast.BoxNonceLength];
            var msg = NaclUtil.DecodeUTF8("message to encrypt");
            var box = NaclFast.Box(msg, nonce, clientKeys.PublicKey, serverKeys.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(NaclFast.BoxOpen(box, nonce, serverKeys.PublicKey, clientKeys.SecretKey)),
                NaclUtil.EncodeUTF8(msg));
            Assert.AreEqual(NaclUtil.EncodeUTF8(NaclFast.BoxOpen(box, nonce, clientKeys.PublicKey, serverKeys.SecretKey)),
                NaclUtil.EncodeUTF8(msg));
            var badPublicKey = new byte[NaclFast.BoxPublicKeyLength];
            Assert.AreEqual(NaclFast.BoxOpen(box, nonce, badPublicKey, clientKeys.SecretKey), null);
            var badSecretKey = new byte[NaclFast.BoxSecretKeyLength];
            Assert.AreEqual(NaclFast.BoxOpen(box, nonce, serverKeys.PublicKey, badSecretKey), null);

            Assert.Pass();
        }

        [Test]
        public void NaclFastHashRandomTestVectors()
        {
            HashRandom.Data.ForEach(vec => {
                var msg = NaclUtil.DecodeBase64(vec[0]);
                var goodHash = NaclUtil.DecodeBase64(vec[1]);
                var hash = NaclFast.Hash(msg);
                Assert.AreEqual(NaclUtil.EncodeUTF8(hash), NaclUtil.EncodeUTF8(goodHash));
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastHashLength()
        {
            Assert.AreEqual(NaclFast.Hash(new byte[0]).Length, 64);
            Assert.AreEqual(NaclFast.Hash(new byte[100]).Length, 64);

            Assert.Pass();
        }

        [Test]
        public void NaclFastHashSpecifiedTestVectors()
        {
            HashSpec.Data.ForEach(vec => {
                var goodHash = vec[0];
                var msg = vec[1];
                var hash = NaclFast.Hash(msg);
                Assert.AreEqual(NaclUtil.EncodeUTF8(hash), NaclUtil.EncodeUTF8(goodHash));
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignAndNaclFastSignOpenSpecifiedVectors()
        {
            SignSpec.Data.ForEach(vec => {
                var keys = NaclFast.SignKeyPairFromSecretKey(NaclUtil.DecodeBase64(vec[0]));
                var msg = NaclUtil.DecodeBase64(vec[1]);
                var goodSig = NaclUtil.DecodeBase64(vec[2]);

                var signedMsg = NaclFast.Sign(msg, keys.SecretKey);
                Assert.AreEqual(NaclUtil.EncodeUTF8(signedMsg.SubArray(0, NaclFast.SignSignatureLength)), NaclUtil.EncodeUTF8(goodSig), "signatures must be equal");
                var openedMsg = NaclFast.SignOpen(signedMsg, keys.PublicKey);
                Assert.AreEqual(NaclUtil.EncodeUTF8(openedMsg), NaclUtil.EncodeUTF8(msg), "messages must be equal");
            });

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignDetachedAndNaclFastSignDetachedVerifySomeSpecifieVectors()
        {
            for (var i = 0; i < SignSpec.Data.Count; i++) {
                var vec = SignSpec.Data[i];
                // We don't need to test all, as internals are already tested above.
                if (i % 100 != 0) return;

                var keys = NaclFast.SignKeyPairFromSecretKey(NaclUtil.DecodeBase64(vec[0]));
                var msg = NaclUtil.DecodeBase64(vec[1]);
                var goodSig = NaclUtil.DecodeBase64(vec[2]);

                var sig = NaclFast.SignDetached(msg, keys.SecretKey);
                Assert.AreEqual(NaclUtil.EncodeUTF8(sig), NaclUtil.EncodeUTF8(goodSig), "signatures must be equal");
                var result = NaclFast.SignDetachedVerify(msg, sig, keys.PublicKey);
                Assert.IsTrue(result, "signature must be verified");
            }

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignKeyPair()
        {
            var keys = NaclFast.SignKeyPair();
            Assert.IsTrue(keys.SecretKey != null && keys.SecretKey.Length == NaclFast.SignSecretKeyLength, "has secret key");
            Assert.IsTrue(keys.PublicKey != null && keys.PublicKey.Length == NaclFast.SignPublicKeyLength, "has public key");
            Assert.AreNotEqual(NaclUtil.EncodeUTF8(keys.SecretKey), NaclUtil.EncodeUTF8(keys.PublicKey));
            var newKeys = NaclFast.SignKeyPair();
            Assert.AreNotEqual(NaclUtil.EncodeUTF8(newKeys.SecretKey), NaclUtil.EncodeUTF8(keys.SecretKey), "two keys differ");

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignKeyPairFromSecretKey()
        {
            var k1 = NaclFast.SignKeyPair();
            var k2 = NaclFast.SignKeyPairFromSecretKey(k1.SecretKey);
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.SecretKey), NaclUtil.EncodeUTF8(k1.SecretKey));
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.PublicKey), NaclUtil.EncodeUTF8(k1.PublicKey));

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignKeyPairFromSeed()
        {
            var seed = NaclFast.RandomBytes(NaclFast.SignSeedLength);
            var k1 = NaclFast.SignKeyPairFromSeed(seed);
            var k2 = NaclFast.SignKeyPairFromSeed(seed);
            Assert.AreEqual(k1.SecretKey.Length, NaclFast.SignSecretKeyLength);
            Assert.AreEqual(k1.PublicKey.Length, NaclFast.SignPublicKeyLength);
            Assert.AreEqual(k2.SecretKey.Length, NaclFast.SignSecretKeyLength);
            Assert.AreEqual(k2.PublicKey.Length, NaclFast.SignPublicKeyLength);
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.SecretKey), NaclUtil.EncodeUTF8(k1.SecretKey));
            Assert.AreEqual(NaclUtil.EncodeUTF8(k2.PublicKey), NaclUtil.EncodeUTF8(k1.PublicKey));
            var seed2 = NaclFast.RandomBytes(NaclFast.SignSeedLength);
            var k3 = NaclFast.SignKeyPairFromSeed(seed2);
            Assert.AreEqual(k3.SecretKey.Length, NaclFast.SignSecretKeyLength);
            Assert.AreEqual(k3.PublicKey.Length, NaclFast.SignPublicKeyLength);
            Assert.AreNotEqual(NaclUtil.EncodeUTF8(k3.SecretKey), NaclUtil.EncodeUTF8(k1.SecretKey));
            Assert.AreNotEqual(NaclUtil.EncodeUTF8(k3.PublicKey), NaclUtil.EncodeUTF8(k1.PublicKey));
            Assert.Throws<NaclException>(() =>
            {
                NaclFast.SignKeyPairFromSeed(seed2.SubArray(0, 16));
            }, "should throw error for wrong seed size");

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignAndNaclFastSignOpen()
        {
            var k = NaclFast.SignKeyPair();
            var m = new byte[100];
            for (var i = 0; i < m.Length; i++) m[i] = (byte)(i & 0xff);
            var sm = NaclFast.Sign(m, k.SecretKey);
            Assert.IsTrue(sm.Length > m.Length, "signed message length should be greater than message length");
            var om = NaclFast.SignOpen(sm, k.PublicKey);
            CollectionAssert.AreEqual(om, m);
            Assert.Throws<NaclException>(() =>
            {
                NaclFast.SignOpen(sm, k.PublicKey.SubArray(1));
            }, "throws error for wrong public key size");
            var badPublicKey = new byte[k.PublicKey.Length];
            om = NaclFast.SignOpen(sm, badPublicKey);
            Assert.AreEqual(om, null, "opened message must be null when using wrong public key");
            for (var i = 80; i < 90; i++) sm[i] = 0;
            om = NaclFast.SignOpen(sm, k.PublicKey);
            Assert.AreEqual(om, null, "opened message must be null when opening bad signed message");

            Assert.Pass();
        }

        [Test]
        public void NaclFastSignDetachedAndNaclFastSignDetachedVerify()
        {
            var k = NaclFast.SignKeyPair();
            var m = new byte[100];
            for (var i = 0; i < m.Length; i++) m[i] = (byte)(i & 0xff);
            var sig = NaclFast.SignDetached(m, k.SecretKey);
            Assert.IsTrue(sig.Length == NaclFast.SignSignatureLength, "signature must have correct length");
            var result = NaclFast.SignDetachedVerify(m, sig, k.PublicKey);
            Assert.IsTrue(result, "signature must be verified");
            Assert.Throws<NaclException>(() =>
            {
                NaclFast.SignDetachedVerify(m, sig, k.PublicKey.SubArray(1));
            }, "throws error for wrong public key size");
            Assert.Throws<NaclException>(() =>
            {
                NaclFast.SignDetachedVerify(m, sig.SubArray(1), k.PublicKey);
            }, "throws error for wrong signature size");
            var badPublicKey = new byte[k.PublicKey.Length];
            result = NaclFast.SignDetachedVerify(m, sig, badPublicKey);
            Assert.AreEqual(result, false, "signature must not be verified with wrong public key");
            for (var i = 0; i < 10; i++) sig[i] = 0;
            result = NaclFast.SignDetachedVerify(m, sig, k.PublicKey);
            Assert.AreEqual(result, false, "bad signature must not be verified");

            Assert.Pass();
        }
    }
}