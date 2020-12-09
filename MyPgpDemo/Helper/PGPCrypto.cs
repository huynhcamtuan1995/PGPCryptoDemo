using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyPgpDemo.Helper
{
    public class PGPCrypto
    {
        private const int BufferSize = 0x10000;

        public static (string privateKey, string publicKey) GenerateKey(
            string username,
            string password)
        {
            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            //FileStream out1 = new FileInfo(string.Format("{0}PGPPrivateKey.asc", keyStoreUrl)).OpenWrite();
            //FileStream out2 = new FileInfo(string.Format("{0}PGPPublicKey.asc", keyStoreUrl)).OpenWrite();
            Stream privateKeyStream = new MemoryStream();
            Stream publicKeyStream = new MemoryStream();
            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, username, password.ToCharArray(), true);

            byte[] privateBuffer = (privateKeyStream as MemoryStream).ToArray();
            string privateKey = Encoding.ASCII.GetString(privateBuffer);

            byte[] publicBuffer = (publicKeyStream as MemoryStream).ToArray();
            string publicKey = Encoding.ASCII.GetString(publicBuffer);
            return (privateKey, publicKey);
        }

        private static void ExportKeyPair(Stream secretOut, Stream publicOut, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, string identity, char[] passPhrase, bool armor)
        {
            if (armor)
                secretOut = new ArmoredOutputStream(secretOut);

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                publicKey,
                privateKey,
                DateTime.Now,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom());

            secretKey.Encode(secretOut);
            secretOut.Close();

            if (armor)
                publicOut = new ArmoredOutputStream(publicOut);

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);
            publicOut.Close();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="inputData"></param>
        /// <param name="privateKeyIn"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        public static string Decrypt(
            string inputData,
            string privateKeyIn,
            string passPhrase,
            string exportFilePath = "")
        {
            Stream outputStream;
            byte[] inputBuffer = Encoding.ASCII.GetBytes(inputData);
            MemoryStream inputStream = new MemoryStream(inputBuffer);

            var result = Decrypt(inputStream, privateKeyIn, passPhrase, out outputStream);

            if (string.IsNullOrWhiteSpace(exportFilePath))
            {
                using (Stream fileStream = new FileStream(exportFilePath, FileMode.Create, FileAccess.Write))
                    outputStream.CopyTo(fileStream);
            }

            return result;
        }

        public static string Decrypt(
            Stream inputStream,
            string privateKeyIn,
            string passPhrase,
            out Stream outputStream)
        {
            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            outputStream = new MemoryStream();

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else if (obj is PgpCompressedData)
                message = (PgpCompressedData)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException($"Failed to detect encrypted content format.");

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;

            PgpSecretKeyRingBundle pgpSecret = null;

            byte[] privateKeyBuffer = Encoding.ASCII.GetBytes(privateKeyIn);
            MemoryStream privateKeyStream = new MemoryStream(privateKeyBuffer);

            pgpSecret = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
            if (enc != null)
            {
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    privateKey = FindSecretKey(pgpSecret, pked.KeyId, passPhrase.ToCharArray());

                    if (privateKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (privateKey == null)
                    throw new ArgumentException($"Secret key for message not found.");

                PgpObjectFactory plainFact = null;

                using (Stream clear = pbe.GetDataStream(privateKey))
                {
                    plainFact = new PgpObjectFactory(clear);
                }

                message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList)
                {
                    message = plainFact.NextPgpObject();
                }
            }

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        throw new PgpException($"Message failed integrity check.");
                    }
                }
            }
            else if (message is PgpOnePassSignatureList)
                throw new PgpException($"Encrypted message contains a signed message - not literal data.");
            else
                throw new PgpException($"Message is not a simple encrypted file.");

            byte[] outputBuffer = (outputStream as MemoryStream).ToArray();
            return Encoding.ASCII.GetString(outputBuffer);
        }

        /// <summary>
        /// EncryptAndSign
        /// </summary>
        /// <param name="message"></param>
        /// <param name="publicKeyIn"></param>
        /// <param name="privateKeyIn"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        public static string EncryptAndSign(
            string message,
            string publicKeyIn,
            string privateKeyIn,
            string passPhrase)
        {
            PgpPublicKey senderPublicKey = ReadPublicKey(publicKeyIn);
            PgpPrivateKey senderPrivateKey = ReadPrivateKey(privateKeyIn, passPhrase);

            Stream outputStream = new MemoryStream();

            byte[] messageBuffer = Encoding.ASCII.GetBytes(message);
            Stream messageStream = new MemoryStream(messageBuffer);

            var result = EncryptAndSign(messageStream, publicKeyIn, privateKeyIn, passPhrase, out outputStream);
            return result;
        }

        public static string EncryptAndSign(
            Stream messageStream,
            string publicKeyIn,
            string privateKeyIn,
            string passPhrase,
            out Stream outputStream)
        {
            PgpPublicKey senderPublicKey = ReadPublicKey(publicKeyIn);
            PgpPrivateKey senderPrivateKey = ReadPrivateKey(privateKeyIn, passPhrase);

            outputStream = new MemoryStream();

            // Create a signature generator.
            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(senderPublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, senderPrivateKey);

            // Add the public key user ID.
            foreach (string userId in senderPublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator signatureSubGenerator = new PgpSignatureSubpacketGenerator();
                signatureSubGenerator.SetSignerUserId(false, userId);
                signatureGenerator.SetHashedSubpackets(signatureSubGenerator.Generate());
                break;
            }

            // Allow any of the corresponding keys to be used for decryption.
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, true, new SecureRandom());
            encryptedDataGenerator.AddMethod(senderPublicKey);


            using (Stream armoredStream = new ArmoredOutputStream(outputStream))
            {
                using (Stream encryptedStream = encryptedDataGenerator.Open(armoredStream, new byte[0x10000]))
                {
                    PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Uncompressed);
                    using (Stream compressedStream = compressedDataGenerator.Open(encryptedStream))
                    {
                        signatureGenerator.GenerateOnePassVersion(false).Encode(compressedStream);

                        PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                        using (Stream literalStream = literalDataGenerator.Open(compressedStream, PgpLiteralData.Binary,
                            PgpLiteralData.Console, DateTime.Now, new byte[0x10000]))
                        {
                            // Process each character in the message.
                            int messageChar;
                            while ((messageChar = messageStream.ReadByte()) >= 0)
                            {
                                literalStream.WriteByte((byte)messageChar);
                                signatureGenerator.Update((byte)messageChar);
                            }
                        }

                        signatureGenerator.Generate().Encode(compressedStream);
                    }
                }
            }

            byte[] signedAndEncryptedMessageBuffer = (outputStream as MemoryStream).ToArray();

            Console.WriteLine(Encoding.ASCII.GetString(signedAndEncryptedMessageBuffer));
            return Encoding.ASCII.GetString(signedAndEncryptedMessageBuffer);
        }

        public static PgpSecretKey ReadSecretKey(string keyIn)
        {
            byte[] keyInBuffer = Encoding.ASCII.GetBytes(keyIn);
            using (Stream keyInStream = new MemoryStream(keyInBuffer))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyInStream))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                PgpSecretKey foundKey = GetFirstSecretKey(secretKeyRingBundle);
                if (foundKey != null)
                    return foundKey;
            }
            throw new ArgumentException("Can't find signing key in key ring.");

        }

        private static PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                PgpSecretKey key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    .Where(k => k.IsSigningKey)
                    .FirstOrDefault();

                if (key != null)
                    return key;
            }
            return null;
        }

        public static PgpPublicKey ReadPublicKey(string keyIn)
        {
            byte[] keyInBuffer = Encoding.ASCII.GetBytes(keyIn);
            using (Stream keyInStream = new MemoryStream(keyInBuffer))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyInStream))
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                PgpPublicKey foundKey = GetFirstPublicKey(publicKeyRingBundle);
                if (foundKey != null)
                    return foundKey;
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        private static PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(k => k.IsEncryptionKey)
                    .FirstOrDefault();

                if (key != null)
                    return key;
            }
            return null;
        }


        public static PgpPrivateKey ReadPrivateKey(
            string keyIn,
            string passPhrase)
        {
            PgpSecretKey secretKey = ReadSecretKey(keyIn);
            PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)

                return privateKey;

            throw new ArgumentException("No private key found in secret key.");

        }

        private static PgpPrivateKey FindSecretKey(
            PgpSecretKeyRingBundle secretRingBundle,
            long keyId,
            char[] pass)
        {
            PgpSecretKey pgpSecKey = secretRingBundle.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }
    }
}
