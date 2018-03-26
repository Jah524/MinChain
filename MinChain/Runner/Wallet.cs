using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;

namespace MinChain
{
    public class Wallet
    {

        public static String GenSeed(){
            Guid g = Guid.NewGuid();
            string GuidString = Convert.ToBase64String(g.ToByteArray());;
            return GuidString;
        }
        
        // retrieved from https://stackoverflow.com/questions/28573526/ecdsa-get-public-key-in-c-sharp
        public static void GetPublicKey(byte[] privateKey, out byte[] pubx, out byte[] puby)
        {
            BigInteger privKeyInt = new BigInteger(+1, privateKey);

            var parameters = SecNamedCurves.GetByName("secp256k1");
            Org.BouncyCastle.Math.EC.ECPoint qa = parameters.G.Multiply(privKeyInt);

            byte[] pubKeyX = qa.X.ToBigInteger().ToByteArrayUnsigned();
            byte[] pubKeyY = qa.Y.ToBigInteger().ToByteArrayUnsigned();
            pubx = pubKeyX;
            puby = pubKeyY;
        }
        

        public static byte[] CreatePrivateKey(String seed, int index)
        {
            byte[] seedBytes = System.Text.Encoding.ASCII.GetBytes(seed);
            var sb = System.Text.Encoding.ASCII.GetString(seedBytes);
            // merge seed with index
            var mergedSeed = sb + index.ToString();
            byte[] keySeed = Hash.ComputeDoubleSHA256(System.Text.Encoding.ASCII.GetBytes(mergedSeed));
            byte[] prv = Hash.ComputeDoubleSHA256(keySeed);
            return prv;
        }

        public static byte[] CreatePublicKey(byte[] prv)
        {
            byte[] pubx;
            byte[] puby;
            GetPublicKey(prv, out pubx, out puby);

            byte[] pub = new byte[pubx.Length+puby.Length];
            pubx.CopyTo(pub, 0);
            puby.CopyTo(pub, pubx.Length);
            return pub;
        }

        public static string Pub2Addr(byte[] pub)
        {
            var h = Hash.ComputeDoubleSHA256(pub);
            return System.Convert.ToBase64String(h);
        }

        private static int LoadLatestIndex(string addrPath)
        {
            var fileInfo = new FileInfo(addrPath);
            if (!fileInfo.Exists){
                System.IO.File.Create(addrPath);
            }

            // load latest addr index
            string lastIndex;
            string text = System.IO.File.ReadAllText(addrPath);
            if(String.IsNullOrEmpty(text)){
                lastIndex = "0";
            }else{
                lastIndex = text;
            }
            
            int x = Int32.Parse(lastIndex);
            return x;
        }

        public static string CreateAddr(string seed, string addrPath)
        {
            int index = LoadLatestIndex(addrPath);

            var prv = CreatePrivateKey(seed,index);
            var pubx = CreatePublicKey(prv);
            var addr = Pub2Addr(pubx);

            byte[] bytes = System.Text.Encoding.ASCII.GetBytes((index+1).ToString());
            var fileInfo = new FileInfo(addrPath);
            using (var stream = fileInfo.OpenWrite())
                stream.Write(bytes, 0, bytes.Length);
            return addr;
        }

        public static string[] AllAddr(string seed, string addrPath){
            
            int index = LoadLatestIndex(addrPath);
            string[] addrs = new string[index];
            foreach (int i in Enumerable.Range(0, index))
            {             
                var prv = CreatePrivateKey(seed, i);
                var pubx = CreatePublicKey(prv);
                var addr = Pub2Addr(pubx);
                addrs[i] = addr;
            }
            return addrs;
        }

    }
}
