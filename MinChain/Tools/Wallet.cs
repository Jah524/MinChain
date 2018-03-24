using System;
using System.Text.RegularExpressions;
using System.Linq;
using System.Collections.Generic;
using System.IO;



namespace MinChain
{
    public class Wallet
    {
        public static void CreateAddrDir(String path){
            DirectoryInfo directory = new DirectoryInfo(path);
            string BaseLocation = directory.FullName;

            if (!directory.Exists)
                directory.Create();
        }
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
        public static String SeedToAddress(byte[] publicKey, Func<String, String> encodeFn){
            var pk = System.Text.Encoding.ASCII.GetString(publicKey);
            var enk = System.Text.Encoding.ASCII.GetBytes( encodeFn(pk) );
            var addr = System.Text.Encoding.ASCII.GetString( BlockchainUtil.ToAddress(enk) );
            return addr;// hash
        }

        static String Encode(byte[] publickKey, int shiftNum){
            //should use hash
            var seed = System.Text.Encoding.ASCII.GetString(publickKey);
            string seedWithShiftnum = seed + shiftNum;
            var it = System.Text.Encoding.ASCII.GetBytes(seedWithShiftnum);
            var it2 = BlockchainUtil.ToAddress(it);
            var it3 = System.Text.Encoding.ASCII.GetString(it2);
            var it4 = Base64Encode(it3);
            Console.WriteLine(it4);
            return it4;
        }
        public static IEnumerable<String> LoadAllAddr(byte[] publicKey, String addrPath)
        {
            DirectoryInfo directory = new DirectoryInfo(addrPath);
            foreach (var file in directory.GetFiles())
            {
                var name = file.Name;
                Console.WriteLine("full=> "+file.FullName);
                var id = name;
                var bytes = File.ReadAllBytes(file.FullName);
                var b = System.Text.Encoding.ASCII.GetString(bytes);
                var shiftNum = int.Parse(b);
                string address = Encode(publicKey, shiftNum);
                yield return address;
            }
        }

        public static String SaveAddrFunc(byte[] privateKey, String addrPath)
        {
            DirectoryInfo directory = new DirectoryInfo(addrPath);
            string dir = directory.FullName;
            if (!directory.Exists) directory.Create();

            var fileCount = directory.GetFiles().Length;
            var fileCountStr = fileCount.ToString();
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(fileCountStr);

            var fileName = Path.Combine(
                    directory.FullName, dir + "/" + fileCount);
            
            //Console.WriteLine(fileName);
            //Console.WriteLine(System.Text.Encoding.ASCII.GetString(bytes));
            var fileInfo = new FileInfo(fileName);
            if (fileInfo.Exists) return "Failed";

            using (var stream = fileInfo.OpenWrite())
                stream.Write(bytes, 0, bytes.Length);

            return fileName;
        }
    }
}

