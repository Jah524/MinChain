using System;
using System.Collections.Generic;
using static MessagePack.MessagePackSerializer;
using System.Linq;

namespace MinChain
{
    public static class BlockchainUtil
    {
        public static IEnumerable<Block> Ancestors(this Block block,
             Dictionary<ByteString, Block> blocks)
        {
            var hash = block.Id;
            while (!hash.IsNull())
            {
                if (!blocks.TryGetValue(hash, out block)) yield break;
                yield return block;

                hash = block.PreviousHash;
            }
        }

        public static Block LowestCommonAncestor(Block b1, Block b2,
            Dictionary<ByteString, Block> blocks)
        {
            var set = new HashSet<ByteString>();

            using (var e1 = b1.Ancestors(blocks).GetEnumerator())
            using (var e2 = b2.Ancestors(blocks).GetEnumerator())
            {
                bool f1, f2 = false;
                while ((f1 = e1.MoveNext()) || (f2 = e2.MoveNext()))
                {
                    if (f1 && !set.Add(e1.Current.Id)) return e1.Current;
                    if (f2 && !set.Add(e2.Current.Id)) return e2.Current;
                }
            }

            return null;
        }

        public static byte[] RootHashTransactionIds(IList<ByteString> txIds)
        {
            return MerkleRootHash(txIds);
        }

        private static IList<byte[]> MerkleLayer(IList<byte[]> txIds)
        {
            byte[] CombinedHash(String left, String right) => Hash.ComputeDoubleSHA256(System.Text.Encoding.ASCII.GetBytes(left + right));
            List<byte[]> layer = new List<byte[]>();
            String l = "";
            for (var i = 0; i < txIds.Count(); i++)
            {
                if ((i % 2) == 0)
                {
                    l = System.Text.Encoding.ASCII.GetString(txIds[i]);
                }
                else
                {
                    layer.Add(CombinedHash(l, System.Text.Encoding.ASCII.GetString(txIds[i])));
                    l = "";
                }
            }
            // process remain if exists
            if(l!="")
            {
                layer.Add(Hash.ComputeDoubleSHA256(System.Text.Encoding.ASCII.GetBytes(l)));
                l = "";
            }
            return layer;
        }
        public static byte[] MerkleRootHash(IList<ByteString> txIds)
        {
            var xx = txIds.Select(x => x.ToString());
            List<byte[]> txIdsBytes = txIds.Select(txid => txid.ToByteArray()).ToList();
            IList<byte[]> layer = txIdsBytes;
            while(layer.Count() > 1){
                Console.WriteLine("nodes: "+layer.Count);
                layer = MerkleLayer(layer);
            }
            Console.WriteLine("nodes: " + layer.Count + ", finish");
            return layer[0];
        }


        public static Block DeserializeBlock(byte[] data)
        {
            var block = Deserialize<Block>(data);
            block.Original = data;
            block.Id = ByteString.CopyFrom(ComputeBlockId(data));
            return block;
        }

        public static Transaction DeserializeTransaction(byte[] data)
        {
            var tx = Deserialize<Transaction>(data);
            tx.Original = data;
            tx.Id = ByteString.CopyFrom(ComputeTransactionId(data));
            return tx;
        }

        public static byte[] ComputeBlockId(byte[] data)
        {
            var block = Deserialize<Block>(data).Clone();
            block.TransactionIds = null;
            block.Transactions = null;
            var bytes = Serialize(block);
            return Hash.ComputeDoubleSHA256(bytes);
        }

        public static byte[] ComputeTransactionId(byte[] data)
        {
            return Hash.ComputeDoubleSHA256(data);
        }

        public static byte[] GetTransactionSignHash(byte[] data)
        {
            var tx = Deserialize<Transaction>(data).Clone();
            foreach (var inEntry in tx.InEntries)
            {
                inEntry.PublicKey = null;
                inEntry.Signature = null;
            }
            var bytes = Serialize(tx);
            return Hash.ComputeDoubleSHA256(bytes);
        }

        public static byte[] ToAddress(byte[] publicKey)
        {
            // NOTE: In Bitcoin, recipient address is computed by SHA256 +
            // RIPEMD160.
            return Hash.ComputeDoubleSHA256(publicKey);
        }
    }
}
