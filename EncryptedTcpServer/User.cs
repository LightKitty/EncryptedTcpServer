using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace EncryptedTcpServer
{
    class User
    {
        public TcpClient client;
        public BinaryReader br;
        public BinaryWriter bw;
        //对称加密
        public TripleDESCryptoServiceProvider tdes;
        //不对称加密
        public RSACryptoServiceProvider rsa;
        public User(TcpClient client)
        {
            this.client = client;
            NetworkStream networkStream = client.GetStream();
            br = new BinaryReader(networkStream, Encoding.UTF8);
            bw = new BinaryWriter(networkStream, Encoding.UTF8);
            tdes = new TripleDESCryptoServiceProvider();
            //随机生成密钥Key 和初始化向量IV,也可以不用此两句，而使用默认的Key 和IV
            //tdes.GenerateKey();
            //tdes.GenerateIV();
            rsa = new RSACryptoServiceProvider();
        }
    }
}