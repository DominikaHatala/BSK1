using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace BSK1
{

    class Users : IEquatable<Users>
    {
        public string Email { get; }
        private string privateKeyPath;
        private string publicKeyPath;

        private static string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HatalaBulawa");

        private static string publicKeyDir = Path.Combine(dataDir, "public");
        private static string privateKeyDir = Path.Combine(dataDir, "private");

        public Users(string email, string password)
        {
            this.Email = email;
            generateKeyPair(email, password);
        }

        private Users(string email, string privateKeyPath, string publicKeyPath)
        {
            this.Email = email;
            this.privateKeyPath = privateKeyPath;
            this.publicKeyPath = publicKeyPath;
        }


        public static List<Users> loadUsers()
        {
            List<Users> allUsers = new List<Users>();

            if (!Directory.Exists(dataDir))
            {
                return allUsers;
            }

            string[] keyPaths = Directory.GetFiles(publicKeyDir, "*");
            foreach (string publicKeyPath in keyPaths)
            {
                string email = Path.GetFileName(publicKeyPath);
                string privateKeyPath = Path.Combine(privateKeyDir, email);
                allUsers.Add(new Users(email, privateKeyPath, publicKeyPath));
            }

            return allUsers;
        }

       
        private void generateKeyPair(string email, string password)
        {
            Directory.CreateDirectory(publicKeyDir);
            Directory.CreateDirectory(privateKeyDir);

            this.publicKeyPath = Path.Combine(publicKeyDir, email);
            this.privateKeyPath = Path.Combine(privateKeyDir, email);

            RSAkey.generateKeyPair(this.publicKeyPath, this.privateKeyPath, password);
        }

        public RSAkey.Key getPublicKey()
        {
            return RSAkey.loadPublicKey(this.publicKeyPath);
        }

        public RSAkey.Key getPrivateKey(string password)
        {
            return RSAkey.loadPrivateKey(this.privateKeyPath, password);
        }


        public bool Equals(Users other)
        {
            return other.Email == this.Email;
        }

        public override string ToString()
        {
            return this.Email;
        }

        
    }
}
