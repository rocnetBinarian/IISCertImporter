using Microsoft.Web.Administration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace CertImporter
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Requires <Cert StoreName> <pfxfile> <friendlyname> and <password> arguments");
                return;
            }
            string certStoreName = args[0];
            string pfxFile = args[1];
            string friendlyName = args[2];
            string password = args[3];

            X509Store store = new X509Store(certStoreName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);


            var newCert = new X509Certificate2(pfxFile, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
            newCert.FriendlyName = friendlyName;
            store.Add(newCert);


            if (File.Exists("previousHash.txt") && File.Exists("previousHash.bin"))
            {
                var oldHashText = File.ReadAllText("previousHash.txt").Trim();
                if (oldHashText == newCert.GetCertHashString())
                {
                    return;
                }
                var oldCert = store.Certificates.Find(X509FindType.FindByThumbprint, oldHashText, false);

                ServerManager mgr = new ServerManager();
                foreach (Site s in mgr.Sites)
                {
                    Console.WriteLine(s.Name);
                    foreach (var b in s.Bindings.Where(x => x.Protocol == "https" && x.CertificateHash.SequenceEqual(File.ReadAllBytes("previousHash.bin"))))
                    {
                        b.CertificateHash = newCert.GetCertHash();
                        b.CertificateStoreName = certStoreName;
                        b.SetAttributeValue("certificateStoreName", certStoreName);
                        b.SetAttributeValue("certificateHash", newCert.GetCertHashString());
                    }
                }
                mgr.CommitChanges();
                store.RemoveRange(oldCert);
                store.Close();
                store.Dispose();
            }


            File.WriteAllBytes("previousHash.bin", newCert.GetCertHash());
            File.WriteAllText("previousHash.txt", newCert.GetCertHashString());

        }
    }
}
