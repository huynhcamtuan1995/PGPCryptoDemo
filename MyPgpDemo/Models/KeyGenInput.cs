using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MyPgpDemo.Models
{
    public class KeyGenInput
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string Passphrase { get; set; }
    }

    public enum EncryptType
    {
        OnlyEncrypt = 0,
        EncryptAndSign = 1
    }
    public class EncryptAndSignInput
    {
        [Required]
        public string PublicKey { get; set; }
        [Required]
        public string Message { get; set; }
        [Required]
        public string PrivateKey { get; set; }
        [Required]
        public string Passphrase { get; set; }

        public EncryptType Type { get; set; }
    }

    public class DecryptInput
    {
        [Required]
        public string PrivateKey { get; set; }
        [Required]
        public string Passphrase { get; set; }
        [Required]
        public string EncryptedMessage { get; set; }
    }
}
