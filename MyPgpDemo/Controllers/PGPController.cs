using Microsoft.AspNetCore.Mvc;
using MyPgpDemo.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyPgpDemo.Models;

namespace MyPgpDemo.Controllers
{
    [Route("[controller]/[action]")]
    public class PGPController : Controller
    {
        [HttpGet]
        [Route("/GeneradeKeyPair")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult GeneradeKeyPair([FromForm] KeyGenInput parametter)
        {
            (string privateKey, string publicKey) = PGPCrypto.GenerateKey(parametter.Name.Replace(" ", ""), parametter.Passphrase.Replace(" ", ""));

            return Json(new
            {
                privateKey = privateKey,
                publicKey = publicKey,
                name = parametter.Name,
                pass = parametter.Passphrase
            });
        }

        [HttpPost]
        public IActionResult EncryptPGP([FromForm] EncryptAndSignInput parametter)
        {
            string data = string.Empty;
            if (parametter.Type == EncryptType.EncryptAndSign)
            {
                data = PGPCrypto.EncryptAndSign(parametter.Message, parametter.PublicKey, parametter.PrivateKey, parametter.Passphrase);
            }
            else
            {
                //coming soon
            }

            return Json(data);
        }
        [HttpPost]
        public IActionResult DecryptPGP([FromForm] DecryptInput parametter)
        {
            string data = PGPCrypto.Decrypt(parametter.EncryptedMessage, parametter.PrivateKey, parametter.Passphrase);

            return Json(data);
        }
    }
}
