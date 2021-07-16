using Microsoft.AspNetCore.Mvc;
using MyPgpDemo.Models;

namespace MyPgpDemo.Controllers
{
    [Route("[controller]/[action]")]
    public class PGPController : Controller
    {
        [HttpGet]
        [Route("/")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult GeneradeKeyPair([FromForm] KeyGenInput parametter)
        {
            (string privateKey, string publicKey) = PGPEncryption.PGPEncryption.GenerateKey(parametter.Name.Replace(" ", ""), parametter.Passphrase.Replace(" ", ""));

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
                data = PGPEncryption.PGPEncryption.EncryptAndSign(parametter.Message, parametter.PublicKey, parametter.PrivateKey, parametter.Passphrase);
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
            string data = PGPEncryption.PGPEncryption.Decrypt(parametter.EncryptedMessage, parametter.PrivateKey, parametter.Passphrase);

            return Json(data);
        }
    }
}
