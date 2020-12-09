using Microsoft.AspNetCore.Mvc;
using MyPgpDemo.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyPgpDemo.Controllers
{
    [Route("[controller]/[action]")]
    public class PGPController : Controller
    {
        [Route("/[controller]")]
        public IActionResult Index()
        {
            var data = PGPCrypto.GenerateKey("tuan", "123456");
            ViewBag.privateKey = data.privateKey;
            ViewBag.publicKey = data.publicKey;
            return View();
        }
    }
}
