using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Security.Cryptography;

namespace DgBordro.Pages
{
    public class PayrollModel : PageModel
    {
        public void OnGet()
        {
        }

        private readonly IWebHostEnvironment _env;

        public PayrollModel(IWebHostEnvironment env)
        {
            _env = env;
        }

        [BindProperty]
        public IFormFile UploadedFile { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public async Task<IActionResult> OnPostUploadAsync()
        {
            if (!ModelState.IsValid || UploadedFile == null || string.IsNullOrEmpty(Password))
            {
                TempData["Message"] = "Lütfen bir dosya seçin ve parola girin.";
                return Page();
            }

            string uploadsFolder = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            string filePath = Path.Combine(uploadsFolder, UploadedFile.FileName);

            using (var stream = new MemoryStream())
            {
                await UploadedFile.CopyToAsync(stream);
                byte[] encryptedData = EncryptFile(stream.ToArray(), Password);
                await System.IO.File.WriteAllBytesAsync(filePath, encryptedData);
            }

            TempData["Message"] = "Dosya baþarýyla yüklendi ve þifrelendi.";
            return RedirectToPage();
        }

        public IActionResult OnPostDownload(string fileName, string password)
        {
            string filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);
            if (!System.IO.File.Exists(filePath))
            {
                TempData["Message"] = "Dosya bulunamadý.";
                return RedirectToPage();
            }

            byte[] encryptedData = System.IO.File.ReadAllBytes(filePath);
            byte[] decryptedData = DecryptFile(encryptedData, password);
            if (decryptedData == null)
            {
                TempData["Message"] = "Parola yanlýþ!";
                return RedirectToPage();
            }

            return File(decryptedData, "application/octet-stream", fileName);
        }

        private byte[] EncryptFile(byte[] data, string password)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] key = Encoding.UTF8.GetBytes(password.PadRight(32).Substring(0, 32));
                aes.Key = key;
                aes.IV = new byte[16]; 

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        private byte[] DecryptFile(byte[] encryptedData, string password)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    byte[] key = Encoding.UTF8.GetBytes(password.PadRight(32).Substring(0, 32));
                    aes.Key = key;
                    aes.IV = new byte[16];

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
