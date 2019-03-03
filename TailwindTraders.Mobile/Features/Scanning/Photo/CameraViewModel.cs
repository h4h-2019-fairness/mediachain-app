using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Org.BouncyCastle;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TailwindTraders.Mobile.Features.Common;
using TailwindTraders.Mobile.Features.Product;
using TailwindTraders.Mobile.Framework;
using Xamarin.Forms;
using Org.BouncyCastle.Crypto.Parameters;
using System.Reflection;

namespace TailwindTraders.Mobile.Features.Scanning.Photo
{
    public class CameraViewModel : BaseViewModel
    {
        private readonly string mediaPath;

        private readonly PhotoService photoService;
        private readonly IPlatformService platformService;
        private readonly IVisionService visionService;

        private string hex;
        private string signature;
        const string userID = "290b4263-8a55-40cf-afbe-e72d1aca5339";

        public const string ReloadGalleryMessage = nameof(ReloadGalleryMessage);

        public ICommand CloseCommand => new AsyncCommand(App.NavigateModallyBackAsync);

        public ICommand AddCommand => FeatureNotAvailableCommand;

        static async Task Crypto()
        {
            // TODO: Upload hash/photo? to the server
        }

        public ICommand TakePhotoCommand => new AsyncCommand(App.NavigateModallyBackAsync);

        private string cameraImage;

        public string CameraImage
        {
            get => cameraImage;
            set => SetAndRaisePropertyChanged(ref cameraImage, value);
        }

        private List<ProductDTO> recommendedProducts;

        public List<ProductDTO> RecommendedProducts
        {
            get => recommendedProducts;
            set => SetAndRaisePropertyChanged(ref recommendedProducts, value);
        }

        public CameraViewModel(string mediaPath)
        {
            this.mediaPath = mediaPath;

            photoService = DependencyService.Get<PhotoService>();
            platformService = DependencyService.Get<IPlatformService>();
            visionService = DependencyService.Get<IVisionService>();
        }

        public override async Task InitializeAsync()
        {
            await base.InitializeAsync();

            var resized = platformService.ResizeImage(this.mediaPath, PhotoSize.Small, quality: 70);
            CameraImage = this.mediaPath;

            // 1) Get binary of the file
            byte[] b = File.ReadAllBytes(mediaPath);

            SHA256 hash = SHA256.Create();
            hash.ComputeHash(b);

            hex = BitConverter.ToString(hash.Hash).Replace("-", "").ToLower();

            string[] keys = Assembly.GetExecutingAssembly().GetManifestResourceNames();

            RSACryptoServiceProvider rsa = PrivateKeyFromPemFile(GetEmbeddedResourceContent(keys[2]));
                       
            byte[] weWin = rsa.SignData(b, new SHA256CryptoServiceProvider());

            signature = System.Convert.ToBase64String(weWin);

            BrandDTO brand = new BrandDTO();
            brand.Name = "Unique Image Signature:";
            
            ProductDTO description = new ProductDTO();
            description.Brand = brand;
            description.Name = signature;

            RecommendedProducts = new List<ProductDTO>();
            RecommendedProducts.Add(description);
        }

        public static RSACryptoServiceProvider PrivateKeyFromPemFile(String str)
        {
            using (TextReader privateKeyTextReader = new StringReader(str))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();


                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

        public static string GetEmbeddedResourceContent(string resourceName)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            Stream stream = asm.GetManifestResourceStream(resourceName);
            StreamReader source = new StreamReader(stream);
            string fileContent = source.ReadToEnd();
            source.Dispose();
            stream.Dispose();
            return fileContent;
        }

        public override async Task UninitializeAsync()
        {
            await base.UninitializeAsync();

            MessagingCenter.Send(this, ReloadGalleryMessage);
        }
    }
}
