﻿using Refit;
using TailwindTraders.Mobile.Features.Home;
using TailwindTraders.Mobile.Features.LogIn;
using TailwindTraders.Mobile.Features.Product;
using TailwindTraders.Mobile.Features.Settings;
using TailwindTraders.Mobile.Helpers;

namespace TailwindTraders.Mobile.Features.Common
{
    public class RestPoolService : IRestPoolService
    {
        public IProfilesAPI ProfilesAPI { get; private set; }

        public IHomeAPI HomeAPI { get; private set; }

        public IProductsAPI ProductsAPI { get; private set; }

        public RestPoolService()
        {
            UpdateApiUrl(DefaultSettings.RootApiUrl);
        }

        public void UpdateApiUrl(string newApiUrl)
        {
            ProfilesAPI = RestService.For<IProfilesAPI>(HttpClientFactory.Create(newApiUrl));
            HomeAPI = RestService.For<IHomeAPI>(HttpClientFactory.Create(newApiUrl));
            ProductsAPI = RestService.For<IProductsAPI>(HttpClientFactory.Create(newApiUrl));
        }
    }
}
