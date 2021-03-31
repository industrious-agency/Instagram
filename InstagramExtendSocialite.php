<?php

namespace SocialiteProviders\Instagram;

use SocialiteProviders\Manager\SocialiteWasCalled;

class InstagramExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('instagram', Provider::class);
    }
}
